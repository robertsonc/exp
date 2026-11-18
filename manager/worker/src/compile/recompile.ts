// Persists compiled desired state: hash compare (no churn), version bump on real change, creds sealed
// at rest, and serving (decrypt at serve time). Fan-out recompile for collector / release / intent changes.
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { credAad, isEncryptedCred, masterKey, openCred, sealCred } from "../secrets/crypto";
import { canonicalJson } from "../util/canonical";
import { sha256Hex } from "../util/encoding";
import { isoNow } from "../util/time";
import { bareBody, compile } from "./compile";
import { loadWorld } from "./load";
import type { DesiredBody, World } from "./types";

export interface RecompileOutcome {
  host_id: string;
  changed: boolean;
  version: number | null;
  held: boolean;
  warnings: string[];
}

interface StoredRow {
  version: number;
  content_hash: string;
}

export const contentHashOf = (body: DesiredBody): Promise<string> => sha256Hex(canonicalJson(body));

async function persist(env: Env, key: CryptoKey, body: DesiredBody, hash: string): Promise<{ changed: boolean; version: number }> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const prev = await env.DB.prepare("SELECT version, content_hash FROM desired_docs WHERE host_id = ?1")
      .bind(body.host_id)
      .first<StoredRow>();
    if (prev && prev.content_hash === hash) return { changed: false, version: prev.version };
    const version = (prev?.version ?? 0) + 1;
    const now = isoNow();
    const sealedComponents = [];
    for (const c of body.components) {
      const creds: Record<string, string> = {};
      for (const [name, value] of Object.entries(c.creds)) creds[name] = await sealCred(key, value, credAad(body.host_id, c.component_id, name));
      sealedComponents.push({ ...c, creds });
    }
    const doc = { ...body, version, generated_at: now, components: sealedComponents };
    const artifactIds = [body.agent?.artifact, ...body.components.map((c) => c.artifact.id)].filter((x): x is string => !!x);
    const upsert = prev
      ? env.DB.prepare(
          `UPDATE desired_docs SET version = ?2, doc_json = ?3, content_hash = ?4, artifacts_json = ?5, updated_at = ?6
           WHERE host_id = ?1 AND version = ?7`,
        ).bind(body.host_id, version, JSON.stringify(doc), hash, JSON.stringify([...new Set(artifactIds)]), now, prev.version)
      : env.DB.prepare(
          `INSERT OR IGNORE INTO desired_docs (host_id, org_id, version, doc_json, content_hash, artifacts_json, created_at, updated_at)
           VALUES (?1, ?7, ?2, ?3, ?4, ?5, ?6, ?6)`,
        ).bind(body.host_id, version, JSON.stringify(doc), hash, JSON.stringify([...new Set(artifactIds)]), now, DEFAULT_ORG);
    const setHost = env.DB.prepare(
      `UPDATE hosts SET desired_version = ?2, desired_hash = ?3, updated_at = ?4
       WHERE host_id = ?1 AND EXISTS (SELECT 1 FROM desired_docs WHERE host_id = ?1 AND version = ?2 AND content_hash = ?3)`,
    ).bind(body.host_id, version, hash, now);
    const [r] = await env.DB.batch([upsert, setHost]);
    if ((r?.meta.changes ?? 0) === 1) return { changed: true, version };
    // lost a race with another recompile: re-read and retry
  }
  throw new Error("desired state update contention");
}

async function recompileInWorld(env: Env, key: CryptoKey, world: World, hostId: string): Promise<RecompileOutcome> {
  const res = compile(world, hostId);
  let body = res.doc;
  let held = false;
  if (!body) {
    held = true;
    const existing = await env.DB.prepare("SELECT version FROM desired_docs WHERE host_id = ?1").bind(hostId).first();
    if (!existing) body = bareBody(world, hostId);
    if (!body) return { host_id: hostId, changed: false, version: null, held, warnings: res.warnings };
  }
  const hash = await contentHashOf(body);
  const r = await persist(env, key, body, hash);
  return { host_id: hostId, changed: r.changed, version: r.version, held, warnings: res.warnings };
}

export interface RecompileScope {
  /** specific hosts */
  hostIds?: string[];
  /** every host of these sites plus every dashboard host (dashboards may federate across sites) */
  sites?: string[];
  all?: boolean;
}

/** Recompile the scope; hosts whose document is unchanged keep their version (no churn). */
export async function recompile(env: Env, scope: RecompileScope): Promise<RecompileOutcome[]> {
  const key = await masterKey(env.EXP_MASTER_KEY);
  const world = await loadWorld(env);
  const ids = new Set<string>(scope.hostIds ?? []);
  if (scope.all) for (const id of Object.keys(world.hosts)) ids.add(id);
  if (scope.sites?.length) {
    const dashHosts = new Set(world.components.filter((c) => c.type === "dashboard").map((c) => c.host_id));
    for (const h of Object.values(world.hosts)) if (scope.sites.includes(h.site) || dashHosts.has(h.host_id)) ids.add(h.host_id);
  }
  const out: RecompileOutcome[] = [];
  for (const id of [...ids].sort()) {
    if (!world.hosts[id]) continue;
    out.push(await recompileInWorld(env, key, world, id));
  }
  return out;
}

/** The stored document with credentials decrypted. Plaintext only ever leaves via the agent response. */
export async function openDesiredDoc(env: Env, docJson: string): Promise<Record<string, unknown>> {
  const key = await masterKey(env.EXP_MASTER_KEY);
  const doc = JSON.parse(docJson) as { host_id: string; components?: Array<{ component_id: string; creds?: Record<string, string> }> };
  for (const c of doc.components ?? []) {
    const creds = c.creds ?? {};
    for (const [name, value] of Object.entries(creds)) {
      if (isEncryptedCred(value)) creds[name] = await openCred(key, value, credAad(doc.host_id, c.component_id, name));
    }
  }
  return doc as unknown as Record<string, unknown>;
}
