// Loads the World (rows -> plain objects, secrets decrypted in memory) for the compiler.
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { keyRing, openWithRing, secretAad } from "../secrets/crypto";
import { type SecretRow, prepareCreateSecret } from "../secrets/store";
import { newSsoSecret, newToken } from "../secrets/tokens";
import { isoNow, nowMs } from "../util/time";
import {
  type ComponentType,
  type WAction,
  type WArtifact,
  type WComponent,
  type WDashboardUser,
  type WHost,
  type WHostFacts,
  type WNocToken,
  type WSecret,
  type WSite,
  type WWebhook,
  type World,
  secretKey,
} from "./types";
import { DASH_TOKEN_KIND, INGEST_KIND, SSO_KIND, WEBHOOK_KIND, requiredSecrets } from "./wiring";

export function parseJson<T>(s: unknown, fallback: T): T {
  if (typeof s !== "string") return fallback;
  try {
    const v = JSON.parse(s) as unknown;
    return (v ?? fallback) as T;
  } catch {
    return fallback;
  }
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

export async function ensureSettings(env: Env): Promise<void> {
  const now = isoNow();
  await env.DB.prepare(
    `INSERT OR IGNORE INTO settings (org_id, org_name, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)`,
  ).bind(DEFAULT_ORG, env.ORG_NAME || "", now).run();
}

/** Sanitized host facts: only the fields the compiler uses. */
export function factsForCompile(factsJson: unknown): WHostFacts {
  const f = parseJson<Record<string, unknown>>(factsJson, {});
  const out: WHostFacts = {};
  if (f.arch === "amd64" || f.arch === "arm64") out.arch = f.arch;
  if (Array.isArray(f.interfaces)) {
    out.interfaces = f.interfaces.filter(isObj).slice(0, 256).map((i) => ({
      name: String(i.name ?? ""),
      state: typeof i.state === "string" ? i.state : undefined,
      addrs: Array.isArray(i.addrs) ? i.addrs.filter((a): a is string => typeof a === "string").slice(0, 32) : [],
      default_route: i.default_route === true,
      in_use_by: typeof i.in_use_by === "string" ? i.in_use_by : undefined,
    }));
  }
  return out;
}

interface Rows {
  settings: Array<{ org_name: string; agent_poll_interval_s: number; agent_status_interval_s: number; manager_url: string | null }>;
  sites: Array<Record<string, unknown>>;
  hosts: Array<Record<string, unknown>>;
  components: Array<Record<string, unknown>>;
  users: Array<Record<string, unknown>>;
  nocs: Array<Record<string, unknown>>;
  hooks: Array<Record<string, unknown>>;
  arts: Array<Record<string, unknown>>;
  secrets: SecretRow[];
}

async function readRows(env: Env): Promise<Rows> {
  const q = (sql: string) => env.DB.prepare(sql);
  const r = await env.DB.batch([
    q("SELECT org_name, agent_poll_interval_s, agent_status_interval_s, manager_url FROM settings WHERE org_id = 'default'"),
    q("SELECT * FROM sites"),
    q("SELECT * FROM hosts WHERE state != 'removed'"),
    q("SELECT * FROM components"),
    q("SELECT dashboard_slug, username, role, hash FROM dashboard_users"),
    q("SELECT noc_id, dashboard_slug, label, hash, expires_at, revoked_at FROM noc_tokens"),
    q("SELECT webhook_id, site, format FROM webhooks"),
    q(`SELECT artifact_id, version, name, component, arch, sha256, size FROM artifacts
       WHERE version IN (SELECT release_version FROM sites WHERE release_version IS NOT NULL
                         UNION SELECT target_version FROM sites WHERE target_version IS NOT NULL)`),
    q(`SELECT * FROM secrets WHERE kind IN ('${INGEST_KIND}','${DASH_TOKEN_KIND}','${SSO_KIND}','${WEBHOOK_KIND}')`),
  ]);
  const rows = (i: number) => (r[i]?.results ?? []) as Array<Record<string, unknown>>;
  return {
    settings: rows(0) as unknown as Rows["settings"],
    sites: rows(1),
    hosts: rows(2),
    components: rows(3),
    users: rows(4),
    nocs: rows(5),
    hooks: rows(6),
    arts: rows(7),
    secrets: rows(8) as unknown as SecretRow[],
  };
}

function buildWorld(env: Env, rows: Rows, secrets: Record<string, WSecret>): World {
  const s = rows.settings[0];
  const sites: Record<string, WSite> = {};
  for (const r of rows.sites) {
    const site = String(r.site);
    sites[site] = {
      site,
      name: String(r.name),
      timezone: String(r.timezone ?? "UTC"),
      edge_label: String(r.edge_label ?? "EC"),
      release_version: (r.release_version as string | null) ?? null,
      target_version: (r.target_version as string | null) ?? null,
      canary_host_id: (r.canary_host_id as string | null) ?? null,
      canary_state: (r.canary_state as WSite["canary_state"]) ?? "none",
      event_net_reaches_mgmt: Number(r.event_net_reaches_mgmt) === 1,
      retention: parseJson(r.retention_json, {}),
      alerts: parseJson(r.alerts_json, {}),
    };
  }
  const hosts: Record<string, WHost> = {};
  for (const r of rows.hosts) {
    const host_id = String(r.host_id);
    hosts[host_id] = {
      host_id,
      name: String(r.name),
      site: String(r.site),
      state: r.state as WHost["state"],
      arch: (r.arch as string | null) ?? null,
      facts: factsForCompile(r.facts_json),
      actions: parseJson<WAction[]>(r.actions_json, []),
    };
  }
  const components: WComponent[] = rows.components.map((r) => {
    const f = parseJson<Record<string, unknown>>(r.facts_json, {});
    const nested = isObj(f.facts) ? f.facts : {};
    return {
      component_id: String(r.component_id),
      host_id: String(r.host_id),
      type: r.type as ComponentType,
      slug: String(r.slug),
      config: parseJson(r.config_json, {}),
      enabled: Number(r.enabled) === 1,
      facts: {
        tls_fingerprint_sha256: typeof nested.tls_fingerprint_sha256 === "string" ? nested.tls_fingerprint_sha256 : undefined,
        listen: typeof nested.listen === "string" ? nested.listen : undefined,
        url: typeof nested.url === "string" ? nested.url : undefined,
      },
      created_at: String(r.created_at),
    };
  });
  return {
    org: { id: DEFAULT_ORG, name: s?.org_name || env.ORG_NAME || "" },
    settings: {
      agent_poll_interval_s: s?.agent_poll_interval_s ?? 30,
      agent_status_interval_s: s?.agent_status_interval_s ?? 60,
    },
    manager_url: (env.MANAGER_URL && env.MANAGER_URL.trim()) || s?.manager_url || null,
    sites,
    hosts,
    components,
    secrets,
    dashboard_users: rows.users as unknown as WDashboardUser[],
    noc_tokens: rows.nocs as unknown as WNocToken[],
    webhooks: rows.hooks as unknown as WWebhook[],
    artifacts: rows.arts as unknown as WArtifact[],
    now: isoNow(),
  };
}

async function decryptAll(env: Env, rows: SecretRow[]): Promise<Record<string, WSecret>> {
  const ring = await keyRing(env);
  const out: Record<string, WSecret> = {};
  const now = nowMs();
  for (const r of rows) {
    const { plaintext } = await openWithRing(ring, { nonce: r.nonce, ciphertext: r.ciphertext }, secretAad(r.secret_id, r.kind, r.version), r.key_id);
    const prevValid = r.previous_hash && r.previous_valid_until && Date.parse(r.previous_valid_until) > now;
    out[secretKey(r.owner_ref, r.kind)] = { plaintext, hash: r.hash, previous_hash: prevValid ? r.previous_hash : null };
  }
  return out;
}

/** Create generated secrets the current intent needs but that do not exist yet (idempotent). */
async function provisionSecrets(env: Env, rows: Rows): Promise<boolean> {
  const bare = buildWorld(env, rows, {});
  const have = new Set(rows.secrets.map((s) => secretKey(s.owner_ref, s.kind)));
  const stmts: D1PreparedStatement[] = [];
  for (const need of requiredSecrets(bare)) {
    if (have.has(secretKey(need.ownerRef, need.kind))) continue;
    const isSso = need.kind === SSO_KIND;
    const { stmt } = await prepareCreateSecret(
      env,
      {
        ownerRef: need.ownerRef,
        kind: need.kind,
        plaintext: isSso ? newSsoSecret() : newToken(need.kind === DASH_TOKEN_KIND ? "expd" : "expi"),
        withHash: !isSso,
        secretId: `sec_${need.kind}_${need.ownerRef}`,
      },
      true,
    );
    stmts.push(stmt);
  }
  if (stmts.length) await env.DB.batch(stmts);
  return stmts.length > 0;
}

export async function loadWorld(env: Env): Promise<World> {
  await ensureSettings(env);
  let rows = await readRows(env);
  if (await provisionSecrets(env, rows)) rows = await readRows(env);
  const secrets = await decryptAll(env, rows.secrets);
  return buildWorld(env, rows, secrets);
}
