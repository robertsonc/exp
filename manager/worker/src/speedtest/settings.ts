// Speedtest settings of a site (12-speedtest-analytics.md section 8, shared/openapi/admin.yaml tag `speedtest`):
// branding, consent text with versioning (+ history), zones and subnet labels, limits, targets, internet-leg pause,
// privacy, serve/TLS/DNS leg, the logo artifact, per-zone QR signage data, the provided TLS pair and the per-org
// device_key secret. The manager only ever holds INTENT here: it receives no test result and no evidence (SR-20),
// and no route in this file accepts or returns one.
import { auditStmt } from "../audit/audit";
import { DEFAULT_CONSENT_TEXT, effectiveServe, speedtestTlsMode } from "../compile/speedtest";
import { loadWorld, parseJson } from "../compile/load";
import { recompile } from "../compile/recompile";
import { DEVICE_KEY_KIND, DEVICE_KEY_OWNER, SPEEDTEST_TLS_KIND, speedtestTlsOwner } from "../compile/wiring";
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { ApiError, invalidRequest, notFound } from "../errors";
import { getSecretByOwner, prepareCreateSecret, prepareSetSecret, readSecret } from "../secrets/store";
import { newToken } from "../secrets/tokens";
import { readLimited } from "../util/body";
import { sha256Hex } from "../util/encoding";
import { SLUG_RE, newId } from "../util/ids";
import { isoNow } from "../util/time";
import type { Actor } from "../admin/service";
import { MAX_CERT_PEM, MAX_KEY_PEM, TlsError, parseCertDer, pemBlocks, validateProvidedTls } from "../tls/cert";
import { z } from "zod";
import { SettingsPutSchema } from "./schemas";
import { LOGO_MAX_BYTES, checkLogo } from "./logo";

type Obj = Record<string, unknown>;
const zIssues = (e: z.ZodError) => ({ errors: e.issues.slice(0, 10).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })) });

interface Row {
  site: string;
  settings_json: string;
  consent_text: string;
  consent_version: number;
  paused: number;
  logo_artifact_id: string | null;
  logo_content_type: string | null;
  created_at: string;
  updated_at: string;
}

async function siteExists(env: Env, site: string): Promise<void> {
  if (!SLUG_RE.test(site)) throw notFound("no such site");
  const s = await env.DB.prepare("SELECT 1 AS x FROM sites WHERE site = ?1").bind(site).first();
  if (!s) throw notFound("no such site");
}
const rowOf = (env: Env, site: string): Promise<Row | null> => env.DB.prepare("SELECT * FROM speedtest_settings WHERE site = ?1").bind(site).first<Row>();

/** `device_key` state: whether the per-org secret exists and when it last changed. The value is never read here. */
export async function deviceKeyState(env: Env): Promise<{ set: boolean; updated_at: string | null; key_id: string | null }> {
  const r = await env.DB.prepare("SELECT version, updated_at FROM secrets WHERE owner_ref = ?1 AND kind = ?2").bind(DEVICE_KEY_OWNER, DEVICE_KEY_KIND).first<{ version: number; updated_at: string }>();
  return r ? { set: true, updated_at: r.updated_at, key_id: `k${r.version}` } : { set: false, updated_at: null, key_id: null };
}

export async function getSettings(env: Env, site: string) {
  await siteExists(env, site);
  const r = await rowOf(env, site);
  const s = parseJson<Obj>(r?.settings_json, {});
  const branding: Obj = { ...(s.branding as Obj | undefined) };
  if (r?.logo_artifact_id) branding.logo_artifact = r.logo_artifact_id;
  else delete branding.logo_artifact;
  const dk = await deviceKeyState(env);
  const out: Obj = {
    ...s,
    ...(Object.keys(branding).length ? { branding } : {}),
    internet_leg: { ...(s.internet_leg as Obj | undefined), paused: r?.paused === 1 },
    consent: r && r.consent_text ? { text: r.consent_text, version: r.consent_version } : { text: DEFAULT_CONSENT_TEXT, version: 1 },
    device_key: { set: dk.set, updated_at: dk.updated_at },
  };
  if (r) out.updated_at = r.updated_at;
  return out;
}

const VERSION_MAX = 1_000_000;

export async function putSettings(env: Env, actor: Actor, site: string, body: unknown) {
  await siteExists(env, site);
  const p = SettingsPutSchema.safeParse(body);
  if (!p.success) throw invalidRequest("settings failed validation", zIssues(p.error));
  const d = p.data;
  const cur = await rowOf(env, site);

  // zones and labels must agree
  if (d.zones) {
    const ids = d.zones.map((z) => z.id);
    if (new Set(ids).size !== ids.length) throw invalidRequest("zone ids must be unique");
  }
  if (d.zone_labels) {
    const cidrs = d.zone_labels.subnets.map((s) => s.cidr);
    if (new Set(cidrs).size !== cidrs.length) throw invalidRequest("zone_labels subnets must be unique");
    if (d.zones && d.zones.length > 0) {
      const known = new Set(d.zones.map((z) => z.id));
      const bad = d.zone_labels.subnets.find((s) => !known.has(s.zone));
      if (bad) throw invalidRequest(`zone_labels refers to unknown zone ${bad.zone}`);
    }
  }
  // NAT guard (D15): requiring the real client IP needs the attendee subnets to compare against
  if (d.serve?.require_real_client_ip === true && !(d.serve.client_subnets?.length || d.zone_labels?.subnets.length)) {
    throw invalidRequest("serve.require_real_client_ip needs serve.client_subnets or zone_labels.subnets (the attendee subnets)");
  }
  if (d.dns_leg?.enabled === true && !d.dns_leg.zone) throw invalidRequest("dns_leg.enabled needs dns_leg.zone");
  // the logo is managed by POST .../logo: PUT may only keep it (same id / omitted) or remove it (null)
  const wantLogo = d.branding?.logo_artifact;
  if (typeof wantLogo === "string" && wantLogo !== cur?.logo_artifact_id) throw invalidRequest("branding.logo_artifact can only be set by uploading a logo");
  if (d.tls?.mode === "provided" && !(await getSecretByOwner(env, speedtestTlsOwner(site), SPEEDTEST_TLS_KIND))) {
    throw invalidRequest("tls.mode provided needs a certificate pair first (PUT sites/{site}/speedtest/tls)");
  }
  if (d.serve?.listen_ip) await checkListenIp(env, site, d.serve.listen_ip);

  const now = isoNow();
  const { consent, ...rest } = d;
  const stored: Obj = { ...rest };
  if (rest.branding) {
    const { logo_artifact: _drop, ...b } = rest.branding;
    if (Object.keys(b).length) stored.branding = b;
    else delete stored.branding;
  }
  let paused = cur?.paused === 1;
  if (rest.internet_leg) {
    const { paused: pz, ...il } = rest.internet_leg;
    if (pz !== undefined) paused = pz;
    if (Object.keys(il).length) stored.internet_leg = il;
    else delete stored.internet_leg;
  }
  // consent versioning: a changed text is a new version; the history keeps every one
  const first = !cur || !cur.consent_text;
  const changed = !first && consent.text !== cur.consent_text;
  const version = first ? 1 : changed ? cur.consent_version + 1 : cur.consent_version;
  if (version > VERSION_MAX) throw new ApiError(409, "conflict", "consent version limit reached");
  const removeLogo = wantLogo === null && !!cur?.logo_artifact_id;
  const logoId = removeLogo ? null : (cur?.logo_artifact_id ?? null);
  const stmts: D1PreparedStatement[] = [
    env.DB.prepare(
      `INSERT INTO speedtest_settings (site, org_id, settings_json, consent_text, consent_version, paused, logo_artifact_id, logo_content_type, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
       ON CONFLICT(site) DO UPDATE SET settings_json = excluded.settings_json, consent_text = excluded.consent_text, consent_version = excluded.consent_version,
         paused = excluded.paused, logo_artifact_id = excluded.logo_artifact_id, logo_content_type = excluded.logo_content_type, updated_at = excluded.updated_at`,
    ).bind(site, DEFAULT_ORG, JSON.stringify(stored), consent.text, version, paused ? 1 : 0, logoId, removeLogo ? null : (cur?.logo_content_type ?? null), now),
  ];
  if (first || changed) {
    stmts.push(env.DB.prepare("INSERT INTO speedtest_consent_history (site, version, text, changed_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5)").bind(site, version, consent.text, actor.email, now));
  }
  stmts.push(
    auditStmt(env.DB, {
      actor: actor.email,
      action: "speedtest.settings",
      resource: `site:${site}`,
      details: { fields: Object.keys(stored), consent_version: version, consent_changed: first || changed, logo_removed: removeLogo, paused },
      ip: actor.ip,
    }),
  );
  try {
    await env.DB.batch(stmts);
  } catch (e) {
    // a concurrent edit took the same consent version (primary key): ask the caller to retry
    if (/UNIQUE|constraint/i.test(String((e as Error)?.message))) throw new ApiError(409, "conflict", "the settings changed concurrently; reload and retry");
    throw e;
  }
  if (removeLogo && cur?.logo_artifact_id) await dropLogoArtifact(env, cur.logo_artifact_id);
  await recompile(env, { all: true });
  return getSettings(env, site);
}

/** `serve.listen_ip` must be an address of a speedtest host of the site, when that host has reported its interfaces. */
async function checkListenIp(env: Env, site: string, ip: string): Promise<void> {
  const world = await loadWorld(env);
  const hosts = world.components.filter((c) => c.type === "speedtest" && c.enabled && world.hosts[c.host_id]?.site === site).map((c) => world.hosts[c.host_id]!);
  const known = hosts.filter((h) => (h.facts.interfaces ?? []).some((i) => (i.addrs ?? []).length > 0));
  if (known.length === 0) return;
  const owns = known.some((h) => (h.facts.interfaces ?? []).some((i) => (i.addrs ?? []).some((a) => a.split("/")[0] === ip)));
  if (!owns) throw invalidRequest(`serve.listen_ip ${ip} is not an interface address of the speedtest host`);
}

// ---- consent history ---------------------------------------------------------------------------------------------
export async function consentHistory(env: Env, site: string) {
  await siteExists(env, site);
  const rows = (await env.DB.prepare("SELECT version, text, changed_by, created_at FROM speedtest_consent_history WHERE site = ?1 ORDER BY version DESC LIMIT 200").bind(site).all<{ version: number; text: string; changed_by: string; created_at: string }>()).results ?? [];
  return { items: rows };
}

// ---- internet-leg pause ------------------------------------------------------------------------------------------
export async function setPause(env: Env, actor: Actor, site: string, paused: boolean) {
  await siteExists(env, site);
  const now = isoNow();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO speedtest_settings (site, org_id, paused, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)
       ON CONFLICT(site) DO UPDATE SET paused = excluded.paused, updated_at = excluded.updated_at`,
    ).bind(site, DEFAULT_ORG, paused ? 1 : 0, now),
    auditStmt(env.DB, { actor: actor.email, action: "speedtest.internet_pause", resource: `site:${site}`, details: { paused }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
  return { paused, updated_at: now };
}

// ---- logo ----------------------------------------------------------------------------------------------------------
const LOGO_TYPES = ["image/png", "image/svg+xml", "image/jpeg"] as const;

/** Deletes a logo artifact (row + object) unless another site's settings still point at it (identical images share one artifact). */
async function dropLogoArtifact(env: Env, artifactId: string): Promise<void> {
  const still = await env.DB.prepare("SELECT 1 AS x FROM speedtest_settings WHERE logo_artifact_id = ?1 LIMIT 1").bind(artifactId).first();
  if (still) return;
  const a = await env.DB.prepare("SELECT r2_key FROM artifacts WHERE artifact_id = ?1 AND component = 'speedtest-logo'").bind(artifactId).first<{ r2_key: string }>();
  if (!a) return;
  await env.DB.prepare("DELETE FROM artifacts WHERE artifact_id = ?1").bind(artifactId).run();
  await env.ARTIFACTS.delete(a.r2_key).catch(() => undefined);
}

export async function uploadLogo(env: Env, actor: Actor, site: string, req: Request) {
  await siteExists(env, site);
  const ct = (req.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (!(LOGO_TYPES as readonly string[]).includes(ct)) throw new ApiError(415, "unsupported_media_type", "the logo must be image/png, image/svg+xml or image/jpeg");
  const bytes = await readLimited(req, LOGO_MAX_BYTES);
  if (bytes.length === 0) throw invalidRequest("an image body is required");
  const bad = checkLogo(ct, bytes);
  if (bad) throw invalidRequest(bad);
  const sha = await sha256Hex(bytes);
  const id = newId("art_");
  const version = `0.0.0-logo.${sha.slice(0, 12)}`;
  const name = `exp-speedtest-${version}-noarch.tar.gz`; // the desired-state artifact name pattern; the content is the raw image
  const key = `speedtest-logo/${sha}`;
  const cur = await rowOf(env, site);
  const dup = await env.DB.prepare("SELECT artifact_id FROM artifacts WHERE version = ?1 AND name = ?2").bind(version, name).first<{ artifact_id: string }>();
  const artifactId = dup?.artifact_id ?? id;
  try {
    await env.ARTIFACTS.put(key, bytes);
  } catch {
    throw new ApiError(503, "unavailable", "artifact storage is unavailable", {}, { "retry-after": "30" });
  }
  const now = isoNow();
  const stmts: D1PreparedStatement[] = [];
  if (!dup) {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO artifacts (artifact_id, org_id, version, name, component, arch, sha256, size, r2_key, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'speedtest-logo', 'noarch', ?5, ?6, ?7, ?8, ?8)`,
      ).bind(artifactId, DEFAULT_ORG, version, name, sha, bytes.length, key, now),
    );
  }
  stmts.push(
    env.DB.prepare(
      `INSERT INTO speedtest_settings (site, org_id, logo_artifact_id, logo_content_type, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)
       ON CONFLICT(site) DO UPDATE SET logo_artifact_id = excluded.logo_artifact_id, logo_content_type = excluded.logo_content_type, updated_at = excluded.updated_at`,
    ).bind(site, DEFAULT_ORG, artifactId, ct, now),
    auditStmt(env.DB, { actor: actor.email, action: "speedtest.logo", resource: `site:${site}`, details: { artifact: artifactId, content_type: ct, size: bytes.length, sha256: sha }, ip: actor.ip }),
  );
  await env.DB.batch(stmts);
  await recompile(env, { all: true });
  if (cur?.logo_artifact_id && cur.logo_artifact_id !== artifactId) await dropLogoArtifact(env, cur.logo_artifact_id);
  return { artifact: artifactId, sha256: sha, size: bytes.length, content_type: ct };
}

// ---- QR signage ----------------------------------------------------------------------------------------------------
/** One URL per zone, `http(s)://<hostname>/?z=<zone>`; the UI renders the QR codes (no server-side image). */
export async function qrData(env: Env, site: string) {
  await siteExists(env, site);
  const world = await loadWorld(env);
  const st = world.speedtest?.[site];
  const zones = Array.isArray(st?.settings.zones) ? (st?.settings.zones as Array<{ id: string; name: string }>) : [];
  const comp = world.components.filter((c) => c.type === "speedtest" && c.enabled && world.hosts[c.host_id]?.site === site).sort((a, b) => (a.created_at < b.created_at ? -1 : 1))[0];
  const serve: Obj = comp ? effectiveServe(world, comp) : isObjV(st?.settings.serve) ? (st?.settings.serve as Obj) : {};
  const host = typeof serve.hostname === "string" ? serve.hostname : typeof serve.listen_ip === "string" ? serve.listen_ip : null;
  if (!host) return { items: [] };
  const provided = comp ? speedtestTlsMode(world, comp) === "provided" : (isObjV(st?.settings.tls) && (st?.settings.tls as Obj).mode === "provided");
  const port = typeof serve.port === "number" ? `:${serve.port}` : "";
  const base = `${provided ? "https" : "http"}://${host}${port}`;
  return { items: zones.slice(0, 256).map((z) => ({ zone: z.id, name: z.name, url: `${base}/?z=${encodeURIComponent(z.id)}` })) };
}
const isObjV = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

// ---- provided TLS pair (additive route, CR-m6-manager) -------------------------------------------------------------------
const TlsPut = z.object({ cert_pem: z.string().min(1).max(MAX_CERT_PEM * 2), key_pem: z.string().min(1).max(MAX_KEY_PEM * 2) }).strict();

export async function getSpeedtestTls(env: Env, site: string) {
  await siteExists(env, site);
  const row = await getSecretByOwner(env, speedtestTlsOwner(site), SPEEDTEST_TLS_KIND);
  if (!row) return { set: false, updated_at: null, cert: null };
  const j = JSON.parse(await readSecret(env, row)) as { cert_pem: string };
  const first = pemBlocks(j.cert_pem, "CERTIFICATE")[0];
  const info = first ? await parseCertDer(first) : null;
  return {
    set: true,
    updated_at: row.updated_at ?? null,
    cert: info ? { subject: info.subject, issuer: info.issuer, not_before: info.not_before, not_after: info.not_after, sha256: info.sha256, san: info.san } : null,
  };
}

export async function putSpeedtestTls(env: Env, actor: Actor, site: string, body: unknown) {
  await siteExists(env, site);
  const p = TlsPut.safeParse(body);
  if (!p.success) throw invalidRequest("request failed validation", zIssues(p.error));
  let v;
  try {
    v = await validateProvidedTls(p.data.cert_pem, p.data.key_pem);
  } catch (e) {
    if (e instanceof TlsError) throw new ApiError(422, "invalid_config", e.message);
    throw e;
  }
  const owner = speedtestTlsOwner(site);
  const cur = await getSecretByOwner(env, owner, SPEEDTEST_TLS_KIND);
  const plaintext = JSON.stringify({ cert_pem: p.data.cert_pem, key_pem: p.data.key_pem });
  const write = cur ? await prepareSetSecret(env, cur, plaintext) : (await prepareCreateSecret(env, { ownerRef: owner, kind: SPEEDTEST_TLS_KIND, plaintext, secretId: `sec_${SPEEDTEST_TLS_KIND}_${site}` })).stmt;
  await env.DB.batch([
    write,
    auditStmt(env.DB, { actor: actor.email, action: "speedtest.tls", resource: `site:${site}`, details: { sha256: v.info.sha256, not_after: v.info.not_after, subject: v.info.subject, chain: v.chain, secret_set: true }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
  return getSpeedtestTls(env, site);
}

// ---- per-org device_key secret -------------------------------------------------------------------------------------------
/** Creates (once) or rotates the per-org device_key secret (32 random bytes, sealed with the master-key keyring). Never returned. */
export async function rotateDeviceKey(env: Env, actor: Actor) {
  const cur = await getSecretByOwner(env, DEVICE_KEY_OWNER, DEVICE_KEY_KIND);
  const secret = newToken("expk");
  const write = cur
    ? await prepareSetSecret(env, cur, secret)
    : (await prepareCreateSecret(env, { ownerRef: DEVICE_KEY_OWNER, kind: DEVICE_KEY_KIND, plaintext: secret, secretId: `sec_${DEVICE_KEY_KIND}_${DEVICE_KEY_OWNER}` })).stmt;
  await env.DB.batch([write, auditStmt(env.DB, { actor: actor.email, action: "speedtest.device_key", resource: "settings", details: { rotated: !!cur, secret_set: true }, ip: actor.ip })]);
  await recompile(env, { all: true });
  const st = await deviceKeyState(env);
  return { set: true, updated_at: st.updated_at ?? isoNow(), key_id: st.key_id ?? "k1" };
}
