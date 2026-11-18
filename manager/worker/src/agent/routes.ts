// Agent API (01-contracts.md section 6, 05-manager.md section 8). Base /api/agent/v1.
import { Hono } from "hono";
import type { ZodError } from "zod";
import { auditStmt } from "../audit/audit";
import { openDesiredDoc, recompile } from "../compile/recompile";
import type { AppBindings, Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { ApiError, ConfigError, forbidden, invalidRequest, invalidToken, notFound, unavailable } from "../errors";
import { onStatusStored } from "../fleet-hooks";
import { hostSampleOf, mgmtNet } from "../fleet/rollup";
import { enforce } from "../ratelimit";
import { masterKey } from "../secrets/crypto";
import { ROTATION_GRACE_S } from "../secrets/store";
import { newToken, tokenHash } from "../secrets/tokens";
import { readJson, readLimited } from "../util/body";
import { ARTIFACT_ID_RE, SEMVER_RE } from "../util/ids";
import { isoAt, isoNow, nowMs } from "../util/time";
import { agentAuth } from "./auth";
import { EnrolSchema, StatusSchema, type StatusReport } from "./status-schema";

export const MAX_STATUS_BYTES = 256 * 1024;
export const MAX_ENROL_BYTES = 64 * 1024;
const STATUS_HISTORY_KEEP = 100;

export const agentRoutes = new Hono<AppBindings>();

function zodDetails(err: ZodError): Record<string, unknown> {
  return {
    errors: err.issues.slice(0, 20).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 200) })),
  };
}

async function requireKey(env: Env): Promise<CryptoKey> {
  try {
    return await masterKey(env.EXP_MASTER_KEY);
  } catch (e) {
    if (e instanceof ConfigError) throw unavailable(e.message);
    throw e;
  }
}

// ---- enrol -----------------------------------------------------------------------------------
agentRoutes.post("/enrol", async (c) => {
  const env = c.env;
  const ip = c.get("ip");
  await enforce(env.RL_ENROL, `enrol:${ip}`);
  const raw = await readJson(c.req.raw, MAX_ENROL_BYTES);
  const parsed = EnrolSchema.safeParse(raw);
  if (!parsed.success) throw invalidRequest("schema validation failed", zodDetails(parsed.error));
  const { token, facts } = parsed.data;
  await requireKey(env); // fail closed before burning the token if the server cannot store secrets

  const hash = await tokenHash(token);
  const tok = await env.DB.prepare("SELECT host_id, expires_at, used_at FROM enrol_tokens WHERE token_hash = ?1")
    .bind(hash)
    .first<{ host_id: string; expires_at: string; used_at: string | null }>();
  if (!tok) throw new ApiError(401, "invalid_token", "unknown enrol token");
  const gone = () => new ApiError(410, "token_used_or_expired", "enrol token already used or expired");
  if (tok.used_at || tok.expires_at <= isoNow()) throw gone();
  const host = await env.DB.prepare("SELECT host_id, state FROM hosts WHERE host_id = ?1")
    .bind(tok.host_id)
    .first<{ host_id: string; state: string }>();
  if (!host || host.state === "removed" || host.state === "decommissioning") throw gone();

  // Atomic single use: only one concurrent request changes a row.
  const now = isoNow();
  const used = await env.DB.prepare(
    "UPDATE enrol_tokens SET used_at = ?1, updated_at = ?1 WHERE token_hash = ?2 AND used_at IS NULL AND expires_at > ?1",
  )
    .bind(now, hash)
    .run();
  if ((used.meta.changes ?? 0) !== 1) throw gone();

  const secret = newToken("expa");
  const secretHash = await tokenHash(secret);
  const hostId = host.host_id;
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO agent_creds (host_id, org_id, secret_hash, previous_hash, previous_valid_until, revoked_at, created_at, updated_at)
       VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, ?4)
       ON CONFLICT(host_id) DO UPDATE SET secret_hash = excluded.secret_hash, previous_hash = NULL,
         previous_valid_until = NULL, revoked_at = NULL, updated_at = excluded.updated_at`,
    ).bind(hostId, DEFAULT_ORG, secretHash, now),
    env.DB.prepare(
      `UPDATE hosts SET state = 'enrolled', facts_json = ?2, arch = ?3, enrolled_at = ?4, last_seen = ?4, updated_at = ?4
       WHERE host_id = ?1`,
    ).bind(hostId, JSON.stringify(facts), facts.arch, now),
    auditStmt(env.DB, { actor: `agent:${hostId}`, action: "host.enrol", resource: `host:${hostId}`, details: { hostname: facts.hostname, arch: facts.arch }, ip }),
  ]);
  try {
    await recompile(env, { hostIds: [hostId] });
  } catch (e) {
    // the host is enrolled; the document is (re)compiled on its first poll if this failed
    console.error("enrol: initial compile failed", e instanceof Error ? e.name : "error");
  }
  const s = await env.DB.prepare("SELECT agent_poll_interval_s FROM settings WHERE org_id = ?1").bind(DEFAULT_ORG).first<{ agent_poll_interval_s: number }>();
  return c.json(
    {
      agent_id: hostId,
      agent_secret: secret,
      poll_interval_s: s?.agent_poll_interval_s ?? 30,
      release_pubkey_pem: env.RELEASE_PUBKEY_PEM ?? "",
      manager_time: isoNow(),
    },
    201,
    { "cache-control": "no-store" },
  );
});

// ---- authenticated routes --------------------------------------------------------------------
const authed = new Hono<AppBindings>();
authed.use("*", agentAuth);

function etagMatches(header: string | undefined, etag: string): boolean {
  if (!header) return false;
  return header
    .split(",")
    .map((p) => p.trim().replace(/^W\//, ""))
    .some((p) => p === etag || p === "*");
}

authed.get("/desired", async (c) => {
  const agent = c.get("agent");
  if (!agent) throw invalidToken();
  let version = agent.desiredVersion;
  if (version === null) {
    // enrolled but nothing compiled yet (e.g. the enrol-time compile failed): compile once, lazily
    try {
      await recompile(c.env, { hostIds: [agent.hostId] });
    } catch (e) {
      if (e instanceof ConfigError) throw unavailable(e.message);
      throw e;
    }
    const r = await c.env.DB.prepare("SELECT version FROM desired_docs WHERE host_id = ?1").bind(agent.hostId).first<{ version: number }>();
    if (!r) throw new ApiError(404, "not_found", "no desired state for this host yet");
    version = r.version;
  }
  const etag = `"${agent.hostId}:${version}"`;
  if (etagMatches(c.req.header("If-None-Match"), etag)) {
    return new Response(null, { status: 304, headers: { etag } });
  }
  const row = await c.env.DB.prepare("SELECT doc_json, version FROM desired_docs WHERE host_id = ?1")
    .bind(agent.hostId)
    .first<{ doc_json: string; version: number }>();
  if (!row) throw new ApiError(404, "not_found", "no desired state for this host yet");
  let doc: Record<string, unknown>;
  try {
    doc = await openDesiredDoc(c.env, row.doc_json);
  } catch (e) {
    if (e instanceof ConfigError) throw unavailable("cannot decrypt desired state");
    throw e;
  }
  return new Response(JSON.stringify(doc), {
    status: 200,
    headers: { "content-type": "application/json", etag: `"${agent.hostId}:${row.version}"`, "cache-control": "no-store" },
  });
});

authed.get("/releases/:version/manifest", async (c) => {
  const v = c.req.param("version");
  if (!SEMVER_RE.test(v)) throw notFound("no such release");
  const rel = await c.env.DB.prepare("SELECT manifest_r2_key FROM releases WHERE version = ?1").bind(v).first<{ manifest_r2_key: string }>();
  if (!rel) throw notFound("no such release");
  const obj = await c.env.ARTIFACTS.get(rel.manifest_r2_key);
  if (!obj) throw notFound("manifest object missing");
  // the exact stored bytes: never re-serialized (they are what was signed)
  return new Response(obj.body, { status: 200, headers: { "content-type": "application/json", "cache-control": "private, max-age=60" } });
});

authed.get("/releases/:version/manifest.sig", async (c) => {
  const v = c.req.param("version");
  if (!SEMVER_RE.test(v)) throw notFound("no such release");
  const rel = await c.env.DB.prepare("SELECT signature FROM releases WHERE version = ?1").bind(v).first<{ signature: string }>();
  if (!rel) throw notFound("no such release");
  return new Response(rel.signature, { status: 200, headers: { "content-type": "text/plain", "cache-control": "private, max-age=60" } });
});

authed.get("/artifacts/:id", async (c) => {
  const agent = c.get("agent");
  if (!agent) throw invalidToken();
  const id = c.req.param("id");
  const ref = await c.env.DB.prepare("SELECT artifacts_json FROM desired_docs WHERE host_id = ?1").bind(agent.hostId).first<{ artifacts_json: string }>();
  let allowed: unknown = [];
  try {
    allowed = ref ? JSON.parse(ref.artifacts_json) : [];
  } catch {
    allowed = [];
  }
  // 403 unless this artifact is referenced by THIS host's current desired document (SR-6)
  if (!ARTIFACT_ID_RE.test(id) || !Array.isArray(allowed) || !allowed.includes(id)) {
    throw forbidden("artifact is not referenced by this host's desired state");
  }
  const art = await c.env.DB.prepare("SELECT r2_key, sha256, size FROM artifacts WHERE artifact_id = ?1")
    .bind(id)
    .first<{ r2_key: string; sha256: string; size: number }>();
  if (!art) throw notFound("artifact not available");
  const etag = `"${art.sha256}"`;
  if (etagMatches(c.req.header("If-None-Match"), etag)) return new Response(null, { status: 304, headers: { etag } });
  const obj = await c.env.ARTIFACTS.get(art.r2_key);
  if (!obj) throw notFound("artifact object missing");
  return new Response(obj.body, {
    status: 200,
    headers: { "content-type": "application/gzip", "content-length": String(obj.size), etag, "cache-control": "private, max-age=3600" },
  });
});

authed.post("/status", async (c) => {
  const agent = c.get("agent");
  if (!agent) throw invalidToken();
  const env = c.env;
  const bytes = await readLimited(c.req.raw, MAX_STATUS_BYTES);
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    throw invalidRequest("body is not valid JSON");
  }
  const parsed = StatusSchema.safeParse(raw);
  if (!parsed.success) throw invalidRequest("status report failed schema validation", zodDetails(parsed.error));
  const report = parsed.data;
  const now = isoNow();
  const hostId = agent.hostId;

  const host = await env.DB.prepare("SELECT host_id, site, state FROM hosts WHERE host_id = ?1").bind(hostId).first<{ host_id: string; site: string; state: string }>();
  if (!host) throw invalidToken();
  const existing = await env.DB.prepare("SELECT component_id, type, slug, facts_json FROM components WHERE host_id = ?1")
    .bind(hostId)
    .all<{ component_id: string; type: string; slug: string; facts_json: string }>();
  const byKey = new Map((existing.results ?? []).map((r) => [`${r.type}/${r.slug}`, r]));

  const stmts: D1PreparedStatement[] = [];
  const reportJson = JSON.stringify(report);
  stmts.push(
    env.DB.prepare(
      `INSERT INTO status_latest (host_id, org_id, received_at, report_json, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?3, ?3)
       ON CONFLICT(host_id) DO UPDATE SET received_at = excluded.received_at, report_json = excluded.report_json, updated_at = excluded.updated_at`,
    ).bind(hostId, DEFAULT_ORG, now, reportJson),
    env.DB.prepare(
      `INSERT INTO status_history (org_id, host_id, received_at, report_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?3, ?3)`,
    ).bind(DEFAULT_ORG, hostId, now, reportJson),
    env.DB.prepare(
      `DELETE FROM status_history WHERE host_id = ?1 AND hist_id <=
         COALESCE((SELECT hist_id FROM status_history WHERE host_id = ?1 ORDER BY hist_id DESC LIMIT 1 OFFSET ?2), 0)`,
    ).bind(hostId, STATUS_HISTORY_KEEP),
    env.DB.prepare(
      `UPDATE hosts SET last_seen = ?2, agent_version = ?3, applied_version = ?4, facts_json = ?5, arch = ?6, latest_json = ?7,
         status_interval_s = COALESCE(?8, status_interval_s),
         state = CASE WHEN state IN ('stale','offline') THEN 'enrolled' ELSE state END, updated_at = ?2
       WHERE host_id = ?1`,
    ).bind(
      hostId, now, report.agent.version, report.agent.applied_version ?? null, JSON.stringify(report.facts), report.facts.arch,
      JSON.stringify(latestHost(report)), report.metrics.interval_s ?? null,
    ),
  );

  let wiringChanged = false;
  for (const rc of report.components) {
    const row = byKey.get(`${rc.type}/${rc.id}`);
    if (!row) continue; // reported components we do not know are ignored, never created
    const facts = {
      tls_fingerprint_sha256: rc.facts?.tls_fingerprint_sha256,
      listen: rc.facts?.listen,
      url: rc.facts?.url,
    };
    const next = {
      health: rc.health,
      state: rc.state,
      detail: rc.detail ?? "",
      version: rc.version ?? null,
      since: rc.since ?? null,
      facts,
      // latest numeric health metrics + process figures: fleet tables read these, never full reports
      metrics: latestMetrics(rc.metrics),
      process: latestProcess(rc.process),
    };
    let prevFacts: Record<string, unknown> = {};
    try {
      const p = JSON.parse(row.facts_json) as { facts?: Record<string, unknown> };
      prevFacts = p.facts ?? {};
    } catch {
      prevFacts = {};
    }
    if (
      (rc.type === "collector" || rc.type === "dashboard") &&
      (prevFacts.tls_fingerprint_sha256 !== facts.tls_fingerprint_sha256 || prevFacts.listen !== facts.listen || prevFacts.url !== facts.url)
    ) {
      wiringChanged = true;
    }
    stmts.push(
      env.DB.prepare("UPDATE components SET facts_json = ?2, updated_at = ?3 WHERE component_id = ?1").bind(row.component_id, JSON.stringify(next), now),
    );
  }
  await env.DB.batch(stmts);

  if (wiringChanged) {
    // collector listen / pin or dashboard url changed: probes, collectors and dashboards recompile
    try {
      await recompile(env, { all: true });
    } catch (e) {
      console.error("status: wiring recompile failed", e instanceof Error ? e.name : "error");
    }
  }
  try {
    await onStatusStored(env, { hostId, site: host.site, receivedAt: now, report, components: existing.results ?? [] });
  } catch (e) {
    console.error("status: fleet hook failed", e instanceof Error ? e.name : "error");
  }
  return new Response(null, { status: 204 });
});

authed.post("/rotate", async (c) => {
  const agent = c.get("agent");
  if (!agent) throw invalidToken();
  const env = c.env;
  await readEmptyObject(c.req.raw);
  const doc = await env.DB.prepare("SELECT doc_json FROM desired_docs WHERE host_id = ?1").bind(agent.hostId).first<{ doc_json: string }>();
  let hasAction = false;
  try {
    const d = JSON.parse(doc?.doc_json ?? "{}") as { actions?: Array<{ type?: string }> };
    hasAction = (d.actions ?? []).some((a) => a.type === "rotate_agent_secret");
  } catch {
    hasAction = false;
  }
  if (!hasAction) throw new ApiError(409, "no_rotate_action", "desired state carries no rotate_agent_secret action");

  const cur = await env.DB.prepare("SELECT secret_hash, revoked_at FROM agent_creds WHERE host_id = ?1").bind(agent.hostId).first<{ secret_hash: string; revoked_at: string | null }>();
  if (!cur || cur.revoked_at) throw invalidToken();
  const hostRow = await env.DB.prepare("SELECT actions_json FROM hosts WHERE host_id = ?1").bind(agent.hostId).first<{ actions_json: string }>();
  let actions: Array<{ type?: string }> = [];
  try {
    actions = JSON.parse(hostRow?.actions_json ?? "[]") as Array<{ type?: string }>;
  } catch {
    actions = [];
  }
  const secret = newToken("expa");
  const newHash = await tokenHash(secret);
  const now = isoNow();
  const [cas] = await env.DB.batch([
    // compare-and-swap on the current hash: a concurrent rotation loses with changes = 0
    env.DB.prepare(
      `UPDATE agent_creds SET previous_hash = secret_hash, previous_valid_until = ?2, secret_hash = ?3, updated_at = ?4
       WHERE host_id = ?1 AND secret_hash = ?5`,
    ).bind(agent.hostId, isoAt(nowMs() + ROTATION_GRACE_S * 1000), newHash, now, cur.secret_hash),
    env.DB.prepare("UPDATE hosts SET actions_json = ?2, updated_at = ?3 WHERE host_id = ?1 AND EXISTS (SELECT 1 FROM agent_creds WHERE host_id = ?1 AND secret_hash = ?4)")
      .bind(agent.hostId, JSON.stringify(actions.filter((a) => a.type !== "rotate_agent_secret")), now, newHash),
    auditStmt(env.DB, { actor: `agent:${agent.hostId}`, action: "agent.rotate", resource: `host:${agent.hostId}`, details: { grace_s: ROTATION_GRACE_S }, ip: c.get("ip") }),
  ]);
  if ((cas?.meta.changes ?? 0) !== 1) throw new ApiError(409, "rotation_conflict", "another rotation is in progress");
  try {
    await recompile(env, { hostIds: [agent.hostId] }); // the action is consumed: the document changes once
  } catch (e) {
    console.error("rotate: recompile failed", e instanceof Error ? e.name : "error");
  }
  return c.json({ agent_secret: secret, grace_s: ROTATION_GRACE_S }, 200, { "cache-control": "no-store" });
});

authed.post("/decommissioned", async (c) => {
  const agent = c.get("agent");
  if (!agent) throw invalidToken();
  const env = c.env;
  await readEmptyObject(c.req.raw);
  const host = await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(agent.hostId).first<{ state: string }>();
  if (!host || host.state !== "decommissioning") {
    throw new ApiError(409, "not_decommissioning", "desired state does not carry decommission: true");
  }
  const now = isoNow();
  await env.DB.batch([
    env.DB.prepare("UPDATE agent_creds SET revoked_at = ?2, updated_at = ?2 WHERE host_id = ?1").bind(agent.hostId, now),
    env.DB.prepare("UPDATE hosts SET state = 'removed', updated_at = ?2 WHERE host_id = ?1").bind(agent.hostId, now),
    auditStmt(env.DB, { actor: `agent:${agent.hostId}`, action: "agent.decommissioned", resource: `host:${agent.hostId}`, ip: c.get("ip") }),
  ]);
  return new Response(null, { status: 204 });
});

const LATEST_COMPONENT_KEYS = [
  "measurements_per_min", "fail_per_min", "error_per_min", "spool_depth", "spool_bytes", "push_lag_s", "clock_offset_ms",
  "ingest_records_per_s", "ingest_rejected_per_min", "ingest_duplicates_per_min", "probes_total", "probes_reporting",
  "vm_up", "vm_backlog_points", "vm_storage_gb", "records_db_gb", "storage_free_gb", "days_to_full", "open_incidents",
  "sessions_active", "requests_per_min", "collectors_total", "collectors_reachable", "login_failures_1h", "drills_active",
];

function latestMetrics(m: Record<string, unknown> | undefined): Record<string, number> {
  const out: Record<string, number> = {};
  for (const k of LATEST_COMPONENT_KEYS) {
    const v = m?.[k];
    if (typeof v === "number" && Number.isFinite(v)) out[k] = v;
  }
  return out;
}

function latestProcess(p: { cpu_pct?: number | null; rss_mb?: number | null; restarts?: number | null; uptime_s?: number | null } | undefined) {
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(p ?? {})) if (typeof v === "number" && Number.isFinite(v)) out[k] = v;
  return out;
}

/** Compact latest host figures for the fleet tables (null = not reported, never zero). */
function latestHost(report: StatusReport): Record<string, unknown> {
  const s = hostSampleOf(report);
  const mg = mgmtNet(report);
  const n = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
  return {
    cpu_pct: s.cpu,
    mem_pct: s.mem,
    disk_pct_max: s.disk,
    load1: s.load1,
    uptime_s: n(report.metrics.uptime_s),
    temp_c_max: n(report.metrics.temp_c_max),
    net: s.net ? { rx_pps: s.net.rxPps, tx_pps: s.net.txPps, rx_bps: s.net.rxBps, tx_bps: s.net.txBps, iface: mg?.iface ?? null } : null,
  };
}

async function readEmptyObject(req: Request): Promise<void> {
  const body = await readJson(req, 4096);
  if (body === undefined) return;
  if (body === null || typeof body !== "object" || Array.isArray(body) || Object.keys(body).length > 0) {
    throw invalidRequest("body must be an empty JSON object {}");
  }
}

agentRoutes.route("/", authed);
