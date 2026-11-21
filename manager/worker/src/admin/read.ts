// Read side of the admin API: rows -> contract objects (admin.yaml). Nothing here ever returns a secret
// value; config objects are scrubbed of secret-looking keys as defence in depth.
import { parseJson } from "../compile/load";
import type { Env } from "../env";
import { invalidRequest, notFound } from "../errors";
import { canaryStateOut, compState, mgmtIpOf } from "../fleet/query";
import { COMPONENT_ID_RE, HOST_ID_RE, REL_ID_RE, SLUG_RE, newId } from "../util/ids";
import { decodeCursor, encodeCursor } from "../util/cursor";

const SECRETISH = /(password|passwd|passphrase|psk|secret|private_key|token|credential|api_?key)/i;

export function redact(v: unknown, depth = 0): unknown {
  if (depth > 8) return null;
  if (Array.isArray(v)) return v.slice(0, 500).map((x) => redact(x, depth + 1));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      out[k] = SECRETISH.test(k) && typeof x === "string" ? { set: true } : redact(x, depth + 1);
    }
    return out;
  }
  return v;
}

export const limitOf = (raw: string | undefined, def = 100): number => {
  if (raw === undefined) return def;
  if (!/^\d{1,4}$/.test(raw)) throw invalidRequest("limit must be an integer 1..1000");
  const n = Number(raw);
  if (n < 1 || n > 1000) throw invalidRequest("limit must be an integer 1..1000");
  return n;
};

// ---- sites --------------------------------------------------------------------------------------------
export function siteOut(r: Record<string, unknown>) {
  const ret = parseJson<Record<string, unknown>>(r.retention_json, {});
  return {
    site: r.site,
    name: r.name,
    timezone: r.timezone,
    edge_label: r.edge_label,
    release_version: r.release_version ?? null,
    target_version: r.target_version ?? null,
    canary_host_id: r.canary_host_id ?? null,
    canary_state: canaryStateOut(r.canary_state as string, r.canary_healthy_since as string | null),
    retention: Object.keys(ret).length ? ret : null,
    created_at: r.created_at,
    updated_at: r.updated_at,
  };
}

export async function getSite(env: Env, site: string) {
  if (!SLUG_RE.test(site)) throw notFound("no such site");
  const r = await env.DB.prepare("SELECT * FROM sites WHERE site = ?1").bind(site).first<Record<string, unknown>>();
  if (!r) throw notFound("no such site");
  return siteOut(r);
}

export async function listSites(env: Env, limit: number, cursor: string | undefined) {
  const cur = decodeCursor<{ k: string }>(cursor);
  const rows = (await env.DB.prepare("SELECT * FROM sites WHERE site > ?1 ORDER BY site LIMIT ?2").bind(cur?.k ?? "", limit + 1).all<Record<string, unknown>>()).results ?? [];
  const page = rows.slice(0, limit);
  return { items: page.map(siteOut), next_cursor: rows.length > limit ? encodeCursor({ k: page[page.length - 1]?.site }) : null };
}

// ---- hosts --------------------------------------------------------------------------------------------
const HOST_SQL = `SELECT h.*, (SELECT group_concat(DISTINCT c.type) FROM components c WHERE c.host_id = h.host_id) AS shape_list FROM hosts h`;

export function hostOut(r: Record<string, unknown>) {
  const facts = parseJson<Record<string, unknown>>(r.facts_json, {});
  const shapes = String(r.shape_list ?? "").split(",").filter((s) => ["probe", "collector", "dashboard", "runner", "speedtest"].includes(s)).sort();
  return {
    host_id: r.host_id,
    name: r.name,
    site: r.site,
    shapes,
    state: r.state,
    mgmt_ip: mgmtIpOf(String(r.facts_json ?? "{}")),
    facts: Object.keys(facts).length ? facts : null,
    last_seen: r.last_seen ?? null,
    agent_version: r.agent_version ?? null,
    desired_version: r.desired_version ?? null,
    applied_version: r.applied_version ?? null,
    created_at: r.created_at,
    updated_at: r.updated_at,
  };
}

export async function getHost(env: Env, id: string) {
  if (!HOST_ID_RE.test(id)) throw notFound("no such host");
  const r = await env.DB.prepare(`${HOST_SQL} WHERE h.host_id = ?1 AND h.state != 'removed'`).bind(id).first<Record<string, unknown>>();
  if (!r) throw notFound("no such host");
  return hostOut(r);
}

export async function listHosts(env: Env, q: { site?: string; state?: string; limit: number; cursor?: string }) {
  if (q.state && !["pending", "enrolled", "stale", "offline", "decommissioning", "removed"].includes(q.state)) throw invalidRequest("invalid state");
  const cur = decodeCursor<{ k: string }>(q.cursor);
  const where = ["h.host_id > ?1"];
  const args: unknown[] = [cur?.k ?? ""];
  if (q.site) (args.push(q.site), where.push(`h.site = ?${args.length}`));
  if (q.state) (args.push(q.state), where.push(`h.state = ?${args.length}`));
  else where.push("h.state != 'removed'");
  args.push(q.limit + 1);
  const rows = (await env.DB.prepare(`${HOST_SQL} WHERE ${where.join(" AND ")} ORDER BY h.host_id LIMIT ?${args.length}`).bind(...args).all<Record<string, unknown>>()).results ?? [];
  const page = rows.slice(0, q.limit);
  return { items: page.map(hostOut), next_cursor: rows.length > q.limit ? encodeCursor({ k: page[page.length - 1]?.host_id }) : null };
}

// ---- components ---------------------------------------------------------------------------------------
export function componentOut(r: Record<string, unknown>, rendered: Record<string, unknown> | null) {
  const st = compState({
    component_id: String(r.component_id),
    host_id: String(r.host_id),
    type: String(r.type),
    slug: String(r.slug),
    enabled: Number(r.enabled),
    facts_json: String(r.facts_json ?? "{}"),
  });
  const f = parseJson<Record<string, unknown>>(r.facts_json, {});
  const facts: Record<string, unknown> = { ...(f.facts && typeof f.facts === "object" ? (f.facts as Record<string, unknown>) : {}) };
  if (Object.keys(st.metrics).length) facts.metrics = st.metrics;
  if (f.process && typeof f.process === "object") facts.process = f.process;
  if (st.state) facts.state = st.state;
  if (typeof f.detail === "string" && f.detail) facts.detail = f.detail;
  return {
    component_id: r.component_id,
    host_id: r.host_id,
    type: r.type,
    id: r.slug,
    config: redact(parseJson(r.config_json, {})),
    rendered_config: rendered,
    enabled: Number(r.enabled) === 1,
    health: st.health,
    version: st.version,
    facts,
    created_at: r.created_at,
    updated_at: r.updated_at,
  };
}

/** The config the manager last compiled for each component of a host (never creds). */
async function renderedConfigs(env: Env, hostId: string): Promise<Map<string, Record<string, unknown>>> {
  const d = await env.DB.prepare("SELECT doc_json FROM desired_docs WHERE host_id = ?1").bind(hostId).first<{ doc_json: string }>();
  const doc = parseJson<{ components?: Array<{ component_id?: string; config?: Record<string, unknown> }> }>(d?.doc_json, {});
  const m = new Map<string, Record<string, unknown>>();
  for (const c of doc.components ?? []) if (c.component_id && c.config) m.set(c.component_id, redact(c.config) as Record<string, unknown>);
  return m;
}

export async function getComponent(env: Env, id: string) {
  if (!COMPONENT_ID_RE.test(id)) throw notFound("no such component");
  const r = await env.DB.prepare("SELECT * FROM components WHERE component_id = ?1").bind(id).first<Record<string, unknown>>();
  if (!r) throw notFound("no such component");
  const rendered = await renderedConfigs(env, String(r.host_id));
  return componentOut(r, rendered.get(id) ?? null);
}

export async function listHostComponents(env: Env, hostId: string, limit: number, cursor: string | undefined) {
  if (!HOST_ID_RE.test(hostId)) throw notFound("no such host");
  const h = await env.DB.prepare("SELECT 1 AS x FROM hosts WHERE host_id = ?1 AND state != 'removed'").bind(hostId).first();
  if (!h) throw notFound("no such host");
  const cur = decodeCursor<{ k: string }>(cursor);
  const rows = (await env.DB.prepare("SELECT * FROM components WHERE host_id = ?1 AND component_id > ?2 ORDER BY component_id LIMIT ?3").bind(hostId, cur?.k ?? "", limit + 1).all<Record<string, unknown>>()).results ?? [];
  const rendered = await renderedConfigs(env, hostId);
  const page = rows.slice(0, limit);
  return {
    items: page.map((r) => componentOut(r, rendered.get(String(r.component_id)) ?? null)),
    next_cursor: rows.length > limit ? encodeCursor({ k: page[page.length - 1]?.component_id }) : null,
  };
}

// ---- releases -----------------------------------------------------------------------------------------
export async function listReleases(env: Env, limit: number, cursor: string | undefined) {
  const cur = decodeCursor<{ c: string; v: string }>(cursor);
  const rows = (
    await env.DB.prepare(
      `SELECT * FROM releases WHERE (?1 IS NULL OR (created_at, version) < (?1, ?2)) ORDER BY created_at DESC, version DESC LIMIT ?3`,
    ).bind(cur?.c ?? null, cur?.v ?? "", limit + 1).all<Record<string, unknown>>()
  ).results ?? [];
  const page = rows.slice(0, limit);
  const out = [];
  for (const r of page) out.push(await releaseOut(env, r));
  const last = page[page.length - 1];
  return { items: out, next_cursor: rows.length > limit && last ? encodeCursor({ c: last.created_at, v: last.version }) : null };
}

export async function releaseOut(env: Env, r: Record<string, unknown>) {
  const version = String(r.version);
  let relId = r.rel_id as string | null;
  if (!relId || !REL_ID_RE.test(relId)) {
    relId = newId("rel_"); // rows recorded before rel_id existed are given one on first sight
    await env.DB.prepare("UPDATE releases SET rel_id = ?2 WHERE version = ?1 AND rel_id IS NULL").bind(version, relId).run();
    relId = ((await env.DB.prepare("SELECT rel_id FROM releases WHERE version = ?1").bind(version).first<{ rel_id: string }>())?.rel_id) ?? relId;
  }
  const arts = (await env.DB.prepare("SELECT artifact_id, name, component, arch, sha256, size FROM artifacts WHERE version = ?1 ORDER BY name").bind(version).all()).results ?? [];
  const sites = (await env.DB.prepare("SELECT site FROM sites WHERE release_version = ?1 OR target_version = ?1 ORDER BY site").bind(version).all<{ site: string }>()).results ?? [];
  return {
    rel_id: relId,
    version,
    source: r.source === "github" ? "github" : "upload",
    verified_at: r.verified_at,
    notes_url: r.notes_url ?? null,
    min_agent_version: r.min_agent_version ?? "0.0.0",
    created: (r.manifest_created as string | null) ?? r.created_at,
    artifacts: arts,
    sites: sites.map((s) => s.site),
  };
}

export async function getReleaseByVersion(env: Env, version: string) {
  const r = await env.DB.prepare("SELECT * FROM releases WHERE version = ?1").bind(version).first<Record<string, unknown>>();
  if (!r) throw notFound("no such release");
  return releaseOut(env, r);
}

// ---- dashboards -----------------------------------------------------------------------------------------
/** `dashboard_id` is the dashboard component's slug (a cmp_ id is accepted too). */
export async function dashboardSlug(env: Env, idOrSlug: string): Promise<{ slug: string; component_id: string }> {
  const r = COMPONENT_ID_RE.test(idOrSlug)
    ? await env.DB.prepare("SELECT slug, component_id FROM components WHERE component_id = ?1 AND type = 'dashboard'").bind(idOrSlug).first<{ slug: string; component_id: string }>()
    : SLUG_RE.test(idOrSlug)
      ? await env.DB.prepare("SELECT slug, component_id FROM components WHERE slug = ?1 AND type = 'dashboard'").bind(idOrSlug).first<{ slug: string; component_id: string }>()
      : null;
  if (!r) throw notFound("no such dashboard");
  return r;
}

export async function listDashboardUsers(env: Env, slug: string, limit: number, cursor: string | undefined) {
  const cur = decodeCursor<{ k: string }>(cursor);
  const rows = (await env.DB.prepare("SELECT usr_id, username, role, created_at FROM dashboard_users WHERE dashboard_slug = ?1 AND usr_id > ?2 ORDER BY usr_id LIMIT ?3").bind(slug, cur?.k ?? "", limit + 1).all<Record<string, unknown>>()).results ?? [];
  const page = rows.slice(0, limit);
  return { items: page, next_cursor: rows.length > limit ? encodeCursor({ k: page[page.length - 1]?.usr_id }) : null };
}

export async function listNocTokens(env: Env, slug: string, limit: number, cursor: string | undefined) {
  const cur = decodeCursor<{ k: string }>(cursor);
  const rows = (await env.DB.prepare("SELECT noc_id, label, expires_at, revoked_at, created_at FROM noc_tokens WHERE dashboard_slug = ?1 AND noc_id > ?2 ORDER BY noc_id LIMIT ?3").bind(slug, cur?.k ?? "", limit + 1).all<Record<string, unknown>>()).results ?? [];
  const page = rows.slice(0, limit);
  return { items: page.map((r) => ({ ...r, role: "viewer" })), next_cursor: rows.length > limit ? encodeCursor({ k: page[page.length - 1]?.noc_id }) : null };
}

// ---- audit -----------------------------------------------------------------------------------------------
const ISO_OR_DATE = /^\d{4}-\d{2}-\d{2}(T[0-9:.]+Z)?$/;

export async function listAudit(env: Env, q: { from?: string; to?: string; actor?: string; resource?: string; limit: number; cursor?: string }) {
  for (const v of [q.from, q.to]) if (v !== undefined && !ISO_OR_DATE.test(v)) throw invalidRequest("from/to must be an ISO-8601 UTC time (or a date)");
  const cur = decodeCursor<{ t: string; i: string }>(q.cursor);
  const where: string[] = [];
  const args: unknown[] = [];
  const add = (sql: string, v: unknown) => (args.push(v), where.push(sql.replace("?", `?${args.length}`)));
  if (q.from) add("ts >= ?", q.from);
  if (q.to) add("ts <= ?", q.to.length === 10 ? `${q.to}T23:59:59.999Z` : q.to);
  if (q.actor) add("actor = ?", q.actor);
  if (q.resource) add("resource = ?", q.resource);
  if (cur) {
    args.push(cur.t, cur.i);
    where.push(`(ts, evt_id) < (?${args.length - 1}, ?${args.length})`);
  }
  args.push(q.limit + 1);
  const rows = (await env.DB.prepare(`SELECT evt_id, ts, actor, action, resource, details_json, ip FROM audit ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY ts DESC, evt_id DESC LIMIT ?${args.length}`).bind(...args).all<Record<string, unknown>>()).results ?? [];
  const page = rows.slice(0, q.limit);
  const last = page[page.length - 1];
  return {
    items: page.map((r) => ({ evt_id: r.evt_id, ts: r.ts, actor: r.actor, action: r.action, resource: r.resource, details: parseJson(r.details_json, {}), ip: r.ip ?? null })),
    next_cursor: rows.length > q.limit && last ? encodeCursor({ t: last.ts, i: last.evt_id }) : null,
  };
}
