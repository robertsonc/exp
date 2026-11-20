// Fleet API read side (05-manager.md section 13): reads hosts / components (latest values), roll-ups and
// issues only - never status_latest report bodies - so it stays fast at 500 hosts.
import type { Env } from "../env";
import { invalidRequest, notFound } from "../errors";
import { parseJson } from "../compile/load";
import { HOST_ID_RE, COMPONENT_ID_RE } from "../util/ids";
import { nowMs, isoNow } from "../util/time";
import { COMPONENT_KEYS, STEP_1H, STEP_5M, bucketOf, componentKeysAllowed } from "./rollup";
import { VISIBLE_OPEN_SQL } from "../issues/visibility";
import { issueOut } from "../issues/store";
import { decodeCursor, encodeCursor } from "../util/cursor";

export type Health = "ok" | "degraded" | "fail" | "unknown";
const HEALTH_RANK: Record<Health, number> = { unknown: 0, ok: 1, degraded: 2, fail: 3 };

interface HostRow {
  host_id: string;
  name: string;
  site: string;
  state: string;
  facts_json: string;
  latest_json: string;
  last_seen: string | null;
  agent_version: string | null;
  desired_version: number | null;
  applied_version: number | null;
  status_interval_s: number | null;
}
interface CompRow {
  component_id: string;
  host_id: string;
  type: string;
  slug: string;
  enabled: number;
  facts_json: string;
}

export interface CompState {
  component_id: string;
  host_id: string;
  type: string;
  slug: string;
  enabled: boolean;
  health: Health;
  version: string | null;
  state: string | null;
  metrics: Record<string, number>;
}

export function compState(r: CompRow): CompState {
  const f = parseJson<Record<string, unknown>>(r.facts_json, {});
  const h = f.health;
  const health: Health = h === "ok" || h === "degraded" || h === "fail" ? h : "unknown";
  const m = f.metrics && typeof f.metrics === "object" ? (f.metrics as Record<string, unknown>) : {};
  const metrics: Record<string, number> = {};
  for (const [k, v] of Object.entries(m)) if (typeof v === "number" && Number.isFinite(v)) metrics[k] = v;
  return {
    component_id: r.component_id,
    host_id: r.host_id,
    type: r.type,
    slug: r.slug,
    enabled: r.enabled === 1,
    health,
    version: typeof f.version === "string" ? f.version : null,
    state: typeof f.state === "string" ? f.state : null,
    metrics,
  };
}

export const worst = (hs: Health[]): Health => hs.reduce<Health>((a, b) => (HEALTH_RANK[b] > HEALTH_RANK[a] ? b : a), "unknown");

export function mgmtIpOf(factsJson: string): string | null {
  const f = parseJson<{ interfaces?: Array<{ default_route?: boolean; in_use_by?: string; addrs?: string[] }> }>(factsJson, {});
  const ifs = f.interfaces ?? [];
  const m = ifs.find((i) => i.default_route) ?? ifs.find((i) => i.in_use_by === "mgmt");
  for (const a of m?.addrs ?? []) {
    const ip = String(a).split("/")[0] ?? "";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip;
  }
  return null;
}

const SHAPES = new Set(["probe", "collector", "dashboard", "runner", "speedtest"]);

async function defaultStatusInterval(env: Env): Promise<number> {
  const r = await env.DB.prepare("SELECT agent_status_interval_s FROM settings WHERE org_id = 'default'").first<{ agent_status_interval_s: number }>();
  return r?.agent_status_interval_s ?? 60;
}

export interface FleetData {
  hosts: HostRow[];
  comps: Map<string, CompState[]>;
  openIssues: Map<string, number>;
  statusInterval: number;
  asOf: string;
}

/** Hosts (not removed), their components, visible open-issue counts. */
export async function loadFleet(env: Env): Promise<FleetData> {
  const now = isoNow();
  const [h, c, i] = await env.DB.batch([
    env.DB.prepare(
      `SELECT host_id, name, site, state, facts_json, latest_json, last_seen, agent_version, desired_version, applied_version, status_interval_s
       FROM hosts WHERE state != 'removed'`,
    ),
    env.DB.prepare("SELECT component_id, host_id, type, slug, enabled, facts_json FROM components"),
    env.DB.prepare(`SELECT host_id, COUNT(*) AS n FROM issues i WHERE ${VISIBLE_OPEN_SQL} GROUP BY host_id`).bind(now),
  ]);
  const comps = new Map<string, CompState[]>();
  for (const r of (c?.results ?? []) as unknown as CompRow[]) {
    const list = comps.get(r.host_id) ?? [];
    list.push(compState(r));
    comps.set(r.host_id, list);
  }
  const openIssues = new Map<string, number>();
  for (const r of (i?.results ?? []) as Array<{ host_id: string; n: number }>) openIssues.set(r.host_id, r.n);
  return {
    hosts: (h?.results ?? []) as unknown as HostRow[],
    comps,
    openIssues,
    statusInterval: await defaultStatusInterval(env),
    asOf: now,
  };
}

export function isStale(h: HostRow, interval: number, now = nowMs()): boolean {
  if (h.state === "stale" || h.state === "offline") return true;
  if (!h.last_seen) return false;
  return now - Date.parse(h.last_seen) > 3 * (h.status_interval_s ?? interval) * 1000;
}

/** Health shown for a host: its components' worst; hosts that stopped reporting are `unknown`. */
export function hostHealth(h: HostRow, comps: CompState[], interval: number): Health {
  if (h.state === "pending" || h.state === "offline" || h.state === "stale") return "unknown";
  if (isStale(h, interval)) return "unknown";
  const active = comps.filter((c) => c.enabled);
  return active.length ? worst(active.map((c) => c.health)) : "unknown";
}

// ---- time series ------------------------------------------------------------------------------------
export const RANGES: Record<string, { seconds: number; step: number }> = {
  "1h": { seconds: 3600, step: STEP_5M },
  "6h": { seconds: 6 * 3600, step: STEP_5M },
  "24h": { seconds: 24 * 3600, step: STEP_5M },
  "7d": { seconds: 7 * 86400, step: STEP_1H },
  "30d": { seconds: 30 * 86400, step: STEP_1H },
};

export function parseRange(v: string | undefined): { name: string; seconds: number; step: number } {
  const name = v ?? "24h";
  const r = RANGES[name];
  if (!r) throw invalidRequest("range must be one of 1h, 6h, 24h, 7d, 30d");
  return { name, ...r };
}

interface KeyDef {
  n: string;
  sum: string;
  max: string | null;
}
export const HOST_KEYS: Record<string, KeyDef> = {
  cpu_pct: { n: "cpu_n", sum: "cpu_sum", max: "cpu_max" },
  mem_pct: { n: "mem_n", sum: "mem_pct_sum", max: "mem_pct_max" },
  disk_pct: { n: "disk_n", sum: "disk_pct_sum", max: "disk_pct_max" },
  load1: { n: "load_n", sum: "load1_sum", max: "load1_max" },
  net_rx_pps: { n: "net_n", sum: "rx_pps_sum", max: null },
  net_tx_pps: { n: "net_n", sum: "tx_pps_sum", max: null },
  net_rx_bps: { n: "net_n", sum: "rx_bps_sum", max: null },
  net_tx_bps: { n: "net_n", sum: "tx_bps_sum", max: null },
  net_errors: { n: "net_n", sum: "errors_sum", max: null },
  net_drops: { n: "net_n", sum: "drops_sum", max: null },
  disk_write_kbps: { n: "dio_n", sum: "disk_write_kbps_sum", max: "disk_write_kbps_max" },
};

export function parseKeys(raw: string | undefined, allowed: readonly string[], defaults: readonly string[] = allowed): string[] {
  if (!raw) return [...defaults];
  const keys = raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (keys.length === 0 || keys.length > 32) throw invalidRequest("keys must list 1..32 metric keys");
  for (const k of keys) if (!allowed.includes(k)) throw invalidRequest(`unknown metric key: ${k.slice(0, 64)}`);
  return [...new Set(keys)];
}

export interface Point {
  t: number;
  avg: number | null;
  max: number | null;
}

export async function hostSeries(env: Env, hostId: string, rangeName: string, keys: string[]): Promise<Record<string, Point[]>> {
  const r = parseRange(rangeName);
  const table = r.step === STEP_5M ? "fleet_host_5m" : "fleet_host_1h";
  const from = bucketOf(nowMs(), r.step) - r.seconds;
  const cols = new Set<string>();
  for (const k of keys) {
    const d = HOST_KEYS[k] as KeyDef;
    cols.add(d.n).add(d.sum);
    if (d.max) cols.add(d.max);
  }
  const rows = await env.DB.prepare(`SELECT bucket, ${[...cols].join(", ")} FROM ${table} WHERE host_id = ?1 AND bucket >= ?2 ORDER BY bucket`)
    .bind(hostId, from)
    .all<Record<string, number | null>>();
  const out: Record<string, Point[]> = {};
  for (const k of keys) out[k] = [];
  for (const row of rows.results ?? []) {
    for (const k of keys) {
      const d = HOST_KEYS[k] as KeyDef;
      const n = row[d.n] ?? 0;
      if (n <= 0) continue; // gap: no samples
      (out[k] as Point[]).push({ t: row.bucket as number, avg: (row[d.sum] as number) / n, max: d.max ? (row[d.max] ?? null) : null });
    }
  }
  return out;
}

export async function componentSeries(env: Env, componentId: string, rangeName: string, keys: string[]): Promise<Record<string, Point[]>> {
  const r = parseRange(rangeName);
  const table = r.step === STEP_5M ? "fleet_component_metric_5m" : "fleet_component_metric_1h";
  const from = bucketOf(nowMs(), r.step) - r.seconds;
  const marks = keys.map((_, i) => `?${i + 3}`).join(", ");
  const rows = await env.DB.prepare(
    `SELECT key, bucket, n, sum, max FROM ${table} WHERE component_id = ?1 AND bucket >= ?2 AND key IN (${marks}) ORDER BY bucket`,
  )
    .bind(componentId, from, ...keys)
    .all<{ key: string; bucket: number; n: number; sum: number; max: number | null }>();
  const out: Record<string, Point[]> = {};
  for (const k of keys) out[k] = [];
  for (const row of rows.results ?? []) if (row.n > 0) (out[row.key] as Point[]).push({ t: row.bucket, avg: row.sum / row.n, max: row.max });
  return out;
}

export async function hostMetrics(env: Env, hostId: string, rangeName: string, keysRaw: string | undefined) {
  if (!HOST_ID_RE.test(hostId)) throw notFound("no such host");
  const exists = await env.DB.prepare("SELECT 1 AS x FROM hosts WHERE host_id = ?1").bind(hostId).first();
  if (!exists) throw notFound("no such host");
  const r = parseRange(rangeName);
  const keys = parseKeys(keysRaw, Object.keys(HOST_KEYS));
  return { host_id: hostId, range: r.name, step_s: r.step, as_of: isoNow(), series: await hostSeries(env, hostId, r.name, keys) };
}

export async function componentMetrics(env: Env, componentId: string, rangeName: string, keysRaw: string | undefined) {
  if (!COMPONENT_ID_RE.test(componentId)) throw notFound("no such component");
  const row = await env.DB.prepare("SELECT type FROM components WHERE component_id = ?1").bind(componentId).first<{ type: string }>();
  if (!row) throw notFound("no such component");
  const r = parseRange(rangeName);
  const keys = parseKeys(keysRaw, componentKeysAllowed(row.type), COMPONENT_KEYS[row.type] ?? []);
  return { component_id: componentId, range: r.name, step_s: r.step, as_of: isoNow(), series: keys.length ? await componentSeries(env, componentId, r.name, keys) : {} };
}

// ---- per-interface history (CR-wp5-fleet-api-gaps item 3) ----------------------------------------------------
/** Interface ranges: only 5-minute roll-ups are kept per interface, for 48 h. */
const IFACE_RANGES: Record<string, number> = { "1h": 3600, "6h": 6 * 3600, "24h": 24 * 3600, "48h": 48 * 3600 };
const IFACE_RE = /^[A-Za-z0-9_.:-]{1,15}$/;
const IFACE_KEYS: Record<string, { sum: string }> = {
  rx_pps: { sum: "rx_pps_sum" },
  tx_pps: { sum: "tx_pps_sum" },
  rx_bps: { sum: "rx_bps_sum" },
  tx_bps: { sum: "tx_bps_sum" },
  errors: { sum: "errors_sum" },
  drops: { sum: "drops_sum" },
};

export async function interfaceMetrics(env: Env, hostId: string, iface: string, rangeName: string | undefined, keysRaw: string | undefined) {
  if (!HOST_ID_RE.test(hostId)) throw notFound("no such host");
  const exists = await env.DB.prepare("SELECT 1 AS x FROM hosts WHERE host_id = ?1").bind(hostId).first();
  if (!exists) throw notFound("no such host");
  if (!IFACE_RE.test(iface)) throw notFound("no such interface");
  const name = rangeName ?? "24h";
  const seconds = IFACE_RANGES[name];
  if (seconds === undefined) throw invalidRequest("range must be one of 1h, 6h, 24h, 48h");
  const keys = parseKeys(keysRaw, Object.keys(IFACE_KEYS));
  const from = bucketOf(nowMs(), STEP_5M) - seconds;
  const rows = await env.DB.prepare(
    `SELECT bucket, samples, rx_pps_sum, tx_pps_sum, rx_bps_sum, tx_bps_sum, errors_sum, drops_sum
     FROM fleet_iface_5m WHERE host_id = ?1 AND iface = ?2 AND bucket >= ?3 ORDER BY bucket`,
  )
    .bind(hostId, iface, from)
    .all<Record<string, number>>();
  const out: Record<string, Point[]> = {};
  for (const k of keys) out[k] = [];
  for (const row of rows.results ?? []) {
    const n = row.samples ?? 0;
    if (n <= 0) continue;
    for (const k of keys) (out[k] as Point[]).push({ t: row.bucket as number, avg: (row[(IFACE_KEYS[k] as { sum: string }).sum] as number) / n, max: null });
  }
  return { host_id: hostId, iface, range: name, step_s: STEP_5M, as_of: isoNow(), series: out };
}

// ---- per-probe rows of a collector (CR-wp5-fleet-api-gaps item 2) -----------------------------------------------
export interface ProbeRow {
  probe_id: string;
  last_seen: string;
  records_per_min: number;
  clock_offset_ms: number | null;
}
export const MAX_PROBE_ROWS = 500;
const PROBE_ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;

/** The bounded, validated probe rows of a collector report; null when the report carries no `probes` array. Invalid rows are dropped. */
export function sanitizeProbeRows(raw: unknown): ProbeRow[] | null {
  if (!Array.isArray(raw)) return null;
  const out: ProbeRow[] = [];
  for (const r of raw) {
    if (out.length >= MAX_PROBE_ROWS) break;
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    const id = o.probe_id;
    const seen = o.last_seen;
    const rpm = nn(o.records_per_min);
    if (typeof id !== "string" || !PROBE_ID_RE.test(id) || typeof seen !== "string" || !ISO_RE.test(seen) || rpm === null || rpm < 0) continue;
    out.push({ probe_id: id, last_seen: seen, records_per_min: rpm, clock_offset_ms: nn(o.clock_offset_ms) });
  }
  return out;
}

export async function componentProbes(env: Env, componentId: string) {
  if (!COMPONENT_ID_RE.test(componentId)) throw notFound("no such component");
  const comp = await env.DB.prepare("SELECT type FROM components WHERE component_id = ?1").bind(componentId).first<{ type: string }>();
  if (!comp) throw notFound("no such component");
  const row = comp.type === "collector"
    ? await env.DB.prepare("SELECT reported_at, probes_json FROM component_probes_latest WHERE component_id = ?1").bind(componentId).first<{ reported_at: string; probes_json: string }>()
    : null;
  const items = row ? (sanitizeProbeRows(parseJson<unknown>(row.probes_json, [])) ?? []) : [];
  return { component_id: componentId, as_of: isoNow(), reported_at: row?.reported_at ?? null, items };
}

// ---- summary / sites / hosts / top ---------------------------------------------------------------------
const emptyHealth = () => ({ ok: 0, degraded: 0, fail: 0, unknown: 0 });

export async function fleetSummary(env: Env) {
  const d = await loadFleet(env);
  const byState: Record<string, number> = { pending: 0, enrolled: 0, stale: 0, offline: 0, decommissioning: 0 };
  let online = 0;
  let drift = 0;
  const byType: Record<string, ReturnType<typeof emptyHealth>> = {};
  let measurements: number | null = null;
  let ingest: number | null = null;
  let incidents: number | null = null;
  for (const h of d.hosts) {
    byState[h.state] = (byState[h.state] ?? 0) + 1;
    const stale = isStale(h, d.statusInterval);
    if (h.state === "enrolled" && !stale) online++;
    if (h.desired_version !== null && h.applied_version !== h.desired_version && h.state !== "pending") drift++;
    for (const c of d.comps.get(h.host_id) ?? []) {
      if (!c.enabled) continue;
      const hl = stale ? "unknown" : c.health;
      (byType[c.type] ??= emptyHealth())[hl]++;
      if (stale) continue;
      if (c.type === "probe" && c.metrics.measurements_per_min !== undefined) measurements = (measurements ?? 0) + c.metrics.measurements_per_min;
      if (c.type === "collector") {
        if (c.metrics.ingest_records_per_s !== undefined) ingest = (ingest ?? 0) + c.metrics.ingest_records_per_s;
        if (c.metrics.open_incidents !== undefined) incidents = (incidents ?? 0) + c.metrics.open_incidents;
      }
    }
  }
  const sev = await env.DB.prepare(`SELECT severity, COUNT(*) AS n FROM issues i WHERE ${VISIBLE_OPEN_SQL} GROUP BY severity`)
    .bind(d.asOf)
    .all<{ severity: string; n: number }>();
  const open = { warn: 0, crit: 0 };
  for (const r of sev.results ?? []) if (r.severity === "warn" || r.severity === "crit") open[r.severity] = r.n;
  return {
    as_of: d.asOf,
    hosts_by_state: byState,
    hosts_total: d.hosts.length,
    hosts_online: online,
    components_by_type_health: byType,
    measurements_per_min: measurements,
    ingest_records_per_s: ingest,
    open_issues: open,
    version_drift_hosts: drift,
    open_experience_incidents: incidents,
  };
}

export async function fleetSites(env: Env) {
  const d = await loadFleet(env);
  const sites = await env.DB.prepare("SELECT site, name, release_version, canary_state FROM sites ORDER BY site").all<{
    site: string;
    name: string;
    release_version: string | null;
    canary_state: string;
  }>();
  const worstIssue = await env.DB.prepare(
    `SELECT * FROM issues i WHERE ${VISIBLE_OPEN_SQL} ORDER BY (severity = 'crit') DESC, opened_at ASC`,
  )
    .bind(d.asOf)
    .all<Record<string, unknown>>();
  const items = (sites.results ?? []).map((s) => {
    const hosts = d.hosts.filter((h) => h.site === s.site);
    const bar = { ok: 0, warn: 0, fail: 0, offline: 0 };
    let probesTotal = 0;
    let probesReporting = 0;
    let ingest: number | null = null;
    for (const h of hosts) {
      const comps = d.comps.get(h.host_id) ?? [];
      const stale = isStale(h, d.statusInterval);
      if (h.state === "offline") bar.offline++;
      else if (stale) bar.warn++;
      else {
        const hl = hostHealth(h, comps, d.statusInterval);
        if (hl === "fail") bar.fail++;
        else if (hl === "degraded") bar.warn++;
        else bar.ok++;
      }
      for (const c of comps) {
        if (c.type === "probe" && c.enabled) {
          probesTotal++;
          if (!stale && c.health !== "unknown") probesReporting++;
        }
        if (c.type === "collector" && !stale && c.metrics.ingest_records_per_s !== undefined) ingest = (ingest ?? 0) + c.metrics.ingest_records_per_s;
      }
    }
    const wi = (worstIssue.results ?? []).find((i) => i.site === s.site);
    return {
      site: s.site,
      name: s.name,
      hosts: hosts.length,
      health_bar: bar,
      probes_reporting: probesReporting,
      probes_total: probesTotal,
      ingest_records_per_s: ingest,
      worst_issue: wi ? issueOut(wi) : null,
      release_version: s.release_version,
      canary_state: canaryStateOut(s.canary_state),
    };
  });
  return { items, as_of: d.asOf };
}

export function canaryStateOut(s: string | null | undefined, healthySince?: string | null): string | null {
  if (!s || s === "none") return null;
  if (s === "canary") return healthySince ? "healthy_waiting" : "pending";
  return s; // promoted | failed
}

const SORTS = new Set(["name", "site", "state", "health", "cpu_pct", "mem_pct", "disk_pct_max", "uptime_s", "last_seen", "open_issues", "agent_version"]);

export interface HostRowOut {
  host_id: string;
  name: string;
  mgmt_ip: string | null;
  site: string;
  shapes: string[];
  state: string;
  stale: boolean;
  health: Health;
  open_issues: number;
  cpu_pct: number | null;
  mem_pct: number | null;
  disk_pct_max: number | null;
  uptime_s: number | null;
  net: { rx_pps: number | null; tx_pps: number | null; rx_bps: number | null; tx_bps: number | null } | null;
  work: { measurements_per_min: number | null; ingest_records_per_s: number | null; sessions_active: number | null; drills_active: number | null; tests_per_hour: number | null };
  cpu_spark: Array<number | null>;
  net_spark: Array<number | null>;
  agent_version: string | null;
  desired_version: number | null;
  applied_version: number | null;
  last_seen: string | null;
}

const nn = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export interface FleetHostQuery {
  site?: string;
  type?: string;
  health?: string;
  state?: string;
  version?: string;
  q?: string;
  sort?: string;
  limit?: number;
  cursor?: string;
}

/** Sparkline arrays: last hour in 5-minute buckets (12 slots, null = gap) for the given hosts. */
async function sparks(env: Env, hostIds: string[]): Promise<Map<string, { cpu: Array<number | null>; net: Array<number | null> }>> {
  const out = new Map<string, { cpu: Array<number | null>; net: Array<number | null> }>();
  if (hostIds.length === 0) return out;
  const nowB = bucketOf(nowMs(), STEP_5M);
  const from = nowB - 11 * STEP_5M;
  const rows = await env.DB.prepare(
    "SELECT host_id, bucket, cpu_n, cpu_sum, net_n, rx_bps_sum, tx_bps_sum FROM fleet_host_5m WHERE bucket >= ?1",
  )
    .bind(from)
    .all<{ host_id: string; bucket: number; cpu_n: number; cpu_sum: number; net_n: number; rx_bps_sum: number; tx_bps_sum: number }>();
  const want = new Set(hostIds);
  for (const r of rows.results ?? []) {
    if (!want.has(r.host_id)) continue;
    let e = out.get(r.host_id);
    if (!e) {
      e = { cpu: Array<number | null>(12).fill(null), net: Array<number | null>(12).fill(null) };
      out.set(r.host_id, e);
    }
    const idx = Math.round((r.bucket - from) / STEP_5M);
    if (idx < 0 || idx > 11) continue;
    if (r.cpu_n > 0) e.cpu[idx] = r.cpu_sum / r.cpu_n;
    if (r.net_n > 0) e.net[idx] = (r.rx_bps_sum + r.tx_bps_sum) / r.net_n;
  }
  return out;
}

export async function fleetHosts(env: Env, q: FleetHostQuery) {
  if (q.health && !["ok", "degraded", "fail", "unknown"].includes(q.health)) throw invalidRequest("invalid health filter");
  if (q.state && !["pending", "enrolled", "stale", "offline", "decommissioning"].includes(q.state)) throw invalidRequest("invalid state filter");
  if (q.type && !SHAPES.has(q.type)) throw invalidRequest("invalid type filter");
  const sortRaw = q.sort ?? "name";
  const desc = sortRaw.startsWith("-");
  const sortKey = desc ? sortRaw.slice(1) : sortRaw;
  if (!SORTS.has(sortKey)) throw invalidRequest(`sort must be one of ${[...SORTS].join(", ")} (optionally prefixed with -)`);
  const limit = Math.min(Math.max(q.limit ?? 100, 1), 1000);
  const cur = decodeCursor<{ o: number }>(q.cursor);
  const offset = cur && Number.isInteger(cur.o) && cur.o >= 0 ? cur.o : 0;

  const d = await loadFleet(env);
  const needle = q.q?.trim().toLowerCase();
  const rows: HostRowOut[] = [];
  for (const h of d.hosts) {
    const comps = d.comps.get(h.host_id) ?? [];
    const latest = parseJson<Record<string, unknown>>(h.latest_json, {});
    const stale = isStale(h, d.statusInterval);
    const health = hostHealth(h, comps, d.statusInterval);
    const shapes = [...new Set(comps.map((c) => c.type).filter((t) => SHAPES.has(t)))].sort();
    const mgmt = mgmtIpOf(h.facts_json);
    if (q.site && h.site !== q.site) continue;
    if (q.state && h.state !== q.state) continue;
    if (q.type && !comps.some((c) => c.type === q.type)) continue;
    if (q.health && health !== q.health) continue;
    if (q.version && h.agent_version !== q.version) continue;
    if (needle && !(h.name.toLowerCase().includes(needle) || h.host_id.toLowerCase().includes(needle) || (mgmt ?? "").includes(needle) || h.site.includes(needle))) {
      const hit = comps.some((c) => c.slug.includes(needle) || c.component_id.toLowerCase().includes(needle));
      if (!hit) continue;
    }
    const sum = (type: string, key: string): number | null => {
      let t: number | null = null;
      for (const c of comps) if (c.type === type && c.enabled && c.metrics[key] !== undefined) t = (t ?? 0) + (c.metrics[key] as number);
      return t;
    };
    const netObj = latest.net && typeof latest.net === "object" ? (latest.net as Record<string, unknown>) : null;
    rows.push({
      host_id: h.host_id,
      name: h.name,
      mgmt_ip: mgmt,
      site: h.site,
      shapes,
      state: h.state,
      stale,
      health,
      open_issues: d.openIssues.get(h.host_id) ?? 0,
      cpu_pct: nn(latest.cpu_pct),
      mem_pct: nn(latest.mem_pct),
      disk_pct_max: nn(latest.disk_pct_max),
      uptime_s: nn(latest.uptime_s),
      net: netObj ? { rx_pps: nn(netObj.rx_pps), tx_pps: nn(netObj.tx_pps), rx_bps: nn(netObj.rx_bps), tx_bps: nn(netObj.tx_bps) } : null,
      work: {
        measurements_per_min: sum("probe", "measurements_per_min"),
        ingest_records_per_s: sum("collector", "ingest_records_per_s"),
        sessions_active: sum("dashboard", "sessions_active"),
        drills_active: sum("runner", "drills_active"),
        tests_per_hour: sum("speedtest", "tests_per_hour"),
      },
      cpu_spark: [],
      net_spark: [],
      agent_version: h.agent_version,
      desired_version: h.desired_version,
      applied_version: h.applied_version,
      last_seen: h.last_seen,
    });
  }
  const rank = (r: HostRowOut): string | number | null => (sortKey === "health" ? HEALTH_RANK[r.health] : ((r as unknown as Record<string, unknown>)[sortKey] as string | number | null));
  rows.sort((a, b) => {
    const x = rank(a);
    const y = rank(b);
    // nulls always last, regardless of direction
    if (x === null && y === null) return a.host_id < b.host_id ? -1 : 1;
    if (x === null) return 1;
    if (y === null) return -1;
    const c = x < y ? -1 : x > y ? 1 : 0;
    return c !== 0 ? (desc ? -c : c) : a.host_id < b.host_id ? -1 : 1;
  });
  const page = rows.slice(offset, offset + limit);
  const sp = await sparks(env, page.map((r) => r.host_id));
  for (const r of page) {
    const s = sp.get(r.host_id);
    r.cpu_spark = s?.cpu ?? [];
    r.net_spark = s?.net ?? [];
  }
  return { items: page, next_cursor: offset + limit < rows.length ? encodeCursor({ o: offset + limit }) : null };
}

export async function fleetTop(env: Env, metric: string, limitRaw: number | undefined) {
  if (!["cpu", "mem", "disk", "net"].includes(metric)) throw invalidRequest("metric must be one of cpu, mem, disk, net");
  const limit = Math.min(Math.max(limitRaw ?? 10, 1), 100);
  const d = await loadFleet(env);
  const items: Array<{ host_id: string; name: string; site: string; value: number; unit: string; value_out: number | null }> = [];
  for (const h of d.hosts) {
    if (isStale(h, d.statusInterval) || h.state === "pending") continue; // stale values are never ranked as current
    const l = parseJson<Record<string, unknown>>(h.latest_json, {});
    const net = l.net && typeof l.net === "object" ? (l.net as Record<string, unknown>) : null;
    const v = metric === "cpu" ? nn(l.cpu_pct) : metric === "mem" ? nn(l.mem_pct) : metric === "disk" ? nn(l.disk_pct_max) : nn(net?.rx_pps);
    if (v === null) continue;
    items.push({ host_id: h.host_id, name: h.name, site: h.site, value: v, unit: metric === "net" ? "pps" : "pct", value_out: metric === "net" ? nn(net?.tx_pps) : null });
  }
  items.sort((a, b) => b.value - a.value || (a.host_id < b.host_id ? -1 : 1));
  const top = items.slice(0, limit);
  const out = [];
  const key = metric === "cpu" ? "cpu_pct" : metric === "mem" ? "mem_pct" : metric === "disk" ? "disk_pct" : "net_rx_pps";
  for (const t of top) {
    const series = (await hostSeries(env, t.host_id, "24h", [key]))[key] ?? [];
    out.push({ ...t, spark: series.map((p) => p.avg) });
  }
  return { metric, as_of: d.asOf, items: out };
}

export async function overview(env: Env) {
  const d = await loadFleet(env);
  const sites = await env.DB.prepare("SELECT site, name, release_version FROM sites ORDER BY site").all<{ site: string; name: string; release_version: string | null }>();
  const versions: Record<string, number> = {};
  const hosts = d.hosts.map((h) => {
    const comps = d.comps.get(h.host_id) ?? [];
    if (h.agent_version) versions[h.agent_version] = (versions[h.agent_version] ?? 0) + 1;
    return {
      host_id: h.host_id,
      name: h.name,
      site: h.site,
      state: h.state,
      health: hostHealth(h, comps, d.statusInterval),
      agent_version: h.agent_version,
      desired_version: h.desired_version,
      applied_version: h.applied_version,
      components: comps.map((c) => ({ component_id: c.component_id, type: c.type, id: c.slug, health: c.health, version: c.version })),
    };
  });
  return {
    as_of: d.asOf,
    sites: (sites.results ?? []).map((s) => {
      const hs = d.hosts.filter((h) => h.site === s.site);
      const states = { pending: 0, enrolled: 0, stale: 0, offline: 0, decommissioning: 0 } as Record<string, number>;
      const ch = emptyHealth();
      for (const h of hs) {
        states[h.state] = (states[h.state] ?? 0) + 1;
        for (const c of d.comps.get(h.host_id) ?? []) ch[c.health]++;
      }
      return { site: s.site, name: s.name, release_version: s.release_version, hosts_total: hs.length, hosts_by_state: states, components_by_health: ch };
    }),
    hosts,
    versions,
  };
}

