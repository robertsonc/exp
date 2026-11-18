// Fleet roll-ups (05-manager.md section 13). Each status report upserts its 5-minute bucket with ONE
// statement per table (INSERT ... ON CONFLICT DO UPDATE accumulating). A value that is null/absent
// (first report, counter reset) is skipped: it adds nothing to the sum and nothing to its sample count,
// so it can never drag an average down as a zero. avg = sum / n; a bucket with n = 0 is simply absent.
import type { StatusReport } from "../agent/status-schema";
import type { Env } from "../env";
import { isoAt, isoNow } from "../util/time";

export const STEP_5M = 300;
export const STEP_1H = 3600;
export const KEEP_5M_S = 48 * 3600;
export const KEEP_1H_S = 30 * 86400;

export const bucketOf = (ms: number, step: number): number => Math.floor(ms / 1000 / step) * step;

/** Chartable component keys per type (05-manager.md section 13). */
export const COMPONENT_KEYS: Record<string, readonly string[]> = {
  probe: ["measurements_per_min", "fail_per_min", "spool_depth", "push_lag_s", "clock_offset_ms"],
  collector: [
    "ingest_records_per_s",
    "ingest_rejected_per_min",
    "vm_backlog_points",
    "vm_storage_gb",
    "records_db_gb",
    "probes_reporting",
  ],
  dashboard: ["sessions_active", "requests_per_min", "collectors_reachable"],
  runner: ["drills_active"],
};

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export interface HostSample {
  cpu: number | null;
  mem: number | null;
  disk: number | null;
  load1: number | null;
  diskWrite: number | null;
  net: { rxPps: number; txPps: number; rxBps: number; txBps: number; errors: number; drops: number; pkts: number } | null;
}

export interface NetSample {
  iface: string;
  rxPps: number;
  txPps: number;
  rxBps: number;
  txBps: number;
  errors: number;
  drops: number;
  pkts: number;
}

type NetEntry = NonNullable<StatusReport["metrics"]["net"]>[number];

/** All four rates present, else null: a partial group is skipped as a whole (never stored as zero). */
export function netSampleOf(n: NetEntry, intervalS: number): NetSample | null {
  const rxPps = num(n.rx_pps);
  const txPps = num(n.tx_pps);
  const rxBps = num(n.rx_bps);
  const txBps = num(n.tx_bps);
  if (rxPps === null || txPps === null || rxBps === null || txBps === null) return null;
  return {
    iface: n.iface,
    rxPps,
    txPps,
    rxBps,
    txBps,
    errors: (num(n.rx_errors) ?? 0) + (num(n.tx_errors) ?? 0),
    drops: (num(n.rx_drops) ?? 0) + (num(n.tx_drops) ?? 0),
    pkts: (rxPps + txPps) * intervalS,
  };
}

/** The management interface entry of a report: role mgmt, else the default-route interface of the facts. */
export function mgmtNet(report: StatusReport): NetEntry | null {
  const nets = report.metrics.net ?? [];
  const byRole = nets.find((n) => n.role === "mgmt");
  if (byRole) return byRole;
  const def = (report.facts.interfaces ?? []).find((i) => i.default_route === true || i.in_use_by === "mgmt");
  return def ? (nets.find((n) => n.iface === def.name) ?? null) : null;
}

export function hostSampleOf(report: StatusReport): HostSample {
  const m = report.metrics;
  const interval = m.interval_s ?? 60;
  const mg = mgmtNet(report);
  const disks = (m.disk ?? []).map((d) => num(d.pct)).filter((x): x is number => x !== null);
  const net = mg ? netSampleOf(mg, interval) : null;
  return {
    cpu: num(m.cpu?.pct),
    mem: num(m.mem?.pct),
    disk: disks.length ? Math.max(...disks) : null,
    load1: num(m.cpu?.load1),
    diskWrite: num(m.disk_io?.write_kbps),
    net: net && { rxPps: net.rxPps, txPps: net.txPps, rxBps: net.rxBps, txBps: net.txBps, errors: net.errors, drops: net.drops, pkts: net.pkts },
  };
}

/** Numeric chartable metrics of one component report (finite numbers of the type's key list only). */
export function componentMetricsOf(type: string, metrics: Record<string, unknown> | undefined): Array<[string, number]> {
  const out: Array<[string, number]> = [];
  for (const k of COMPONENT_KEYS[type] ?? []) {
    const v = num(metrics?.[k]);
    if (v !== null) out.push([k, v]);
  }
  return out;
}

// max() that ignores NULL on either side (scalar max() returns NULL if any argument is NULL)
const mx = (col: string): string => `max(COALESCE(${col}, excluded.${col}), COALESCE(excluded.${col}, ${col}))`;

const HOST_COLS = [
  "samples", "cpu_n", "cpu_sum", "mem_n", "mem_pct_sum", "disk_n", "disk_pct_sum", "load_n", "load1_sum",
  "net_n", "rx_pps_sum", "tx_pps_sum", "rx_bps_sum", "tx_bps_sum", "errors_sum", "drops_sum", "pkts_sum",
  "dio_n", "disk_write_kbps_sum",
] as const;
const HOST_MAX = ["cpu_max", "mem_pct_max", "disk_pct_max", "load1_max", "disk_write_kbps_max"] as const;

function hostUpsertSql(table: string): string {
  const cols = ["host_id", "bucket", "org_id", ...HOST_COLS, ...HOST_MAX, "created_at", "updated_at"];
  const sets = [
    ...HOST_COLS.map((c) => `${c} = ${c} + excluded.${c}`),
    ...HOST_MAX.map((c) => `${c} = ${mx(c)}`),
    "updated_at = excluded.updated_at",
  ];
  return `INSERT INTO ${table} (${cols.join(", ")}) VALUES (${cols.map((_, i) => `?${i + 1}`).join(", ")})
          ON CONFLICT(host_id, bucket) DO UPDATE SET ${sets.join(", ")}`;
}
const HOST_UPSERT = hostUpsertSql("fleet_host_5m");

/** One statement per table: host row, interface rows (json_each), component metric rows (json_each). */
export function rollupStatements(
  env: Env,
  hostId: string,
  receivedMs: number,
  report: StatusReport,
  components: Array<{ component_id: string; type: string; slug: string }>,
): D1PreparedStatement[] {
  const bucket = bucketOf(receivedMs, STEP_5M);
  const now = isoAt(receivedMs);
  const s = hostSampleOf(report);
  const n = s.net;
  const stmts: D1PreparedStatement[] = [];
  const nz = (v: number | null): number => v ?? 0;
  const cnt = (v: number | null): number => (v === null ? 0 : 1);
  stmts.push(
    env.DB.prepare(HOST_UPSERT).bind(
      hostId, bucket, "default",
      1, cnt(s.cpu), nz(s.cpu), cnt(s.mem), nz(s.mem), cnt(s.disk), nz(s.disk), cnt(s.load1), nz(s.load1),
      n ? 1 : 0, n?.rxPps ?? 0, n?.txPps ?? 0, n?.rxBps ?? 0, n?.txBps ?? 0, n?.errors ?? 0, n?.drops ?? 0, n?.pkts ?? 0,
      cnt(s.diskWrite), nz(s.diskWrite),
      s.cpu, s.mem, s.disk, s.load1, s.diskWrite,
      now, now,
    ),
  );

  const interval = report.metrics.interval_s ?? 60;
  const ifaces = (report.metrics.net ?? []).map((x) => netSampleOf(x, interval)).filter((x): x is NetSample => x !== null);
  if (ifaces.length) {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO fleet_iface_5m (host_id, iface, bucket, org_id, samples, rx_pps_sum, tx_pps_sum, rx_bps_sum, tx_bps_sum,
                                     errors_sum, drops_sum, pkts_sum, created_at, updated_at)
         SELECT ?1, json_extract(value, '$.i'), ?2, 'default', 1, json_extract(value, '$.rp'), json_extract(value, '$.tp'),
                json_extract(value, '$.rb'), json_extract(value, '$.tb'), json_extract(value, '$.e'), json_extract(value, '$.d'),
                json_extract(value, '$.k'), ?4, ?4
         FROM json_each(?3) WHERE true
         ON CONFLICT(host_id, iface, bucket) DO UPDATE SET samples = samples + 1,
           rx_pps_sum = rx_pps_sum + excluded.rx_pps_sum, tx_pps_sum = tx_pps_sum + excluded.tx_pps_sum,
           rx_bps_sum = rx_bps_sum + excluded.rx_bps_sum, tx_bps_sum = tx_bps_sum + excluded.tx_bps_sum,
           errors_sum = errors_sum + excluded.errors_sum, drops_sum = drops_sum + excluded.drops_sum,
           pkts_sum = pkts_sum + excluded.pkts_sum, updated_at = excluded.updated_at`,
      ).bind(
        hostId,
        bucket,
        JSON.stringify(ifaces.map((i) => ({ i: i.iface, rp: i.rxPps, tp: i.txPps, rb: i.rxBps, tb: i.txBps, e: i.errors, d: i.drops, k: i.pkts }))),
        now,
      ),
    );
  }

  const byKey = new Map(components.map((c) => [`${c.type}/${c.slug}`, c]));
  const rows: Array<{ c: string; k: string; v: number }> = [];
  for (const rc of report.components) {
    const row = byKey.get(`${rc.type}/${rc.id}`);
    if (!row) continue;
    for (const [k, v] of componentMetricsOf(rc.type, rc.metrics)) rows.push({ c: row.component_id, k, v });
  }
  if (rows.length) {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO fleet_component_metric_5m (component_id, key, bucket, org_id, n, sum, max)
         SELECT json_extract(value, '$.c'), json_extract(value, '$.k'), ?1, 'default', 1, json_extract(value, '$.v'), json_extract(value, '$.v')
         FROM json_each(?2) WHERE true
         ON CONFLICT(component_id, key, bucket) DO UPDATE SET n = n + 1, sum = sum + excluded.sum, max = ${mx("max")}`,
      ).bind(bucket, JSON.stringify(rows)),
    );
  }
  return stmts;
}

export async function recordRollups(
  env: Env,
  hostId: string,
  receivedMs: number,
  report: StatusReport,
  components: Array<{ component_id: string; type: string; slug: string }>,
): Promise<void> {
  await env.DB.batch(rollupStatements(env, hostId, receivedMs, report, components));
}

// ---- hourly compaction and pruning -----------------------------------------------------------------
/** Completed hours are recomputed from the 5-minute rows (REPLACE semantics: idempotent, safe to re-run). */
export async function compactHours(env: Env, nowMs: number, lookbackHours = 6): Promise<number> {
  const endHour = bucketOf(nowMs, STEP_1H); // the current (incomplete) hour is not compacted
  const from = endHour - lookbackHours * STEP_1H;
  const now = isoNow();
  const sumCols = HOST_COLS.map((c) => `SUM(${c})`).join(", ");
  const maxCols = HOST_MAX.map((c) => `MAX(${c})`).join(", ");
  const sets = [...HOST_COLS, ...HOST_MAX].map((c) => `${c} = excluded.${c}`).join(", ");
  const cols = ["host_id", "bucket", "org_id", ...HOST_COLS, ...HOST_MAX, "created_at", "updated_at"].join(", ");
  const r = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO fleet_host_1h (${cols})
       SELECT host_id, (bucket / 3600) * 3600, 'default', ${sumCols}, ${maxCols}, ?3, ?3
       FROM fleet_host_5m WHERE bucket >= ?1 AND bucket < ?2 GROUP BY host_id, bucket / 3600
       ON CONFLICT(host_id, bucket) DO UPDATE SET ${sets}, updated_at = excluded.updated_at`,
    ).bind(from, endHour, now),
    env.DB.prepare(
      `INSERT INTO fleet_component_metric_1h (component_id, key, bucket, org_id, n, sum, max)
       SELECT component_id, key, (bucket / 3600) * 3600, 'default', SUM(n), SUM(sum), MAX(max)
       FROM fleet_component_metric_5m WHERE bucket >= ?1 AND bucket < ?2 GROUP BY component_id, key, bucket / 3600
       ON CONFLICT(component_id, key, bucket) DO UPDATE SET n = excluded.n, sum = excluded.sum, max = excluded.max`,
    ).bind(from, endHour),
  ]);
  return (r[0]?.meta.changes ?? 0) + (r[1]?.meta.changes ?? 0);
}

/** 5-minute data older than 48 h and 1-hour data older than 30 d are deleted. */
export async function pruneRollups(env: Env, nowMs: number): Promise<void> {
  const cut5 = Math.floor(nowMs / 1000) - KEEP_5M_S;
  const cut1 = Math.floor(nowMs / 1000) - KEEP_1H_S;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM fleet_host_5m WHERE bucket < ?1").bind(cut5),
    env.DB.prepare("DELETE FROM fleet_iface_5m WHERE bucket < ?1").bind(cut5),
    env.DB.prepare("DELETE FROM fleet_component_metric_5m WHERE bucket < ?1").bind(cut5),
    env.DB.prepare("DELETE FROM fleet_host_1h WHERE bucket < ?1").bind(cut1),
    env.DB.prepare("DELETE FROM fleet_component_metric_1h WHERE bucket < ?1").bind(cut1),
  ]);
}
