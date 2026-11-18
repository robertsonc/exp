// Helpers for roll-up / issue / cron tests: a simulated clock, a status-report builder, and a direct feed of
// reports into the same hook the status route calls (avoids the per-agent rate limit for long series).
import { StatusSchema } from "../src/agent/status-schema";
import { onStatusStored } from "../src/fleet-hooks";
import { setClock } from "../src/util/time";
import { FACTS, env } from "./helpers";

export const T0 = Date.parse("2026-11-18T10:00:00.000Z"); // an exact hour
export const MIN = 60_000;
export const at = (min: number): number => T0 + min * MIN;
export const useClock = (ms: number): void => setClock(() => ms);

export interface RO {
  cpu?: number | null;
  memAvailPct?: number;
  disks?: Array<{ mount: string; pct: number }>;
  time?: { synced: boolean; offset_ms: number | null };
  reconcile?: { at: string; result: "ok" | "error" | "rolled_back"; error: string | null } | null;
  applied?: number | null;
  net?: Array<Record<string, unknown>> | null;
  comps?: Array<Record<string, unknown>>;
  interval?: number;
  uptime?: number | null;
  facts?: Record<string, unknown>;
}

export function report(o: RO = {}): Record<string, unknown> {
  const total = 32000;
  const avail = Math.round((total * (o.memAvailPct ?? 70)) / 100);
  return {
    schema: "exp.status/1",
    agent: { version: "0.1.0", desired_version: 1, applied_version: o.applied === undefined ? 1 : o.applied, uptime_s: 86400, last_poll: null },
    facts: { ...(o.facts ?? FACTS()), ...(o.time ? { time: { synced: o.time.synced, source: "systemd-timesyncd", offset_ms: o.time.offset_ms } } : {}) },
    metrics: {
      interval_s: o.interval ?? 60,
      uptime_s: o.uptime === undefined ? 1234567 : o.uptime,
      cpu: { pct: o.cpu === undefined ? 20 : o.cpu, iowait_pct: 0, steal_pct: 0, load1: 0.8, load5: 0.6, load15: 0.5 },
      mem: { total_mb: total, used_mb: total - avail, available_mb: avail, pct: 100 - (o.memAvailPct ?? 70), swap_used_mb: 0 },
      disk: o.disks ?? [{ mount: "/", total_gb: 437, used_gb: 13, pct: 3 }],
      disk_io: { read_kbps: 1, write_kbps: 5 },
      net:
        o.net === null
          ? []
          : o.net ?? [{ iface: "eno1", role: "mgmt", link: "up", speed_mbps: 1000, rx_pps: 100, tx_pps: 50, rx_bps: 800000, tx_bps: 400000, rx_errors: 0, tx_errors: 0, rx_drops: 0, tx_drops: 0 }],
    },
    components: o.comps ?? [],
    reconcile: o.reconcile === undefined ? { at: "2026-11-18T10:00:00.000Z", result: "ok", error: null, duration_ms: 100 } : o.reconcile,
    events: [],
  };
}

export const collectorComp = (metrics: Record<string, unknown> = {}, over: Record<string, unknown> = {}) => ({
  type: "collector", id: "col-hallb", state: "running", health: "ok", version: "0.1.0",
  process: { cpu_pct: 2, rss_mb: 100, restarts: 0, uptime_s: 1000 },
  metrics: { ingest_records_per_s: 100, ingest_rejected_per_min: 0, probes_total: 2, probes_reporting: 2, vm_up: 1, vm_backlog_points: 0, days_to_full: 90, ...metrics },
  facts: { listen: "10.32.98.25:8443", tls_fingerprint_sha256: "DC:2B:CE:95:F2:A0:0C:B9:5B:3A:CF:F5:00:CB:0C:DE:E7:BD:CA:AC:63:CC:83:95:F6:30:EA:F1:27:34:6D:C6" },
  ...over,
});
export const probeComp = (metrics: Record<string, unknown> = {}, facts: Record<string, unknown> = {}, over: Record<string, unknown> = {}) => ({
  type: "probe", id: "probe-a1", state: "running", health: "ok", version: "0.1.0",
  process: { cpu_pct: 1, rss_mb: 50, restarts: 0, uptime_s: 1000 },
  metrics: { measurements_per_min: 120, fail_per_min: 0, spool_depth: 0, spool_bytes: 0, push_lag_s: 1, clock_offset_ms: 2, ports: [], ...metrics },
  facts: { collector_reachable: true, ...facts },
  ...over,
});
export const dashComp = (metrics: Record<string, unknown> = {}, over: Record<string, unknown> = {}) => ({
  type: "dashboard", id: "dash-main", state: "running", health: "ok", version: "0.1.0",
  metrics: { sessions_active: 2, requests_per_min: 30, collectors_total: 1, collectors_reachable: 1, ...metrics },
  facts: { url: "https://10.32.98.30" },
  ...over,
});

/** Same effect as POST /status for the hook stages (hosts row refresh + rollups + issue rules), at simulated time t. */
export async function feed(hostId: string, t: number, rep: Record<string, unknown>): Promise<void> {
  useClock(t);
  const parsed = StatusSchema.parse(rep);
  const iso = new Date(t).toISOString();
  await env.DB.prepare(
    `UPDATE hosts SET last_seen = ?2, applied_version = ?3, agent_version = ?4,
       state = CASE WHEN state IN ('stale','offline') THEN 'enrolled' ELSE state END, updated_at = ?2 WHERE host_id = ?1`,
  ).bind(hostId, iso, parsed.agent.applied_version ?? null, parsed.agent.version).run();
  const host = await env.DB.prepare("SELECT site FROM hosts WHERE host_id = ?1").bind(hostId).first<{ site: string }>();
  const comps = (await env.DB.prepare("SELECT component_id, type, slug FROM components WHERE host_id = ?1").bind(hostId).all<{ component_id: string; type: string; slug: string }>()).results ?? [];
  await onStatusStored(env, { hostId, site: host!.site, receivedAt: iso, report: parsed, components: comps });
}

export interface IssueRowT {
  issue_id: string;
  kind: string;
  severity: string;
  host_id: string;
  component_id: string | null;
  opened_at: string;
  resolved_at: string | null;
  last_value: number | null;
  detail: string;
  clean_reports: number;
  notified: number;
}
export async function issuesOf(hostId: string, kind?: string): Promise<IssueRowT[]> {
  const r = await env.DB.prepare(`SELECT * FROM issues WHERE host_id = ?1 ${kind ? "AND kind = ?2" : ""} ORDER BY opened_at, issue_id`).bind(...(kind ? [hostId, kind] : [hostId])).all<IssueRowT>();
  return r.results ?? [];
}
export const openOf = async (hostId: string, kind?: string): Promise<IssueRowT[]> => (await issuesOf(hostId, kind)).filter((i) => i.resolved_at === null);
