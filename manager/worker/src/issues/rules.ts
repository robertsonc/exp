// Issue rules (05-manager.md section 14), pure over the report + precomputed windows. They return the
// conditions that currently HOLD; durations, opening and hysteresis are applied by the engine.
// host_stale / host_offline are evaluated by cron only (a report is proof the host is alive).
import type { StatusReport } from "../agent/status-schema";
import type { Thresholds } from "./thresholds";

export type Severity = "warn" | "crit";
export const ISSUE_KINDS = [
  "host_stale", "host_offline", "disk_high", "storage_runway", "mem_low", "cpu_high", "clock", "component_unhealthy",
  "crash_loop", "reconcile_failed", "version_drift", "probe_ports", "probe_push_lag", "probe_spool", "probe_collector",
  "collector_rejects", "collector_vm", "collector_probes", "dashboard_collectors", "iface_errors",
] as const;
export type IssueKind = (typeof ISSUE_KINDS)[number];

export interface Cond {
  kind: IssueKind;
  component_id: string | null;
  severity: Severity;
  value: number | null;
  detail: string;
  /** the rule must hold continuously for this long before the issue opens */
  forS?: number;
}

export interface CompInfo {
  component_id: string;
  type: string;
  slug: string;
  config: Record<string, unknown>;
}

export interface Windows {
  /** average cpu over the window with its sample count, null when no data */
  cpu: { avg: number; n: number } | null;
  /** (errors + drops) / packets in percent over the window, with sample count */
  iface: { pct: number | null; n: number } | null;
  /** per collector component: rejected share of ingest over the window */
  rejects: Map<string, { pct: number; n: number }>;
}

export interface RuleCtx {
  nowMs: number;
  th: Thresholds;
  report: StatusReport;
  intervalS: number;
  host: { desired_version: number | null; applied_version: number | null };
  comps: Map<string, CompInfo>; // key `${type}/${slug}`
  win: Windows;
  getData: (kind: string, comp: string) => unknown;
  setData: (kind: string, comp: string, data: unknown) => void;
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const fmt = (v: number, d = 1): string => String(Math.round(v * 10 ** d) / 10 ** d);

/** enough samples inside a window: at least 80 % of the expected report count */
export const coverageOk = (n: number, windowS: number, intervalS: number): boolean => n >= Math.max(1, Math.floor((0.8 * windowS) / intervalS));

export function evaluateRules(ctx: RuleCtx): Cond[] {
  const out: Cond[] = [];
  const { th, report: r } = ctx;
  const m = r.metrics;

  // disk_high
  const disks = (m.disk ?? []).filter((d) => num(d.pct) !== null) as Array<{ mount: string; pct: number }>;
  if (disks.length) {
    const top = disks.reduce((a, b) => (b.pct > a.pct ? b : a));
    if (top.pct >= th.disk_high.warn_pct) {
      out.push({ kind: "disk_high", component_id: null, severity: top.pct >= th.disk_high.crit_pct ? "crit" : "warn", value: top.pct, detail: `${top.mount} ${fmt(top.pct)}% used` });
    }
  }

  // mem_low (duration)
  const mem = m.mem;
  if (mem) {
    const avail = num(mem.available_mb);
    const total = num(mem.total_mb);
    const pctAvail = avail !== null && total ? (avail / total) * 100 : num(mem.pct) !== null ? 100 - (mem.pct as number) : null;
    if (pctAvail !== null && pctAvail < th.mem_low.available_pct) {
      out.push({ kind: "mem_low", component_id: null, severity: "warn", value: pctAvail, detail: `${fmt(pctAvail)}% memory available`, forS: th.mem_low.for_min * 60 });
    }
  }

  // cpu_high (windowed average)
  const cpuWin = th.cpu_high.avg_min * 60;
  if (ctx.win.cpu && ctx.win.cpu.avg >= th.cpu_high.pct && coverageOk(ctx.win.cpu.n, cpuWin, ctx.intervalS)) {
    out.push({ kind: "cpu_high", component_id: null, severity: "warn", value: ctx.win.cpu.avg, detail: `cpu ${fmt(ctx.win.cpu.avg)}% averaged over ${th.cpu_high.avg_min} min` });
  }

  // clock
  const t = r.facts.time;
  if (t) {
    const off = num(t.offset_ms);
    if (t.synced === false) out.push({ kind: "clock", component_id: null, severity: "warn", value: off, detail: "time is not synchronised" });
    else if (off !== null && Math.abs(off) > th.clock.offset_ms) out.push({ kind: "clock", component_id: null, severity: "warn", value: off, detail: `clock offset ${fmt(off)} ms` });
  }

  // reconcile_failed
  if (r.reconcile && (r.reconcile.result === "error" || r.reconcile.result === "rolled_back")) {
    out.push({ kind: "reconcile_failed", component_id: null, severity: "warn", value: null, detail: `last reconcile ${r.reconcile.result}${r.reconcile.error ? `: ${r.reconcile.error}`.slice(0, 200) : ""}` });
  }

  // version_drift (duration)
  const desired = ctx.host.desired_version;
  const applied = r.agent.applied_version ?? ctx.host.applied_version;
  if (desired !== null && applied !== desired) {
    out.push({ kind: "version_drift", component_id: null, severity: "warn", value: applied ?? null, detail: `applied ${applied ?? "none"} != desired ${desired}`, forS: th.version_drift.minutes * 60 });
  }

  // iface_errors (windowed)
  const ie = ctx.win.iface;
  if (ie && ie.pct !== null && ie.pct > th.iface_errors.pct && coverageOk(ie.n, th.iface_errors.window_min * 60, ctx.intervalS)) {
    out.push({ kind: "iface_errors", component_id: null, severity: "warn", value: ie.pct, detail: `management interface errors+drops ${fmt(ie.pct, 3)}% of packets over ${th.iface_errors.window_min} min` });
  }

  // component rules
  for (const rc of r.components) {
    const c = ctx.comps.get(`${rc.type}/${rc.id}`);
    if (!c) continue;
    const cid = c.component_id;
    const label = `${rc.type} ${rc.id}`;
    const met = (rc.metrics ?? {}) as Record<string, unknown>;
    const facts = (rc.facts ?? {}) as Record<string, unknown>;

    if (rc.health === "degraded" || rc.health === "fail") {
      out.push({ kind: "component_unhealthy", component_id: cid, severity: rc.health === "fail" ? "crit" : "warn", value: null, detail: `${label} ${rc.health}${rc.detail ? `: ${rc.detail}`.slice(0, 200) : ""}` });
    }

    // crash_loop: restarts counted from successive samples of the process restart counter
    const restarts = num(rc.process?.restarts);
    if (restarts !== null) {
      const win = th.crash_loop.window_min * 60_000;
      const prev = (Array.isArray(ctx.getData("crash_loop", cid)) ? (ctx.getData("crash_loop", cid) as Array<[number, number]>) : []).filter(
        (s) => Array.isArray(s) && s.length === 2 && ctx.nowMs - s[0] <= win,
      );
      const samples = [...prev, [ctx.nowMs, restarts] as [number, number]].slice(-200);
      ctx.setData("crash_loop", cid, samples);
      let count = 0;
      for (let i = 1; i < samples.length; i++) {
        const a = (samples[i - 1] as [number, number])[1];
        const b = (samples[i] as [number, number])[1];
        count += b >= a ? b - a : b; // a counter reset means the unit restarted at least `b` times
      }
      if (count >= th.crash_loop.restarts) {
        out.push({ kind: "crash_loop", component_id: cid, severity: "crit", value: count, detail: `${label} restarted ${count} times in ${th.crash_loop.window_min} min` });
      }
    }

    if (rc.type === "probe") {
      const ports = Array.isArray(met.ports) ? (met.ports as Array<Record<string, unknown>>) : [];
      const bad = ports.filter((p) => p && p.role === "client" && (p.leased === false || p.link === "down"));
      if (bad.length) {
        out.push({ kind: "probe_ports", component_id: cid, severity: "warn", value: bad.length, detail: `${bad.length} client port(s) without lease or link down: ${bad.slice(0, 5).map((p) => String(p.id)).join(", ")}` });
      }
      const lag = num(met.push_lag_s);
      if (lag !== null && lag > th.probe_push_lag.warn_s) {
        out.push({ kind: "probe_push_lag", component_id: cid, severity: lag > th.probe_push_lag.crit_s ? "crit" : "warn", value: lag, detail: `${label} push lag ${fmt(lag, 0)} s` });
      }
      const spoolBytes = num(met.spool_bytes);
      const spoolCfg = c.config.spool as { max_mb?: unknown } | undefined;
      const maxMb = typeof spoolCfg?.max_mb === "number" && spoolCfg.max_mb > 0 ? spoolCfg.max_mb : 500;
      if (spoolBytes !== null) {
        const pct = (spoolBytes / (maxMb * 1024 * 1024)) * 100;
        if (pct > th.probe_spool.pct) out.push({ kind: "probe_spool", component_id: cid, severity: "warn", value: pct, detail: `${label} spool ${fmt(pct)}% of ${maxMb} MB` });
      }
      if (facts.collector_reachable === false) {
        out.push({ kind: "probe_collector", component_id: cid, severity: "crit", value: null, detail: `${label} cannot reach its collector`, forS: 120 });
      }
    }

    if (rc.type === "collector") {
      const dtf = num(met.days_to_full);
      if (dtf !== null && dtf < th.storage_runway.warn_days) {
        out.push({ kind: "storage_runway", component_id: cid, severity: dtf < th.storage_runway.crit_days ? "crit" : "warn", value: dtf, detail: `${label} storage full in ${fmt(dtf)} days` });
      }
      const rej = ctx.win.rejects.get(cid);
      if (rej && rej.pct > 1 && coverageOk(rej.n, 300, ctx.intervalS)) {
        out.push({ kind: "collector_rejects", component_id: cid, severity: "warn", value: rej.pct, detail: `${label} rejected ${fmt(rej.pct)}% of ingest over 5 min` });
      }
      const vmUp = num(met.vm_up);
      const backlog = num(met.vm_backlog_points);
      if (vmUp === 0) {
        out.push({ kind: "collector_vm", component_id: cid, severity: "crit", value: 0, detail: `${label} VictoriaMetrics is down` });
      }
      if (backlog !== null) {
        const keep = 15 * 60_000;
        const prev = (Array.isArray(ctx.getData("collector_vm", cid)) ? (ctx.getData("collector_vm", cid) as Array<[number, number]>) : []).filter(
          (s) => Array.isArray(s) && s.length === 2 && ctx.nowMs - s[0] <= keep,
        );
        const samples = [...prev, [ctx.nowMs, backlog] as [number, number]].slice(-200);
        ctx.setData("collector_vm", cid, samples);
        const win10 = samples.filter((s) => ctx.nowMs - s[0] <= 10 * 60_000 + 1000);
        const first = win10[0];
        const last = win10[win10.length - 1];
        const spans = first !== undefined && last !== undefined && last[0] - first[0] >= 10 * 60_000 - 5_000;
        const mono = win10.every((s, i) => i === 0 || s[1] >= (win10[i - 1] as [number, number])[1]);
        if (vmUp !== 0 && spans && mono && first !== undefined && last !== undefined && last[1] > first[1]) {
          out.push({ kind: "collector_vm", component_id: cid, severity: "crit", value: backlog, detail: `${label} VictoriaMetrics write backlog growing for 10 min (${fmt(backlog, 0)} points)` });
        }
      }
      const total = num(met.probes_total);
      const reporting = num(met.probes_reporting);
      if (total !== null && reporting !== null && reporting < total) {
        out.push({ kind: "collector_probes", component_id: cid, severity: "warn", value: total - reporting, detail: `${label}: ${reporting}/${total} probes reporting`, forS: 120 });
      }
    }

    if (rc.type === "dashboard") {
      const total = num(met.collectors_total);
      const reach = num(met.collectors_reachable);
      if (total !== null && reach !== null && reach < total) {
        out.push({ kind: "dashboard_collectors", component_id: cid, severity: "warn", value: total - reach, detail: `${label}: ${reach}/${total} collectors reachable` });
      }
    }
  }
  return out;
}
