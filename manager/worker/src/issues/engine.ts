// Issue engine (05-manager.md section 14). evaluateReport() runs on every stored status report; the cron
// handler evaluateStaleness() covers hosts that stopped reporting.
//  - an issue opens when its rule holds (after its duration), at most one open issue per (host, kind, component)
//  - it resolves after TWO consecutive clean evaluations (hysteresis)
//  - an open host_offline suppresses the host's other issues (nothing new opens, nothing resolves)
//  - snoozed kinds are still recorded but never reach the platform webhook
import type { StatusReport } from "../agent/status-schema";
import { parseJson } from "../compile/load";
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { bucketOf, STEP_5M } from "../fleet/rollup";
import { newId } from "../util/ids";
import { isoAt, nowMs } from "../util/time";
import { type IssueEvent, notifyPlatform } from "./notify";
import { type Cond, type CompInfo, type Windows, evaluateRules } from "./rules";
import type { IssueRow } from "./store";
import { loadThresholds } from "./thresholds";

const HYSTERESIS = 2;

interface StateRow {
  kind: string;
  component_id: string;
  since: string | null;
  data: string | null;
}

const keyOf = (kind: string, comp: string | null): string => `${kind}|${comp ?? ""}`;

async function windows(env: Env, hostId: string, report: StatusReport, comps: Map<string, CompInfo>, th: Awaited<ReturnType<typeof loadThresholds>>, now: number): Promise<Windows> {
  const w: Windows = { cpu: null, iface: null, rejects: new Map() };
  const cpuFrom = bucketOf(now - th.cpu_high.avg_min * 60_000, STEP_5M);
  const ifFrom = bucketOf(now - th.iface_errors.window_min * 60_000, STEP_5M);
  const [a, b] = await env.DB.batch([
    env.DB.prepare("SELECT SUM(cpu_sum) AS s, SUM(cpu_n) AS n FROM fleet_host_5m WHERE host_id = ?1 AND bucket >= ?2").bind(hostId, cpuFrom),
    env.DB.prepare("SELECT SUM(errors_sum + drops_sum) AS e, SUM(pkts_sum) AS p, SUM(net_n) AS n FROM fleet_host_5m WHERE host_id = ?1 AND bucket >= ?2").bind(hostId, ifFrom),
  ]);
  const c = (a?.results?.[0] ?? {}) as { s: number | null; n: number | null };
  if (c.n && c.s !== null) w.cpu = { avg: c.s / c.n, n: c.n };
  const i = (b?.results?.[0] ?? {}) as { e: number | null; p: number | null; n: number | null };
  if (i.n) w.iface = { pct: i.p && i.p > 0 ? ((i.e ?? 0) / i.p) * 100 : null, n: i.n };
  const from5 = bucketOf(now - 300_000, STEP_5M);
  for (const rc of report.components) {
    if (rc.type !== "collector") continue;
    const comp = comps.get(`${rc.type}/${rc.id}`);
    if (!comp) continue;
    const rows = await env.DB.prepare(
      "SELECT key, SUM(sum) AS s, SUM(n) AS n FROM fleet_component_metric_5m WHERE component_id = ?1 AND bucket >= ?2 AND key IN ('ingest_rejected_per_min','ingest_records_per_s') GROUP BY key",
    )
      .bind(comp.component_id, from5)
      .all<{ key: string; s: number; n: number }>();
    const m = new Map((rows.results ?? []).map((r) => [r.key, r]));
    const rej = m.get("ingest_rejected_per_min");
    const acc = m.get("ingest_records_per_s");
    if (rej && rej.n > 0) {
      const rejected = rej.s / rej.n;
      const accepted = acc && acc.n > 0 ? (acc.s / acc.n) * 60 : 0;
      const total = rejected + accepted;
      if (total > 0) w.rejects.set(comp.component_id, { pct: (rejected / total) * 100, n: rej.n });
    }
  }
  return w;
}

function dedupe(conds: Cond[]): Cond[] {
  const best = new Map<string, Cond>();
  for (const c of conds) {
    const k = keyOf(c.kind, c.component_id);
    const cur = best.get(k);
    if (!cur || (c.severity === "crit" && cur.severity !== "crit")) best.set(k, c);
  }
  return [...best.values()];
}

interface Reconcile {
  hostId: string;
  site: string;
  now: number;
  conds: Cond[];
  /** kinds this pass is allowed to open / keep / resolve (null = all) */
  scope: Set<string> | null;
  snoozed: Set<string>;
  suppressed: boolean;
}

/** Builds the statements that open / update / resolve the host's issues; returns the events to announce. */
async function reconcile(env: Env, r: Reconcile): Promise<{ stmts: D1PreparedStatement[]; events: IssueEvent[] }> {
  const nowIso = isoAt(r.now);
  const open = (
    await env.DB.prepare("SELECT * FROM issues WHERE host_id = ?1 AND resolved_at IS NULL").bind(r.hostId).all<IssueRow & { clean_reports: number; notified: number }>()
  ).results ?? [];
  const stmts: D1PreparedStatement[] = [];
  const events: IssueEvent[] = [];
  const heldKeys = new Set<string>();
  const openByKey = new Map(open.map((o) => [keyOf(o.kind, o.component_id), o]));

  for (const c of r.conds) {
    const k = keyOf(c.kind, c.component_id);
    heldKeys.add(k);
    const cur = openByKey.get(k);
    if (cur) {
      const escalated = cur.severity === "warn" && c.severity === "crit";
      if (escalated || cur.clean_reports !== 0 || cur.detail !== c.detail || cur.severity !== c.severity) {
        stmts.push(
          env.DB.prepare("UPDATE issues SET severity = ?2, last_value = ?3, detail = ?4, clean_reports = 0, updated_at = ?5 WHERE issue_id = ?1").bind(cur.issue_id, c.severity, c.value, c.detail.slice(0, 512), nowIso),
        );
      }
      if (escalated && !r.snoozed.has(c.kind) && !r.suppressed) {
        events.push({ type: "open", issue: { ...cur, severity: "crit", detail: c.detail, last_value: c.value } });
      }
      continue;
    }
    const id = newId("iss_");
    const row: IssueRow = { issue_id: id, kind: c.kind, severity: c.severity, host_id: r.hostId, component_id: c.component_id, site: r.site, opened_at: nowIso, resolved_at: null, last_value: c.value, detail: c.detail.slice(0, 512) };
    stmts.push(
      env.DB.prepare(
        `INSERT OR IGNORE INTO issues (issue_id, org_id, kind, severity, host_id, component_id, site, opened_at, resolved_at, clean_reports, last_value, detail, created_at, updated_at, notified)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, 0, ?9, ?10, ?8, ?8, 0)`,
      ).bind(id, DEFAULT_ORG, c.kind, c.severity, r.hostId, c.component_id, r.site, nowIso, c.value, row.detail),
    );
    if (c.severity === "crit" && !r.snoozed.has(c.kind) && !r.suppressed) events.push({ type: "open", issue: row });
  }

  for (const o of open) {
    const k = keyOf(o.kind, o.component_id);
    if (heldKeys.has(k)) continue;
    if (r.scope && !r.scope.has(o.kind)) continue;
    const clean = o.clean_reports + 1;
    if (clean >= HYSTERESIS) {
      stmts.push(
        env.DB.prepare("UPDATE issues SET resolved_at = ?2, clean_reports = ?3, updated_at = ?2 WHERE issue_id = ?1").bind(o.issue_id, nowIso, clean),
        // an "until resolved" snooze ends with the issue; a time-boxed one just expires
        env.DB.prepare("DELETE FROM issue_snoozes WHERE host_id = ?1 AND kind = ?2 AND until_resolved = 1").bind(r.hostId, o.kind),
      );
      if (o.severity === "crit" && o.notified === 1 && !r.snoozed.has(o.kind)) events.push({ type: "resolved", issue: { ...o, resolved_at: nowIso } });
    } else {
      stmts.push(env.DB.prepare("UPDATE issues SET clean_reports = ?2, updated_at = ?3 WHERE issue_id = ?1").bind(o.issue_id, clean, nowIso));
    }
  }
  return { stmts, events };
}

async function announce(env: Env, events: IssueEvent[]): Promise<void> {
  for (const ev of events) {
    const sent = await notifyPlatform(env, ev);
    if (sent && ev.type === "open") await env.DB.prepare("UPDATE issues SET notified = 1 WHERE issue_id = ?1").bind(ev.issue.issue_id).run();
  }
}

async function snoozedKinds(env: Env, hostId: string, now: number): Promise<Set<string>> {
  const rows = await env.DB.prepare("SELECT kind FROM issue_snoozes WHERE host_id = ?1 AND (until_resolved = 1 OR until > ?2)").bind(hostId, isoAt(now)).all<{ kind: string }>();
  return new Set((rows.results ?? []).map((r) => r.kind));
}

/** Evaluate every report-driven rule for one host after its status report was stored. */
export async function evaluateReport(env: Env, hostId: string, report: StatusReport, receivedMs: number = nowMs()): Promise<void> {
  const host = await env.DB.prepare("SELECT site, desired_version, applied_version, status_interval_s FROM hosts WHERE host_id = ?1").bind(hostId).first<{
    site: string;
    desired_version: number | null;
    applied_version: number | null;
    status_interval_s: number | null;
  }>();
  if (!host) return;
  const compRows = (await env.DB.prepare("SELECT component_id, type, slug, config_json FROM components WHERE host_id = ?1").bind(hostId).all<{ component_id: string; type: string; slug: string; config_json: string }>()).results ?? [];
  const comps = new Map<string, CompInfo>(compRows.map((c) => [`${c.type}/${c.slug}`, { component_id: c.component_id, type: c.type, slug: c.slug, config: parseJson(c.config_json, {}) }]));
  const th = await loadThresholds(env);
  const win = await windows(env, hostId, report, comps, th, receivedMs);
  const stateRows = (await env.DB.prepare("SELECT kind, component_id, since, data FROM issue_state WHERE host_id = ?1").bind(hostId).all<StateRow>()).results ?? [];
  const state = new Map(stateRows.map((s) => [keyOf(s.kind, s.component_id), s]));
  const dataWrites = new Map<string, unknown>();
  const intervalS = report.metrics.interval_s ?? host.status_interval_s ?? 60;

  const raw = dedupe(
    evaluateRules({
      nowMs: receivedMs,
      th,
      report,
      intervalS,
      host,
      comps,
      win,
      getData: (kind, comp) => {
        const s = state.get(keyOf(kind, comp));
        return s?.data ? parseJson(s.data, null) : null;
      },
      setData: (kind, comp, data) => dataWrites.set(keyOf(kind, comp), data),
    }),
  );

  const offlineOpen = !!(await env.DB.prepare("SELECT 1 AS x FROM issues WHERE host_id = ?1 AND kind = 'host_offline' AND resolved_at IS NULL").bind(hostId).first());
  const openNow = new Set(
    ((await env.DB.prepare("SELECT kind, component_id FROM issues WHERE host_id = ?1 AND resolved_at IS NULL").bind(hostId).all<{ kind: string; component_id: string | null }>()).results ?? []).map((o) => keyOf(o.kind, o.component_id)),
  );
  const nowIso = isoAt(receivedMs);
  const stateStmts: D1PreparedStatement[] = [];
  const active: Cond[] = [];
  const rawKeys = new Set(raw.map((c) => keyOf(c.kind, c.component_id)));
  for (const c of raw) {
    const k = keyOf(c.kind, c.component_id);
    if (!c.forS) {
      active.push(c);
      continue;
    }
    if (openNow.has(k)) {
      active.push(c); // already open: the duration only gates opening
      continue;
    }
    const st = state.get(k);
    if (!st?.since) {
      stateStmts.push(
        env.DB.prepare(
          `INSERT INTO issue_state (host_id, kind, component_id, org_id, since, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?5)
           ON CONFLICT(host_id, kind, component_id) DO UPDATE SET since = excluded.since, updated_at = excluded.updated_at`,
        ).bind(hostId, c.kind, c.component_id ?? "", DEFAULT_ORG, nowIso),
      );
      if (c.forS <= 0) active.push(c);
    } else if (receivedMs - Date.parse(st.since) >= c.forS * 1000) {
      active.push(c);
    }
  }
  // a duration-gated rule that stopped holding loses its pending "since"
  for (const [k, st] of state) if (st.since && !rawKeys.has(k)) stateStmts.push(env.DB.prepare("DELETE FROM issue_state WHERE host_id = ?1 AND kind = ?2 AND component_id = ?3").bind(hostId, st.kind, st.component_id));
  for (const [k, data] of dataWrites) {
    const [kind, comp] = k.split("|") as [string, string];
    stateStmts.push(
      env.DB.prepare(
        `INSERT INTO issue_state (host_id, kind, component_id, org_id, since, data, updated_at) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)
         ON CONFLICT(host_id, kind, component_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
      ).bind(hostId, kind, comp, DEFAULT_ORG, JSON.stringify(data), nowIso),
    );
  }

  const snoozed = await snoozedKinds(env, hostId, receivedMs);
  const { stmts, events } = await reconcile(env, {
    hostId,
    site: host.site,
    now: receivedMs,
    conds: offlineOpen ? [] : active,
    scope: offlineOpen ? new Set(["host_offline", "host_stale"]) : null,
    snoozed,
    suppressed: offlineOpen,
  });
  const all = [...stateStmts, ...stmts];
  if (all.length) await env.DB.batch(all);
  await announce(env, events);
}

/** Cron: stale after 3 x status interval, offline after 10 min without a report. */
export async function evaluateStaleness(env: Env, now: number = nowMs()): Promise<{ stale: number; offline: number }> {
  const def = await env.DB.prepare("SELECT agent_status_interval_s FROM settings WHERE org_id = ?1").bind(DEFAULT_ORG).first<{ agent_status_interval_s: number }>();
  const hosts = (
    await env.DB.prepare("SELECT host_id, site, state, last_seen, status_interval_s FROM hosts WHERE state IN ('enrolled','stale','offline') AND last_seen IS NOT NULL").all<{
      host_id: string;
      site: string;
      state: string;
      last_seen: string;
      status_interval_s: number | null;
    }>()
  ).results ?? [];
  let stale = 0;
  let offline = 0;
  for (const h of hosts) {
    const interval = h.status_interval_s ?? def?.agent_status_interval_s ?? 60;
    const age = now - Date.parse(h.last_seen);
    let kind: "host_stale" | "host_offline" | null = null;
    if (age >= 600_000) kind = "host_offline";
    else if (age > 3 * interval * 1000) kind = "host_stale";
    if (!kind) continue;
    const newState = kind === "host_offline" ? "offline" : "stale";
    const nowIso = isoAt(now);
    const detail = kind === "host_offline" ? `no status report for ${Math.floor(age / 60000)} min` : `no status report for ${Math.floor(age / 1000)} s (3 x ${interval} s)`;
    const cond: Cond = { kind, component_id: null, severity: kind === "host_offline" ? "crit" : "warn", value: Math.floor(age / 1000), detail };
    const stmts: D1PreparedStatement[] = [env.DB.prepare("UPDATE hosts SET state = ?2, updated_at = ?3 WHERE host_id = ?1 AND state IN ('enrolled','stale','offline')").bind(h.host_id, newState, nowIso)];
    const snoozed = await snoozedKinds(env, h.host_id, now);
    // offline replaces stale: the stale issue is closed immediately (no hysteresis: the host got worse, not better)
    if (kind === "host_offline") stmts.push(env.DB.prepare("UPDATE issues SET resolved_at = ?2, updated_at = ?2 WHERE host_id = ?1 AND kind = 'host_stale' AND resolved_at IS NULL").bind(h.host_id, nowIso));
    const { stmts: rs, events } = await reconcile(env, { hostId: h.host_id, site: h.site, now, conds: [cond], scope: new Set(), snoozed, suppressed: false });
    await env.DB.batch([...stmts, ...rs]);
    await announce(env, events);
    if (kind === "host_offline") offline++;
    else stale++;
  }
  return { stale, offline };
}

/** Daily/hourly housekeeping: resolved issues older than 30 days, expired snoozes, pending state of removed hosts. */
export async function pruneIssues(env: Env, now: number = nowMs()): Promise<void> {
  const cut = isoAt(now - 30 * 86400_000);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM issues WHERE resolved_at IS NOT NULL AND resolved_at < ?1").bind(cut),
    env.DB.prepare("DELETE FROM issue_snoozes WHERE until_resolved = 0 AND until IS NOT NULL AND until < ?1").bind(isoAt(now)),
    env.DB.prepare("DELETE FROM issue_state WHERE host_id NOT IN (SELECT host_id FROM hosts)"),
  ]);
}
