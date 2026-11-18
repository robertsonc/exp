// 05-manager.md section 15 item 10: every section-14 rule opens and resolves with hysteresis; host_offline
// suppresses the host's other issues; snooze hides (UI + webhook) and is audited; the platform webhook fires
// on crit open and on resolve only.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluateStaleness } from "../../src/issues/engine";
import { runEveryFiveMinutes } from "../../src/cron";
import { setClock } from "../../src/util/time";
import { type Harness, harness } from "../admin-harness";
import { MIN, T0, at, collectorComp, dashComp, feed, issuesOf, openOf, probeComp, report, useClock } from "../fleet-helpers";
import { env, fullScenario, resetDb, seedSiteWithRelease, type Scenario } from "../helpers";

let h: Harness;
let sc: Scenario;
beforeEach(async () => {
  await resetDb();
  useClock(T0);
  h = await harness();
  await seedSiteWithRelease("hall-b", "0.1.0");
  sc = await fullScenario();
  for (const t of ["fleet_host_5m", "fleet_iface_5m", "fleet_component_metric_5m", "issues", "issue_state", "audit"]) await env.DB.prepare(`DELETE FROM ${t}`).run();
  await env.DB.prepare("UPDATE hosts SET last_seen = ?1, state = 'enrolled'").bind(new Date(T0).toISOString()).run();
  useClock(T0);
});
afterEach(() => {
  h.restore();
  setClock(null);
});

type Rep = Record<string, unknown>;
const COL = () => sc.col.host_id;
const PROBE = () => sc.probe.host_id;
const DASH = () => sc.dash.host_id;

/** feeds `n` one-minute reports built by `mk(i)` starting at minute `from`; returns the next minute */
async function run(host: string, from: number, n: number, mk: (i: number) => Rep): Promise<number> {
  for (let i = 0; i < n; i++) await feed(host, at(from + i), mk(i));
  return from + n;
}

/** opens with `hold`, then proves hysteresis: one clean report keeps it open, a re-hold resets, two clean resolve */
async function holdsThenResolves(host: string, kind: string, hold: Rep, clean: Rep, severity: string, holdMinutes = 1) {
  let m = await run(host, 0, holdMinutes, () => hold);
  const opened = await openOf(host, kind);
  expect(opened, `${kind} open`).toHaveLength(1);
  expect(opened[0]).toMatchObject({ severity, kind });
  m = await run(host, m, 1, () => clean);
  expect((await openOf(host, kind))[0]!.clean_reports).toBe(1); // one clean report: still open
  m = await run(host, m, 1, () => hold);
  expect((await openOf(host, kind))[0]!.clean_reports).toBe(0); // holding again resets the counter
  m = await run(host, m, 2, () => clean);
  expect(await openOf(host, kind), `${kind} resolved`).toHaveLength(0);
  const all = await issuesOf(host, kind);
  expect(all).toHaveLength(1); // one issue row whole life: no flapping duplicates
  expect(all[0]!.resolved_at).not.toBeNull();
  return m;
}

describe("host rules", () => {
  it("disk_high: warn >= 85 %, crit >= 95 % (escalates in place), resolves after two clean reports", async () => {
    const disk = (pct: number) => report({ disks: [{ mount: "/", pct }, { mount: "/var/lib/exp", pct: 10 }] });
    await feed(COL(), at(0), disk(84));
    expect(await openOf(COL())).toHaveLength(0);
    await feed(COL(), at(1), disk(86));
    expect((await openOf(COL(), "disk_high"))[0]).toMatchObject({ severity: "warn", last_value: 86 });
    await feed(COL(), at(2), disk(96));
    const i = (await openOf(COL(), "disk_high"))[0]!;
    expect(i).toMatchObject({ severity: "crit", last_value: 96 });
    expect(i.detail).toContain("/");
    await feed(COL(), at(3), disk(50));
    await feed(COL(), at(4), disk(50));
    expect(await openOf(COL(), "disk_high")).toHaveLength(0);
    expect(await issuesOf(COL(), "disk_high")).toHaveLength(1);
  });

  it("mem_low: available < 10 % for 10 minutes (not before)", async () => {
    for (let i = 0; i < 10; i++) {
      await feed(COL(), at(i), report({ memAvailPct: 5 }));
      expect(await openOf(COL(), "mem_low"), `minute ${i}`).toHaveLength(0);
    }
    await feed(COL(), at(10), report({ memAvailPct: 5 }));
    expect((await openOf(COL(), "mem_low"))[0]).toMatchObject({ severity: "warn" });
    await feed(COL(), at(11), report({ memAvailPct: 60 }));
    await feed(COL(), at(12), report({ memAvailPct: 60 }));
    expect(await openOf(COL(), "mem_low")).toHaveLength(0);
    // a dip that recovers before 10 minutes never opens (the pending timer resets)
    await run(COL(), 20, 6, () => report({ memAvailPct: 5 }));
    await feed(COL(), at(26), report({ memAvailPct: 60 }));
    await run(COL(), 27, 6, () => report({ memAvailPct: 5 }));
    expect(await openOf(COL(), "mem_low")).toHaveLength(0);
  });

  it("cpu_high: >= 90 % averaged over 15 minutes", async () => {
    await run(COL(), 0, 10, () => report({ cpu: 99 }));
    expect(await openOf(COL(), "cpu_high")).toHaveLength(0); // not enough history yet
    await run(COL(), 10, 6, () => report({ cpu: 99 }));
    expect((await openOf(COL(), "cpu_high"))[0]).toMatchObject({ severity: "warn" });
    expect((await openOf(COL(), "cpu_high"))[0]!.last_value).toBeGreaterThanOrEqual(90);
    await run(COL(), 16, 25, () => report({ cpu: 5 }));
    expect(await openOf(COL(), "cpu_high")).toHaveLength(0);
    // a single spike does not average to 90
    await run(COL(), 60, 14, () => report({ cpu: 5 }));
    await feed(COL(), at(74), report({ cpu: 100 }));
    expect(await openOf(COL(), "cpu_high")).toHaveLength(0);
  });

  it("clock: not synced, or |offset| > 1 s", async () => {
    await holdsThenResolves(COL(), "clock", report({ time: { synced: false, offset_ms: null } }), report({ time: { synced: true, offset_ms: 3 } }), "warn");
    await feed(COL(), at(20), report({ time: { synced: true, offset_ms: 2500 } }));
    expect((await openOf(COL(), "clock"))[0]!.last_value).toBe(2500);
  });

  it("reconcile_failed: last reconcile error or rolled_back", async () => {
    const bad = (result: "error" | "rolled_back") => report({ reconcile: { at: "2026-11-18T10:00:00.000Z", result, error: "boom" } });
    await holdsThenResolves(COL(), "reconcile_failed", bad("rolled_back"), report(), "warn");
    await feed(COL(), at(20), bad("error"));
    expect(await openOf(COL(), "reconcile_failed")).toHaveLength(1);
  });

  it("version_drift: applied != desired for more than 10 minutes", async () => {
    const desired = (await env.DB.prepare("SELECT desired_version FROM hosts WHERE host_id = ?1").bind(COL()).first<{ desired_version: number }>())!.desired_version;
    expect(desired).toBeGreaterThan(0);
    await run(COL(), 0, 10, () => report({ applied: desired - 1 }));
    expect(await openOf(COL(), "version_drift")).toHaveLength(0);
    await run(COL(), 10, 2, () => report({ applied: desired - 1 }));
    expect((await openOf(COL(), "version_drift"))[0]).toMatchObject({ severity: "warn", last_value: desired - 1 });
    await run(COL(), 12, 2, () => report({ applied: desired }));
    expect(await openOf(COL(), "version_drift")).toHaveLength(0);
  });

  it("iface_errors: management errors + drops > 0.1 % of packets over 15 minutes", async () => {
    const errs = (e: number) => report({ net: [{ iface: "eno1", role: "mgmt", link: "up", rx_pps: 1000, tx_pps: 1000, rx_bps: 1, tx_bps: 1, rx_errors: e, tx_errors: 0, rx_drops: 0, tx_drops: 0 }] });
    await run(COL(), 0, 16, () => errs(500)); // 500 / 120000 = 0.42 %
    const i = (await openOf(COL(), "iface_errors"))[0]!;
    expect(i.severity).toBe("warn");
    expect(i.last_value).toBeGreaterThan(0.1);
    await run(COL(), 16, 20, () => errs(0));
    expect(await openOf(COL(), "iface_errors")).toHaveLength(0);
    // 0.05 % never opens
    await run(COL(), 100, 16, () => errs(60));
    expect(await openOf(COL(), "iface_errors")).toHaveLength(0);
  });
});

describe("component rules", () => {
  it("component_unhealthy: degraded = warn, fail = crit", async () => {
    const comp = (health: string) => report({ comps: [collectorComp({}, { health, detail: "vm slow" })] });
    await feed(COL(), at(0), comp("degraded"));
    expect((await openOf(COL(), "component_unhealthy"))[0]).toMatchObject({ severity: "warn", component_id: sc.colId });
    await feed(COL(), at(1), comp("fail"));
    expect((await openOf(COL(), "component_unhealthy"))[0]).toMatchObject({ severity: "crit" });
    await feed(COL(), at(2), comp("ok"));
    await feed(COL(), at(3), comp("ok"));
    expect(await openOf(COL(), "component_unhealthy")).toHaveLength(0);
  });

  it("crash_loop: >= 3 restarts in 15 minutes (counter resets handled)", async () => {
    const r = (n: number) => report({ comps: [collectorComp({}, { process: { restarts: n } })] });
    await feed(COL(), at(0), r(0));
    await feed(COL(), at(2), r(1));
    await feed(COL(), at(4), r(2));
    expect(await openOf(COL(), "crash_loop")).toHaveLength(0);
    await feed(COL(), at(6), r(3));
    expect((await openOf(COL(), "crash_loop"))[0]).toMatchObject({ severity: "crit", last_value: 3, component_id: sc.colId });
    // slow restarts (one per 10 minutes) never open
    await feed(COL(), at(40), r(3));
    await feed(COL(), at(41), r(3));
    await feed(COL(), at(42), r(3));
    expect(await openOf(COL(), "crash_loop")).toHaveLength(0);
    await feed(COL(), at(50), r(4));
    await feed(COL(), at(60), r(5));
    await feed(COL(), at(61), r(5));
    expect(await openOf(COL(), "crash_loop")).toHaveLength(0);
  });

  it("probe_ports: client ports without lease or with link down (value = count)", async () => {
    const ports = [{ id: "c01", role: "client", link: "up", leased: true }, { id: "c02", role: "client", link: "up", leased: false }, { id: "c03", role: "client", link: "down", leased: false }, { id: "t01", role: "target", link: "up", leased: false }];
    await feed(PROBE(), at(0), report({ comps: [probeComp({ ports })] }));
    expect((await openOf(PROBE(), "probe_ports"))[0]).toMatchObject({ severity: "warn", last_value: 2, component_id: sc.probeId });
    const good = report({ comps: [probeComp({ ports: [{ id: "c01", role: "client", link: "up", leased: true }] })] });
    await feed(PROBE(), at(1), good);
    await feed(PROBE(), at(2), good);
    expect(await openOf(PROBE(), "probe_ports")).toHaveLength(0);
  });

  it("probe_push_lag: warn > 120 s, crit > 600 s", async () => {
    await feed(PROBE(), at(0), report({ comps: [probeComp({ push_lag_s: 130 })] }));
    expect((await openOf(PROBE(), "probe_push_lag"))[0]).toMatchObject({ severity: "warn", last_value: 130 });
    await feed(PROBE(), at(1), report({ comps: [probeComp({ push_lag_s: 700 })] }));
    expect((await openOf(PROBE(), "probe_push_lag"))[0]).toMatchObject({ severity: "crit" });
    await feed(PROBE(), at(2), report({ comps: [probeComp({ push_lag_s: 3 })] }));
    await feed(PROBE(), at(3), report({ comps: [probeComp({ push_lag_s: 3 })] }));
    expect(await openOf(PROBE(), "probe_push_lag")).toHaveLength(0);
  });

  it("probe_spool: spool above 50 % of its limit", async () => {
    const mb = 1024 * 1024;
    await holdsThenResolves(PROBE(), "probe_spool", report({ comps: [probeComp({ spool_bytes: 300 * mb })] }), report({ comps: [probeComp({ spool_bytes: 10 * mb })] }), "warn");
  });

  it("probe_collector: collector unreachable for more than 2 minutes (crit)", async () => {
    const down = report({ comps: [probeComp({}, { collector_reachable: false })] });
    await run(PROBE(), 0, 2, () => down);
    expect(await openOf(PROBE(), "probe_collector")).toHaveLength(0);
    await run(PROBE(), 2, 2, () => down);
    expect((await openOf(PROBE(), "probe_collector"))[0]).toMatchObject({ severity: "crit", component_id: sc.probeId });
    const up = report({ comps: [probeComp()] });
    await run(PROBE(), 4, 2, () => up);
    expect(await openOf(PROBE(), "probe_collector")).toHaveLength(0);
  });

  it("storage_runway: days_to_full < 7 warn, < 2 crit", async () => {
    const dtf = (d: number | null) => report({ comps: [collectorComp({ days_to_full: d })] });
    await feed(COL(), at(0), dtf(30));
    await feed(COL(), at(1), dtf(null));
    expect(await openOf(COL(), "storage_runway")).toHaveLength(0);
    await feed(COL(), at(2), dtf(5));
    expect((await openOf(COL(), "storage_runway"))[0]).toMatchObject({ severity: "warn", last_value: 5 });
    await feed(COL(), at(3), dtf(1.5));
    expect((await openOf(COL(), "storage_runway"))[0]).toMatchObject({ severity: "crit" });
    await feed(COL(), at(4), dtf(40));
    await feed(COL(), at(5), dtf(40));
    expect(await openOf(COL(), "storage_runway")).toHaveLength(0);
  });

  it("collector_rejects: more than 1 % of ingest rejected over 5 minutes", async () => {
    const rej = (perMin: number) => report({ comps: [collectorComp({ ingest_records_per_s: 10, ingest_rejected_per_min: perMin })] });
    await run(COL(), 0, 3, () => rej(300));
    expect(await openOf(COL(), "collector_rejects")).toHaveLength(0); // under 80 % of a 5-minute window
    await run(COL(), 3, 3, () => rej(300));
    expect((await openOf(COL(), "collector_rejects"))[0]).toMatchObject({ severity: "warn", component_id: sc.colId });
    await run(COL(), 6, 12, () => rej(0));
    expect(await openOf(COL(), "collector_rejects")).toHaveLength(0);
    await run(COL(), 30, 8, () => rej(3)); // 3 / (3 + 600) = 0.5 %
    expect(await openOf(COL(), "collector_rejects")).toHaveLength(0);
  });

  it("collector_vm: vm_up = 0 is crit at once; a write backlog growing for 10 minutes is crit too", async () => {
    await feed(COL(), at(0), report({ comps: [collectorComp({ vm_up: 0 })] }));
    expect((await openOf(COL(), "collector_vm"))[0]).toMatchObject({ severity: "crit", last_value: 0 });
    await feed(COL(), at(1), report({ comps: [collectorComp({ vm_up: 1 })] }));
    await feed(COL(), at(2), report({ comps: [collectorComp({ vm_up: 1 })] }));
    expect(await openOf(COL(), "collector_vm")).toHaveLength(0);
    // backlog growing 10 minutes
    for (let i = 0; i < 10; i++) await feed(COL(), at(10 + i), report({ comps: [collectorComp({ vm_backlog_points: 1000 + i * 500 })] }));
    expect(await openOf(COL(), "collector_vm")).toHaveLength(0);
    await feed(COL(), at(20), report({ comps: [collectorComp({ vm_backlog_points: 9000 })] }));
    expect((await openOf(COL(), "collector_vm"))[0]).toMatchObject({ severity: "crit" });
    // a backlog that drains is not growing
    await run(COL(), 21, 3, () => report({ comps: [collectorComp({ vm_backlog_points: 0 })] }));
    expect(await openOf(COL(), "collector_vm")).toHaveLength(0);
  });

  it("collector_probes: probes_reporting < probes_total for more than 2 minutes", async () => {
    const low = report({ comps: [collectorComp({ probes_total: 4, probes_reporting: 3 })] });
    await run(COL(), 0, 2, () => low);
    expect(await openOf(COL(), "collector_probes")).toHaveLength(0);
    await run(COL(), 2, 2, () => low);
    expect((await openOf(COL(), "collector_probes"))[0]).toMatchObject({ severity: "warn", last_value: 1 });
    await run(COL(), 4, 2, () => report({ comps: [collectorComp({ probes_total: 4, probes_reporting: 4 })] }));
    expect(await openOf(COL(), "collector_probes")).toHaveLength(0);
  });

  it("dashboard_collectors: collectors_reachable < collectors_total", async () => {
    await holdsThenResolves(DASH(), "dashboard_collectors", report({ comps: [dashComp({ collectors_total: 2, collectors_reachable: 1 })] }), report({ comps: [dashComp()] }), "warn");
  });
});

/** leaves only `hostId` eligible for the staleness job (every other host looks freshly seen) */
async function onlyHost(hostId: string): Promise<void> {
  await env.DB.prepare("UPDATE hosts SET last_seen = '2099-01-01T00:00:00.000Z' WHERE host_id != ?1").bind(hostId).run();
}

describe("staleness (cron) and suppression", () => {
  it("host_stale after 3 x the status interval, host_offline after 10 minutes; both resolve after two clean reports", async () => {
    await feed(PROBE(), at(0), report({ comps: [probeComp()] }));
    await onlyHost(PROBE());
    useClock(at(3));
    let r = await evaluateStaleness(env, at(3));
    expect(r).toEqual({ stale: 0, offline: 0 }); // 3 x 60 s is not exceeded yet
    r = await evaluateStaleness(env, at(4));
    expect(r.stale).toBe(1);
    expect((await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(PROBE()).first<{ state: string }>())!.state).toBe("stale");
    expect((await openOf(PROBE(), "host_stale"))[0]).toMatchObject({ severity: "warn" });
    await evaluateStaleness(env, at(9)); // idempotent: still one stale issue
    expect(await openOf(PROBE(), "host_stale")).toHaveLength(1);
    await evaluateStaleness(env, at(10));
    expect((await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(PROBE()).first<{ state: string }>())!.state).toBe("offline");
    expect((await openOf(PROBE(), "host_offline"))[0]).toMatchObject({ severity: "crit" });
    expect(await openOf(PROBE(), "host_stale")).toHaveLength(0); // replaced by offline
    // the host comes back
    await feed(PROBE(), at(20), report({ comps: [probeComp()] }));
    expect((await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(PROBE()).first<{ state: string }>())!.state).toBe("enrolled");
    expect(await openOf(PROBE(), "host_offline")).toHaveLength(1); // hysteresis: one clean report is not enough
    await feed(PROBE(), at(21), report({ comps: [probeComp()] }));
    expect(await openOf(PROBE(), "host_offline")).toHaveLength(0);
  });

  it("the 5-minute cron job runs staleness; a custom status interval is honoured", async () => {
    await feed(PROBE(), at(0), report({ comps: [probeComp()], interval: 120 }));
    await env.DB.prepare("UPDATE hosts SET status_interval_s = 120 WHERE host_id = ?1").bind(PROBE()).run();
    await onlyHost(PROBE());
    await runEveryFiveMinutes(env, at(5)); // 5 min < 3 x 120 s = 6 min
    expect(await openOf(PROBE(), "host_stale")).toHaveLength(0);
    await runEveryFiveMinutes(env, at(7));
    expect(await openOf(PROBE(), "host_stale")).toHaveLength(1);
    await runEveryFiveMinutes(env, at(11)); // offline takes over after 10 minutes whatever the interval
    expect(await openOf(PROBE(), "host_offline")).toHaveLength(1);
    expect(await openOf(PROBE(), "host_stale")).toHaveLength(0);
  });

  it("host_offline suppresses the host's other issues: they stay recorded, are hidden, and nothing new opens", async () => {
    await feed(COL(), at(0), report({ disks: [{ mount: "/", pct: 97 }], comps: [collectorComp({ vm_up: 0 })] }));
    expect((await openOf(COL())).map((i) => i.kind).sort()).toEqual(["collector_vm", "disk_high"]);
    expect((await h.json<{ items: unknown[] }>("viewer", "GET", "/issues")).body.items).toHaveLength(2);
    await onlyHost(COL());
    await evaluateStaleness(env, at(11));
    const visible = (await h.json<{ items: Array<{ kind: string }> }>("viewer", "GET", "/issues")).body.items.filter((i) => i);
    expect(visible.map((i) => i.kind)).toEqual(["host_offline"]);
    expect((await openOf(COL())).map((i) => i.kind).sort()).toEqual(["collector_vm", "disk_high", "host_offline"]); // still recorded
    // a report arrives with a NEW problem while offline is still open (clean count 1): nothing new opens
    await feed(COL(), at(20), report({ memAvailPct: 1, time: { synced: false, offset_ms: null }, disks: [{ mount: "/", pct: 97 }], comps: [collectorComp({ vm_up: 0 })] }));
    expect(await openOf(COL(), "clock")).toHaveLength(0);
    // other issues are not resolved by the suppressed evaluation either
    expect((await openOf(COL(), "disk_high"))).toHaveLength(1);
    await feed(COL(), at(21), report({ disks: [{ mount: "/", pct: 97 }], comps: [collectorComp({ vm_up: 0 })] }));
    expect(await openOf(COL(), "host_offline")).toHaveLength(0);
    // evaluation resumes normally afterwards
    await feed(COL(), at(22), report({ time: { synced: false, offset_ms: null } }));
    expect(await openOf(COL(), "clock")).toHaveLength(1);
    const sum = await h.json<{ open_issues: { warn: number; crit: number } }>("viewer", "GET", "/fleet/summary");
    expect(sum.body.open_issues.warn + sum.body.open_issues.crit).toBeGreaterThan(0);
  });
});

describe("snooze", () => {
  it("hides the issue kind for that host from the UI list (1h expires, until-resolved ends with the issue), is audited, still recorded", async () => {
    await feed(COL(), at(0), report({ disks: [{ mount: "/", pct: 90 }] }));
    const issue = (await openOf(COL(), "disk_high"))[0]!;
    expect((await h.json<{ items: unknown[] }>("viewer", "GET", "/issues")).body.items).toHaveLength(1);
    const s = await h.json<{ issue_id: string; until: string }>("admin", "POST", `/issues/${issue.issue_id}/snooze`, { for: "1h" });
    expect(s.status).toBe(200);
    expect(Date.parse(s.body.until)).toBe(T0 + 3600_000);
    expect((await h.json<{ items: unknown[] }>("viewer", "GET", "/issues")).body.items).toHaveLength(0);
    expect((await h.json<{ items: Array<{ snoozed_until: string }> }>("viewer", "GET", "/issues?include_snoozed=true")).body.items[0]!.snoozed_until).toBe(s.body.until);
    expect((await h.json<{ open_issues: { warn: number } }>("viewer", "GET", "/fleet/summary")).body.open_issues.warn).toBe(0);
    expect(await openOf(COL(), "disk_high")).toHaveLength(1); // still recorded
    const audit = await env.DB.prepare("SELECT actor, action, details_json FROM audit WHERE action = 'issue.snooze'").all<{ actor: string; details_json: string }>();
    expect(audit.results).toHaveLength(1);
    expect(audit.results[0]!.actor).toBe("admin@example.com");
    expect(JSON.parse(audit.results[0]!.details_json)).toMatchObject({ issue_id: issue.issue_id, kind: "disk_high", for: "1h" });
    useClock(at(61)); // expired
    expect((await h.json<{ items: unknown[] }>("viewer", "GET", "/issues")).body.items).toHaveLength(1);
    // until resolved
    await h.json("admin", "POST", `/issues/${issue.issue_id}/snooze`, { for: "resolved" });
    expect((await h.json<{ items: unknown[] }>("viewer", "GET", "/issues")).body.items).toHaveLength(0);
    expect((await h.json("admin", "DELETE", `/issues/${issue.issue_id}/snooze`)).status).toBe(204);
    expect((await h.json<{ items: unknown[] }>("viewer", "GET", "/issues")).body.items).toHaveLength(1);
    expect((await h.json("admin", "DELETE", `/issues/${issue.issue_id}/snooze`)).status).toBe(404);
    await h.json("admin", "POST", `/issues/${issue.issue_id}/snooze`, { for: "resolved" });
    await feed(COL(), at(70), report());
    await feed(COL(), at(71), report());
    expect(await env.DB.prepare("SELECT 1 AS x FROM issue_snoozes").first()).toBeNull(); // the snooze ended with the issue
    const resolved = await h.json<{ items: Array<{ issue_id: string; resolved_at: string }> }>("viewer", "GET", "/issues?state=resolved");
    expect(resolved.body.items.map((i) => i.issue_id)).toEqual([issue.issue_id]);
    expect((await h.json("admin", "POST", `/issues/${issue.issue_id}/snooze`, { for: "1h" })).status).toBe(409);
    expect((await h.json("admin", "POST", `/issues/${issue.issue_id}/snooze`, { for: "1y" })).status).toBe(400);
    expect((await h.json("admin", "POST", `/issues/iss_01ARZ3NDEKTSV4RRFFQ69G5FAV/snooze`, { for: "1h" })).status).toBe(404);
  });

  it("list filters: severity, site, kind, state; bad values are 400", async () => {
    await feed(COL(), at(0), report({ disks: [{ mount: "/", pct: 97 }], time: { synced: false, offset_ms: null } }));
    const get = async (qs: string) => (await h.json<{ items: Array<{ kind: string; severity: string }> }>("viewer", "GET", `/issues${qs}`)).body.items;
    expect((await get("")).map((i) => i.kind).sort()).toEqual(["clock", "disk_high"]);
    expect((await get("?severity=crit")).map((i) => i.kind)).toEqual(["disk_high"]);
    expect((await get("?kind=clock")).map((i) => i.severity)).toEqual(["warn"]);
    expect(await get("?site=elsewhere")).toEqual([]);
    expect(await get("?state=resolved")).toEqual([]);
    for (const qs of ["?severity=bad", "?kind=bogus", "?state=maybe", "?limit=0"]) expect((await h.json("viewer", "GET", `/issues${qs}`)).status, qs).toBe(400);
    const page = await h.json<{ items: unknown[]; next_cursor: string | null }>("viewer", "GET", "/issues?limit=1");
    expect(page.body.items).toHaveLength(1);
    expect(page.body.next_cursor).toBeTruthy();
    const page2 = await h.json<{ items: unknown[]; next_cursor: string | null }>("viewer", "GET", `/issues?limit=1&cursor=${page.body.next_cursor}`);
    expect(page2.body.items).toHaveLength(1);
    expect(page2.body.next_cursor).toBeNull();
  });
});

describe("platform webhook", () => {
  const URL_ = "https://hooks.slack.com/services/T0/B0/PLATFORMXXXX";
  const posted = () => h.calls.filter((c) => c.url === URL_);
  beforeEach(async () => {
    h.handlers.push((u) => (u === URL_ ? new Response("ok", { status: 200 }) : undefined));
    expect((await h.json("admin", "PUT", "/settings/platform-webhook", { format: "slack", url: URL_ })).status).toBe(200);
  });

  it("fires on crit open and on resolve; never on warn; escalation warn -> crit counts as a crit open", async () => {
    await feed(COL(), at(0), report({ disks: [{ mount: "/", pct: 90 }] })); // warn: silent
    expect(posted()).toHaveLength(0);
    await feed(COL(), at(1), report({ disks: [{ mount: "/", pct: 97 }] })); // escalates to crit
    expect(posted()).toHaveLength(1);
    const body = JSON.parse(posted()[0]!.init!.body as string) as { text: string };
    expect(body.text).toContain("[CRIT]");
    expect(body.text).toContain("disk_high");
    expect(body.text).not.toContain("PLATFORMXXXX");
    await feed(COL(), at(2), report({ disks: [{ mount: "/", pct: 98 }] })); // still crit: no repeat
    expect(posted()).toHaveLength(1);
    await feed(COL(), at(3), report());
    expect(posted()).toHaveLength(1); // one clean report: still open
    await feed(COL(), at(4), report());
    expect(posted()).toHaveLength(2);
    expect(JSON.parse(posted()[1]!.init!.body as string).text).toContain("[RESOLVED]");
    // a warn issue opening and resolving sends nothing at all
    await run(PROBE(), 10, 1, () => report({ comps: [probeComp({ push_lag_s: 200 })] }));
    await run(PROBE(), 11, 2, () => report({ comps: [probeComp()] }));
    expect(posted()).toHaveLength(2);
    expect((await issuesOf(PROBE(), "probe_push_lag"))[0]!.resolved_at).not.toBeNull();
  });

  it("snoozed issues never reach the webhook (opening or resolving); an issue opened before the webhook existed is not announced on resolve", async () => {
    await feed(COL(), at(0), report({ disks: [{ mount: "/", pct: 90 }] }));
    const w = (await openOf(COL(), "disk_high"))[0]!;
    await h.json("admin", "POST", `/issues/${w.issue_id}/snooze`, { for: "24h" });
    await feed(COL(), at(1), report({ disks: [{ mount: "/", pct: 99 }] })); // escalation while snoozed
    expect(posted()).toHaveLength(0);
    expect((await openOf(COL(), "disk_high"))[0]!.severity).toBe("crit"); // recorded
    await run(COL(), 2, 2, () => report());
    expect(posted()).toHaveLength(0);
  });

  it("offline fires (crit); suppressed issues of an offline host do not", async () => {
    await feed(COL(), at(0), report({ disks: [{ mount: "/", pct: 50 }] }));
    await onlyHost(COL());
    await evaluateStaleness(env, at(11));
    expect(posted()).toHaveLength(1);
    expect(JSON.parse(posted()[0]!.init!.body as string).text).toContain("host_offline");
  });

  it("a failing webhook never breaks status ingestion and the URL stays out of logs/audit", async () => {
    h.handlers.length = 0;
    h.handlers.push(() => new Response("nope", { status: 500 }));
    await feed(COL(), at(0), report({ disks: [{ mount: "/", pct: 99 }] }));
    expect(await openOf(COL(), "disk_high")).toHaveLength(1);
    expect((await openOf(COL(), "disk_high"))[0]!.notified).toBe(0);
    expect(JSON.stringify((await env.DB.prepare("SELECT * FROM audit").all()).results)).not.toContain("hooks.slack");
    const t = await h.json<{ ok: boolean; http_status: number; error: string }>("admin", "POST", "/settings/platform-webhook/test", {});
    expect(t.body).toMatchObject({ ok: false, http_status: 500 });
    expect(JSON.stringify(t.body)).not.toContain("hooks.slack");
  });

  it("write-only: GET shows {set,updated_at}; test sends; fleet thresholds editable and validated", async () => {
    const g = await h.json<{ format: string; url: { set: boolean; updated_at: string } }>("viewer", "GET", "/settings/platform-webhook");
    expect(g.body).toMatchObject({ format: "slack", url: { set: true } });
    expect(JSON.stringify(g.body)).not.toContain("hooks");
    h.handlers.length = 0;
    h.handlers.push(() => new Response("ok"));
    expect((await h.json<{ ok: boolean }>("admin", "POST", "/settings/platform-webhook/test", {})).body.ok).toBe(true);
    // thresholds
    const def = await h.json<{ disk_high: { warn_pct: number; crit_pct: number }; cpu_high: { pct: number } }>("viewer", "GET", "/settings/fleet-thresholds");
    expect(def.body.disk_high).toEqual({ warn_pct: 85, crit_pct: 95 });
    expect((await h.json("admin", "PUT", "/settings/fleet-thresholds", { disk_high: { warn_pct: 70 } })).status).toBe(200);
    expect((await h.json<{ disk_high: unknown }>("viewer", "GET", "/settings/fleet-thresholds")).body.disk_high).toEqual({ warn_pct: 70, crit_pct: 95 });
    await feed(COL(), at(0), report({ disks: [{ mount: "/", pct: 75 }] })); // below the default 85 but above the edited 70
    expect((await openOf(COL(), "disk_high"))[0]).toMatchObject({ severity: "warn" });
    expect((await h.json("admin", "PUT", "/settings/fleet-thresholds", { disk_high: { warn_pct: 99, crit_pct: 90 } })).status).toBe(400);
    expect((await h.json("admin", "PUT", "/settings/fleet-thresholds", { disk_high: { bogus: 1 } })).status).toBe(400);
    expect((await h.json("admin", "PUT", "/settings/fleet-thresholds", { nope: {} })).status).toBe(400);
    expect((await h.json("admin", "PUT", "/settings/fleet-thresholds", { cpu_high: { pct: 150 } })).status).toBe(400);
    const au = await env.DB.prepare("SELECT COUNT(*) AS n FROM audit WHERE action = 'settings.fleet_thresholds'").first<{ n: number }>();
    expect(au!.n).toBe(1);
    void MIN;
  });
});
