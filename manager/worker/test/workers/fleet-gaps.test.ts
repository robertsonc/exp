// M3 p1 (CR-wp5-fleet-api-gaps items 2, 3, 5, 6): per-probe rows of a collector, per-interface history,
// per-test history for probes, Issue.component_type. Everything is additive to the fleet API.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { compactHours } from "../../src/fleet/rollup";
import { sanitizeProbeRows } from "../../src/fleet/query";
import { setClock } from "../../src/util/time";
import { type Harness, harness } from "../admin-harness";
import { T0, at, collectorComp, feed, probeComp, report, useClock } from "../fleet-helpers";
import { type Scenario, env, fullScenario, resetDb, seedSiteWithRelease } from "../helpers";

let h: Harness;
let sc: Scenario;
beforeEach(async () => {
  await resetDb();
  useClock(T0);
  h = await harness();
  await seedSiteWithRelease("hall-b", "0.1.0");
  sc = await fullScenario();
  for (const t of ["fleet_host_5m", "fleet_host_1h", "fleet_iface_5m", "fleet_component_metric_5m", "fleet_component_metric_1h", "component_probes_latest", "issues", "issue_state"]) await env.DB.prepare(`DELETE FROM ${t}`).run();
  await env.DB.prepare("UPDATE hosts SET last_seen = ?1, state = 'enrolled'").bind(new Date(T0).toISOString()).run();
  useClock(T0);
});
afterEach(() => {
  h.restore();
  setClock(null);
});

const epoch = (ms: number): number => Math.floor(ms / 1000);
const row = (id: string, o: Record<string, unknown> = {}) => ({ probe_id: id, last_seen: "2026-01-01T00:00:00.000Z", records_per_min: 12, clock_offset_ms: 0.4, ...o });
type Probes = { component_id: string; reported_at: string | null; items: Array<Record<string, unknown>> };

describe("item 2: per-probe rows of a collector", () => {
  it("the latest rows are stored per collector and served; each report replaces them", async () => {
    await feed(sc.col.host_id, at(0), report({ comps: [collectorComp({ probes: [row("probe-a1"), row("probe-b2", { clock_offset_ms: null, records_per_min: 0 })] })] }));
    const r = await h.json<Probes>("viewer", "GET", `/fleet/components/${sc.colId}/probes`);
    expect(r.status).toBe(200);
    expect(r.body.component_id).toBe(sc.colId);
    expect(r.body.reported_at).toBe(new Date(T0).toISOString());
    expect(r.body.items).toEqual([row("probe-a1"), row("probe-b2", { clock_offset_ms: null, records_per_min: 0 })]);
    await feed(sc.col.host_id, at(1), report({ comps: [collectorComp({ probes: [row("probe-c3", { records_per_min: 7 })] })] }));
    const r2 = await h.json<Probes>("viewer", "GET", `/fleet/components/${sc.colId}/probes`);
    expect(r2.body.items.map((i) => i.probe_id)).toEqual(["probe-c3"]); // latest values only, no history
    expect(((await env.DB.prepare("SELECT COUNT(*) AS n FROM component_probes_latest").first<{ n: number }>())!).n).toBe(1);
  });

  it("is bounded (500 rows), drops malformed rows, and a report without probes[] clears the row", async () => {
    const many = Array.from({ length: 600 }, (_, i) => row(`p${String(i).padStart(4, "0")}`));
    const junk = [{ probe_id: "BAD ID", last_seen: "2026-01-01T00:00:00Z", records_per_min: 1, clock_offset_ms: 0 }, { probe_id: "ok-1", last_seen: "yesterday", records_per_min: 1, clock_offset_ms: 0 }, { probe_id: "ok-2", last_seen: "2026-01-01T00:00:00Z", records_per_min: -3, clock_offset_ms: 0 }, "x", null, row("good-1")];
    expect(sanitizeProbeRows(junk)).toEqual([row("good-1", { last_seen: "2026-01-01T00:00:00.000Z" })]);
    expect(sanitizeProbeRows("nope")).toBeNull();
    await feed(sc.col.host_id, at(0), report({ comps: [collectorComp({ probes: many })] }));
    expect((await h.json<Probes>("viewer", "GET", `/fleet/components/${sc.colId}/probes`)).body.items).toHaveLength(500);
    await feed(sc.col.host_id, at(1), report({ comps: [collectorComp({})] }));
    const r = await h.json<Probes>("viewer", "GET", `/fleet/components/${sc.colId}/probes`);
    expect(r.body).toMatchObject({ reported_at: null, items: [] });
  });

  it("404 for an unknown component, empty for a non-collector, gone with its component; ETag honoured", async () => {
    expect((await h.json("viewer", "GET", "/fleet/components/cmp_01ARZ3NDEKTSV4RRFFQ69G5FAV/probes")).status).toBe(404);
    expect((await h.json("viewer", "GET", "/fleet/components/nope/probes")).status).toBe(404);
    expect((await h.json<Probes>("viewer", "GET", `/fleet/components/${sc.probeId}/probes`)).body.items).toEqual([]);
    await feed(sc.col.host_id, at(0), report({ comps: [collectorComp({ probes: [row("probe-a1")] })] }));
    const a = await h.api("viewer", "GET", `/fleet/components/${sc.colId}/probes`);
    const etag = a.headers.get("etag")!;
    expect(a.headers.get("cache-control")).toBe("private, max-age=15");
    expect((await h.api("viewer", "GET", `/fleet/components/${sc.colId}/probes`, undefined, { "If-None-Match": etag })).status).toBe(304);
    await h.json("admin", "DELETE", `/components/${sc.colId}`);
    expect(((await env.DB.prepare("SELECT COUNT(*) AS n FROM component_probes_latest").first<{ n: number }>())!).n).toBe(0);
  });

  it("the status route stores the rows too (POST /status end to end)", async () => {
    const { postStatus } = await import("../helpers");
    const rep = report({ comps: [collectorComp({ probes: [row("probe-a1")] })] });
    expect((await postStatus(sc.col.secret, rep)).status).toBe(204);
    expect((await h.json<Probes>("viewer", "GET", `/fleet/components/${sc.colId}/probes`)).body.items).toHaveLength(1);
  });
});

describe("item 3: per-interface history", () => {
  const nets = (e: number, d: number) => [
    { iface: "eno1", role: "mgmt", link: "up", speed_mbps: 1000, rx_pps: 100, tx_pps: 50, rx_bps: 800000, tx_bps: 400000, rx_errors: 0, tx_errors: 0, rx_drops: 0, tx_drops: 0 },
    { iface: "enp1", role: "none", link: "up", speed_mbps: 1000, rx_pps: 10 + e, tx_pps: 30, rx_bps: 80, tx_bps: 240, rx_errors: e, tx_errors: 1, rx_drops: d, tx_drops: 0 },
  ];
  it("serves rx/tx pps and bps, errors and drops per interface (5-minute buckets, 48 h)", async () => {
    const col = sc.col.host_id;
    for (let i = 0; i < 3; i++) await feed(col, at(i), report({ net: nets(i, i * 2) }));
    await feed(col, at(5), report({ net: nets(9, 4) }));
    const r = await h.json<{ iface: string; range: string; step_s: number; series: Record<string, Array<{ t: number; avg: number; max: number | null }>> }>("viewer", "GET", `/fleet/hosts/${col}/interfaces/enp1/metrics?range=1h`);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ host_id: col, iface: "enp1", range: "1h", step_s: 300 });
    expect(Object.keys(r.body.series).sort()).toEqual(["drops", "errors", "rx_bps", "rx_pps", "tx_bps", "tx_pps"]);
    const b0 = epoch(T0);
    expect(r.body.series.rx_pps).toEqual([{ t: b0, avg: 11, max: null }, { t: b0 + 300, avg: 19, max: null }]);
    expect(r.body.series.errors).toEqual([{ t: b0, avg: (1 + 2 + 3) / 3, max: null }, { t: b0 + 300, avg: 10, max: null }]); // rx + tx errors per report
    expect(r.body.series.drops?.map((p) => p.avg)).toEqual([2, 4]);
    const sub = await h.json<{ series: Record<string, unknown> }>("viewer", "GET", `/fleet/hosts/${col}/interfaces/eno1/metrics?range=48h&keys=rx_bps,errors`);
    expect(Object.keys(sub.body.series).sort()).toEqual(["errors", "rx_bps"]);
    expect((await h.json<{ series: Record<string, unknown[]> }>("viewer", "GET", `/fleet/hosts/${col}/interfaces/zzz9/metrics`)).body.series.rx_pps).toEqual([]);
  });
  it("validates range, keys, host and interface name", async () => {
    const col = sc.col.host_id;
    for (const bad of ["range=7d", "range=2h", "keys=cpu_pct", "keys=bogus"]) expect((await h.json("viewer", "GET", `/fleet/hosts/${col}/interfaces/eno1/metrics?${bad}`)).status, bad).toBe(400);
    expect((await h.json("viewer", "GET", `/fleet/hosts/h_01ARZ3NDEKTSV4RRFFQ69G5FAV/interfaces/eno1/metrics`)).status).toBe(404);
    expect((await h.json("viewer", "GET", `/fleet/hosts/${col}/interfaces/${"x".repeat(40)}/metrics`)).status).toBe(404);
    expect((await h.json("viewer", "GET", `/fleet/hosts/${col}/interfaces/a%2Fb/metrics`)).status).toBe(404);
  });
  it("host-level errors and drops series exist (management interface)", async () => {
    const col = sc.col.host_id;
    await feed(col, at(0), report({ net: nets(0, 0).map((n) => ({ ...n, rx_errors: 3, rx_drops: 2 })).slice(0, 1) }));
    const r = await h.json<{ series: Record<string, Array<{ avg: number }>> }>("viewer", "GET", `/fleet/hosts/${col}/metrics?range=1h&keys=net_errors,net_drops`);
    expect([r.body.series.net_errors?.[0]?.avg, r.body.series.net_drops?.[0]?.avg]).toEqual([3, 2]);
  });
});

describe("item 5: per-test history for probes", () => {
  it("by_test_per_min is rolled up per catalog test (bounded set), 5 m and 1 h, and charted on request", async () => {
    const pr = sc.probe.host_id;
    for (let i = 0; i < 3; i++) await feed(pr, at(i), report({ comps: [probeComp({ by_test_per_min: { ping: 6 + i, dns_hb: 6, app: 2, bogus_test: 99, "x'; DROP": 5, wifi_hb: -1 } })] }));
    const keys = (await env.DB.prepare("SELECT DISTINCT key FROM fleet_component_metric_5m WHERE component_id = ?1 AND key LIKE 'by_test_%' ORDER BY key").bind(sc.probeId).all<{ key: string }>()).results!.map((r) => r.key);
    expect(keys).toEqual(["by_test_app", "by_test_dns_hb", "by_test_ping"]); // catalog only, never the probe's own names, no negatives
    const r = await h.json<{ series: Record<string, Array<{ t: number; avg: number; max: number }>> }>("viewer", "GET", `/fleet/components/${sc.probeId}/metrics?range=1h&keys=by_test_ping,by_test_app,by_test_trace`);
    expect(r.status).toBe(200);
    expect(r.body.series.by_test_ping).toEqual([{ t: epoch(T0), avg: 7, max: 8 }]);
    expect(r.body.series.by_test_app?.[0]?.avg).toBe(2);
    expect(r.body.series.by_test_trace).toEqual([]); // known key without samples: a gap
    // not part of the default key list; keys outside the catalog stay rejected
    const d = await h.json<{ series: Record<string, unknown> }>("viewer", "GET", `/fleet/components/${sc.probeId}/metrics?range=1h`);
    expect(Object.keys(d.body.series).some((k) => k.startsWith("by_test_"))).toBe(false);
    expect((await h.json("viewer", "GET", `/fleet/components/${sc.probeId}/metrics?range=1h&keys=by_test_bogus_test`)).status).toBe(400);
    // by_test_ keys are probe keys only
    expect((await h.json("viewer", "GET", `/fleet/components/${sc.colId}/metrics?range=1h&keys=by_test_ping`)).status).toBe(400);
    // hourly compaction carries them to the 1 h table
    await compactHours(env, T0 + 2 * 3600_000, 6);
    const hr = await h.json<{ series: Record<string, Array<{ avg: number }>> }>("viewer", "GET", `/fleet/components/${sc.probeId}/metrics?range=7d&keys=by_test_ping`);
    expect(hr.body.series.by_test_ping?.[0]?.avg).toBe(7);
  });
});

describe("item 6: Issue.component_type", () => {
  it("component issues carry the component type, host issues null; stored, so it survives the component", async () => {
    await feed(sc.col.host_id, at(0), report({ comps: [collectorComp({}, { health: "degraded", detail: "vm slow" })] }));
    await feed(sc.probe.host_id, at(0), report({ applied: 0, comps: [probeComp({}, {}, { health: "fail" })] }));
    const list = await h.json<{ items: Array<Record<string, unknown>> }>("viewer", "GET", "/issues");
    const byKind = (k: string, c?: string) => list.body.items.find((i) => i.kind === k && (c === undefined || i.component_id === c));
    expect(byKind("component_unhealthy", sc.colId)).toMatchObject({ component_id: sc.colId, component_type: "collector" });
    expect(byKind("component_unhealthy", sc.probeId)).toMatchObject({ component_type: "probe" });
    const hostLevel = list.body.items.find((i) => i.component_id === null);
    if (hostLevel) expect(hostLevel.component_type).toBeNull();
    for (const i of list.body.items) expect("component_type" in i).toBe(true);
    await env.DB.prepare("DELETE FROM components WHERE component_id = ?1").bind(sc.colId).run();
    expect((await h.json<{ items: Array<Record<string, unknown>> }>("viewer", "GET", "/issues?include_snoozed=true")).body.items.find((i) => i.component_id === sc.colId)).toMatchObject({ component_type: "collector" });
  });
  it("the migration backfills existing issues from their component", async () => {
    await feed(sc.col.host_id, at(0), report({ comps: [collectorComp({}, { health: "degraded" })] }));
    await env.DB.prepare("UPDATE issues SET component_type = NULL").run();
    await env.DB.prepare("UPDATE issues SET component_type = (SELECT c.type FROM components c WHERE c.component_id = issues.component_id) WHERE component_id IS NOT NULL").run();
    expect((await env.DB.prepare("SELECT component_type FROM issues WHERE component_id = ?1").bind(sc.colId).first<{ component_type: string }>())!.component_type).toBe("collector");
  });
});
