// 05-manager.md section 15 item 9: roll-ups. A synthetic status sequence produces the expected 5-minute and
// 1-hour buckets; null rates and counter resets are skipped (never zero); compaction and pruning keep the
// stated retention; the fleet API serves series with gaps absent, ETag and a 15-second private cache.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { StatusSchema } from "../../src/agent/status-schema";
import { compactHours, pruneRollups, rollupStatements } from "../../src/fleet/rollup";
import { runHourly } from "../../src/cron";
import { setClock } from "../../src/util/time";
import { type Harness, harness } from "../admin-harness";
import { MIN, T0, at, collectorComp, feed, report, useClock } from "../fleet-helpers";
import { env, fullScenario, resetDb, seedSiteWithRelease, postStatus, statusReport } from "../helpers";

let h: Harness;
beforeEach(async () => {
  await resetDb();
  useClock(T0);
  h = await harness();
});
afterEach(() => {
  h.restore();
  setClock(null);
});

const net = (rx: number | null, tx: number | null, extra: Record<string, unknown> = {}) => [
  { iface: "eno1", role: "mgmt", link: "up", speed_mbps: 1000, rx_pps: rx, tx_pps: tx, rx_bps: rx === null ? null : rx * 1000, tx_bps: tx === null ? null : tx * 1000, rx_errors: rx === null ? null : 0, tx_errors: rx === null ? null : 0, rx_drops: rx === null ? null : 0, tx_drops: rx === null ? null : 0, ...extra },
];

async function hostRow(hostId: string, table = "fleet_host_5m", bucket?: number) {
  const q = bucket === undefined ? `SELECT * FROM ${table} WHERE host_id = ?1 ORDER BY bucket` : `SELECT * FROM ${table} WHERE host_id = ?1 AND bucket = ${bucket}`;
  return ((await env.DB.prepare(q).bind(hostId).all<Record<string, number | null>>()).results ?? []);
}
const epoch = (ms: number): number => Math.floor(ms / 1000);

describe("5-minute buckets", () => {
  it("accumulate sums, maxima and per-metric sample counts; null cpu / null rates are skipped, never zero", async () => {
    const sc = await seedAndEnrol();
    // bucket 0: three reports; the first has NO rates (first report after a start) and a null cpu
    await feed(sc, at(0), report({ cpu: null, net: net(null, null), uptime: 5 }));
    await feed(sc, at(1), report({ cpu: 30, net: net(1000, 500) }));
    await feed(sc, at(2), report({ cpu: 50, net: net(3000, 1500, { rx_errors: 2, tx_drops: 1 }) }));
    // bucket 1 (5 minutes later): a counter reset gives null rates again
    await feed(sc, at(5), report({ cpu: 10, net: net(null, null) }));
    const rows = await hostRow(sc);
    expect(rows).toHaveLength(2);
    const b0 = rows[0]!;
    expect(b0.bucket).toBe(epoch(T0));
    expect(b0).toMatchObject({ samples: 3, cpu_n: 2, cpu_sum: 80, cpu_max: 50, net_n: 2, rx_pps_sum: 4000, tx_pps_sum: 2000, rx_bps_sum: 4_000_000, tx_bps_sum: 2_000_000, errors_sum: 2, drops_sum: 1 });
    expect(b0.pkts_sum).toBe((1500 + 4500) * 60);
    expect(b0.mem_n).toBe(3);
    const b1 = rows[1]!;
    expect(b1).toMatchObject({ bucket: epoch(T0) + 300, samples: 1, cpu_n: 1, cpu_sum: 10, net_n: 0, rx_pps_sum: 0 });
    // the API: avg = sum / n over the samples that exist, so the skipped ones do not drag it down
    const m = await h.json<{ series: Record<string, Array<{ t: number; avg: number | null; max: number | null }>>; step_s: number; range: string }>("viewer", "GET", `/fleet/hosts/${sc}/metrics?range=1h&keys=cpu_pct,net_rx_pps,net_errors`);
    expect(m.body.step_s).toBe(300);
    expect(m.body.series.cpu_pct).toEqual([{ t: epoch(T0), avg: 40, max: 50 }, { t: epoch(T0) + 300, avg: 10, max: 10 }]);
    expect(m.body.series.net_rx_pps).toEqual([{ t: epoch(T0), avg: 2000, max: null }]); // bucket 1 has no rate samples: absent, not zero
    expect(m.body.series.net_errors).toEqual([{ t: epoch(T0), avg: 1, max: null }]);
  });

  it("one report writes at most one statement per roll-up table, whatever the number of interfaces and components", async () => {
    const sc = await seedAndEnrol();
    const many = Array.from({ length: 40 }, (_, i) => ({ iface: `veth${i}`, role: "none", link: "up", rx_pps: 1, tx_pps: 1, rx_bps: 8, tx_bps: 8, rx_errors: 0, tx_errors: 0, rx_drops: 0, tx_drops: 0 }));
    const rep = StatusSchema.parse(report({ net: [...net(10, 10), ...many], comps: [collectorComp()] }));
    const stmts = rollupStatements(env, sc, T0, rep, [{ component_id: "cmp_X", type: "collector", slug: "col-hallb" }]);
    expect(stmts).toHaveLength(3); // host, interfaces, components
  });

  it("per-interface rows (host namespace) and component metric rows accumulate in the same buckets", async () => {
    const sc = await seedAndEnrol();
    const col = (await env.DB.prepare("SELECT component_id FROM components WHERE slug = 'col-hallb'").first<{ component_id: string }>())!.component_id;
    for (let i = 0; i < 3; i++) await feed(sc, at(i), report({ net: [...net(100, 100), { iface: "enp1", role: "none", link: "up", rx_pps: 7, tx_pps: 3, rx_bps: 56, tx_bps: 24 }], comps: [collectorComp({ ingest_records_per_s: 100 + i * 100 })] }));
    const ifs = (await env.DB.prepare("SELECT * FROM fleet_iface_5m WHERE host_id = ?1 ORDER BY iface").bind(sc).all<Record<string, number>>()).results!;
    expect(ifs.map((r) => [r.iface, r.samples, r.rx_pps_sum])).toEqual([["eno1", 3, 300], ["enp1", 3, 21]]);
    const cm = await env.DB.prepare("SELECT n, sum, max FROM fleet_component_metric_5m WHERE component_id = ?1 AND key = 'ingest_records_per_s'").bind(col).first<{ n: number; sum: number; max: number }>();
    expect(cm).toEqual({ n: 3, sum: 600, max: 300 });
    const api = await h.json<{ series: Record<string, Array<{ avg: number; max: number }>> }>("viewer", "GET", `/fleet/components/${col}/metrics?range=1h&keys=ingest_records_per_s,probes_reporting`);
    expect(api.body.series.ingest_records_per_s).toEqual([{ t: epoch(T0), avg: 200, max: 300 }]);
    expect(api.body.series.probes_reporting?.[0]).toEqual({ t: epoch(T0), avg: 2, max: 2 });
    expect((await h.json("viewer", "GET", `/fleet/components/${col}/metrics?range=1h&keys=bogus`)).status).toBe(400);
    expect((await h.json("viewer", "GET", `/fleet/hosts/${sc}/metrics?range=2h`)).status).toBe(400);
    expect((await h.json("viewer", "GET", `/fleet/hosts/h_01ARZ3NDEKTSV4RRFFQ69G5FAV/metrics?range=1h`)).status).toBe(404);
  });

  it("the status route itself upserts the buckets (end to end through POST /status)", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    const sc = await fullScenario();
    for (const t of ["fleet_host_5m", "fleet_iface_5m", "fleet_component_metric_5m"]) await env.DB.prepare(`DELETE FROM ${t}`).run(); // the scenario's own report
    useClock(T0 + 3 * MIN);
    const r = await postStatus(sc.col.secret, statusReport());
    expect(r.status).toBe(204);
    const rows = await hostRow(sc.col.host_id);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ bucket: epoch(T0), samples: 1, cpu_n: 1, cpu_sum: 23.4, net_n: 1, rx_pps_sum: 120.5 });
    const latest = await env.DB.prepare("SELECT latest_json FROM hosts WHERE host_id = ?1").bind(sc.col.host_id).first<{ latest_json: string }>();
    expect(JSON.parse(latest!.latest_json)).toMatchObject({ cpu_pct: 23.4, mem_pct: 25.6, disk_pct_max: 3, net: { rx_pps: 120.5 } });
  });
});

describe("hourly compaction and pruning", () => {
  it("compacts completed hours exactly (sum of the 5-minute rows), is idempotent, and 7d/30d read the hourly data", async () => {
    const sc = await seedAndEnrol();
    // 12 buckets of the first hour, 2 reports each: cpu = bucket index * 10 and +10
    for (let b = 0; b < 12; b++) {
      await feed(sc, at(b * 5), report({ cpu: b * 5 }));
      await feed(sc, at(b * 5 + 1), report({ cpu: b * 5 + 10 }));
    }
    await feed(sc, at(65), report({ cpu: 99 })); // the next, incomplete hour
    useClock(at(70));
    expect(await hostRow(sc, "fleet_host_1h")).toHaveLength(0);
    await runHourly(env, at(70));
    const hr = await hostRow(sc, "fleet_host_1h");
    expect(hr).toHaveLength(1); // only the completed hour
    const sum5 = (await env.DB.prepare("SELECT SUM(cpu_sum) AS s, SUM(cpu_n) AS n, MAX(cpu_max) AS m, SUM(samples) AS k FROM fleet_host_5m WHERE host_id = ?1 AND bucket < ?2").bind(sc, epoch(at(60))).first<{ s: number; n: number; m: number; k: number }>())!;
    expect(hr[0]).toMatchObject({ bucket: epoch(T0), cpu_sum: sum5.s, cpu_n: sum5.n, cpu_max: sum5.m, samples: sum5.k });
    expect(sum5.n).toBe(24);
    // idempotent: running again changes nothing
    await compactHours(env, at(70));
    await compactHours(env, at(70));
    expect(await hostRow(sc, "fleet_host_1h")).toEqual(hr);
    const api = await h.json<{ step_s: number; series: { cpu_pct: Array<{ t: number; avg: number; max: number }> } }>("viewer", "GET", `/fleet/hosts/${sc}/metrics?range=7d&keys=cpu_pct`);
    expect(api.body.step_s).toBe(3600);
    expect(api.body.series.cpu_pct).toEqual([{ t: epoch(T0), avg: sum5.s / 24, max: 65 }]);
  });

  it("prunes 5-minute data older than 48 h and 1-hour data older than 30 d, and nothing newer", async () => {
    const sc = await seedAndEnrol();
    const now = at(0);
    const s = (n: number) => epoch(now) - n;
    const ins = async (table: string, bucket: number) =>
      env.DB.prepare(`INSERT INTO ${table} (host_id, bucket, org_id, samples, created_at, updated_at) VALUES (?1, ?2, 'default', 1, 'x', 'x')`).bind(sc, bucket).run();
    for (const b of [s(49 * 3600), s(48 * 3600 + 600), s(47 * 3600), s(300)]) await ins("fleet_host_5m", b);
    for (const b of [s(31 * 86400), s(30 * 86400 + 3600), s(29 * 86400), s(7200)]) await ins("fleet_host_1h", b);
    const col = "cmp_01ARZ3NDEKTSV4RRFFQ69G5FAV";
    for (const [t, b] of [["fleet_component_metric_5m", s(49 * 3600)], ["fleet_component_metric_5m", s(60)], ["fleet_component_metric_1h", s(31 * 86400)], ["fleet_component_metric_1h", s(3600)]] as Array<[string, number]>) {
      await env.DB.prepare(`INSERT INTO ${t} (component_id, key, bucket, n, sum, max) VALUES (?1, 'k', ?2, 1, 1, 1)`).bind(col, b).run();
    }
    await pruneRollups(env, now);
    expect((await hostRow(sc, "fleet_host_5m")).map((r) => r.bucket)).toEqual([s(47 * 3600), s(300)]);
    expect((await hostRow(sc, "fleet_host_1h")).map((r) => r.bucket)).toEqual([s(29 * 86400), s(7200)]);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM fleet_component_metric_5m").first<{ n: number }>())!.n).toBe(1);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM fleet_component_metric_1h").first<{ n: number }>())!.n).toBe(1);
  });
});

describe("fleet metric endpoints: gaps, ETag, cache", () => {
  it("buckets without samples are absent (gaps), responses carry ETag + private max-age=15, 304 on If-None-Match", async () => {
    const sc = await seedAndEnrol();
    await feed(sc, at(0), report({ cpu: 10 }));
    await feed(sc, at(20), report({ cpu: 20 })); // buckets at +5, +10, +15 min have nothing
    useClock(at(21));
    const r = await h.api("viewer", "GET", `/fleet/hosts/${sc}/metrics?range=1h&keys=cpu_pct`);
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("private, max-age=15");
    const etag = r.headers.get("etag")!;
    expect(etag).toMatch(/^"[0-9a-f]{32}"$/);
    const body = (await r.json()) as { series: { cpu_pct: Array<{ t: number }> } };
    expect(body.series.cpu_pct.map((p) => p.t)).toEqual([epoch(T0), epoch(T0) + 1200]);
    const r2 = await h.api("viewer", "GET", `/fleet/hosts/${sc}/metrics?range=1h&keys=cpu_pct`, undefined, { "If-None-Match": etag });
    expect(r2.status).toBe(304);
    expect(r2.headers.get("etag")).toBe(etag);
    await feed(sc, at(21), report({ cpu: 77 }));
    const r3 = await h.api("viewer", "GET", `/fleet/hosts/${sc}/metrics?range=1h&keys=cpu_pct`, undefined, { "If-None-Match": etag });
    expect(r3.status).toBe(200); // data changed: new ETag
    expect(r3.headers.get("etag")).not.toBe(etag);
  });
});

async function seedAndEnrol(): Promise<string> {
  await seedSiteWithRelease("hall-b", "0.1.0");
  const sc = await fullScenario();
  // fullScenario created the hosts through the status route (which used the real clock): start clean
  for (const t of ["fleet_host_5m", "fleet_host_1h", "fleet_iface_5m", "fleet_component_metric_5m", "fleet_component_metric_1h", "issues", "issue_state"]) await env.DB.prepare(`DELETE FROM ${t}`).run();
  useClock(T0);
  return sc.col.host_id;
}
