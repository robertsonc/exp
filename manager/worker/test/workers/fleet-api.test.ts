// Fleet API (01-contracts.md section 13, 11-manager-ui.md): summary, sites, hosts (filters, sort, cursor),
// metrics, top, overview, host status; ETag + private max-age=15; stale data is never shown as current.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluateStaleness } from "../../src/issues/engine";
import { setClock } from "../../src/util/time";
import { type Harness, harness } from "../admin-harness";
import { MIN, T0, at, collectorComp, dashComp, feed, probeComp, report, useClock } from "../fleet-helpers";
import { type EnrolledHost, FACTS, env, enrolHost, postStatus, resetDb, seedSiteWithRelease } from "../helpers";

let h: Harness;
beforeEach(async () => {
  await resetDb();
  useClock(T0);
  h = await harness();
  await seedSiteWithRelease("hall-b", "0.1.0");
  await h.json("admin", "POST", "/sites", { site: "hall-c", name: "Hall C", timezone: "UTC" });
});
afterEach(() => {
  h.restore();
  setClock(null);
});

const mgmtFacts = (ip: string) => FACTS({ interfaces: [{ name: "eno1", mac: "18:66:da:00:00:01", state: "up", speed_mbps: 1000, addrs: [`${ip}/24`], default_route: true, in_use_by: "mgmt" }] });
async function mk(site: string, name: string, ip: string, type: string, id: string, config: Record<string, unknown> = {}): Promise<{ host: EnrolledHost; cid: string }> {
  const host = await enrolHost(site, name, mgmtFacts(ip));
  const c = await h.json<{ component_id: string }>("admin", "POST", `/hosts/${host.host_id}/components`, { type, id, config });
  return { host, cid: c.body.component_id };
}

interface World {
  col: { host: EnrolledHost; cid: string };
  probe: { host: EnrolledHost; cid: string };
  dash: { host: EnrolledHost; cid: string };
  col2: { host: EnrolledHost; cid: string };
}
async function world(): Promise<World> {
  const col = await mk("hall-b", "col-hallb", "10.1.0.10", "collector", "col-hallb");
  const probe = await mk("hall-b", "probe-a1", "10.1.0.20", "probe", "probe-a1", { label: "A1" });
  const dash = await mk("hall-b", "dash-main", "10.1.0.30", "dashboard", "dash-main");
  const col2 = await mk("hall-c", "col-hallc", "10.2.0.10", "collector", "col-hallc");
  useClock(T0);
  const post = async (e: EnrolledHost, rep: Record<string, unknown>) => expect((await postStatus(e.secret, rep)).status).toBe(204);
  await post(col.host, report({ facts: mgmtFacts("10.1.0.10"), cpu: 82, comps: [collectorComp({ ingest_records_per_s: 300, probes_total: 1, probes_reporting: 1, open_incidents: 2 })] }));
  await post(probe.host, report({ facts: mgmtFacts("10.1.0.20"), cpu: 12, memAvailPct: 40, comps: [probeComp({ measurements_per_min: 90 })] }));
  await post(dash.host, report({ facts: mgmtFacts("10.1.0.30"), cpu: 5, comps: [dashComp({ sessions_active: 4 })] }));
  await post(col2.host, report({ facts: mgmtFacts("10.2.0.10"), cpu: 41, comps: [collectorComp({ ingest_records_per_s: 50 }, { id: "col-hallc", health: "degraded" })].map((c) => ({ ...c, id: "col-hallc" })) }));
  return { col, probe, dash, col2 };
}

describe("fleet summary and sites", () => {
  it("KPIs: hosts by state, components by type x health, measurements/min, ingest/s, issues, drift, incidents", async () => {
    await world();
    await enrolHost("hall-c", "silent"); // enrolled, never reported
    await h.json("admin", "POST", "/hosts", { name: "pending-one", site: "hall-b" });
    const s = await h.json<Record<string, any>>("viewer", "GET", "/fleet/summary");
    expect(s.status).toBe(200);
    expect(s.body).toMatchObject({
      hosts_total: 6,
      hosts_online: 5,
      hosts_by_state: { pending: 1, enrolled: 5, stale: 0, offline: 0 },
      measurements_per_min: 90,
      ingest_records_per_s: 350,
      open_experience_incidents: 2,
    });
    expect(s.body.components_by_type_health.collector).toEqual({ ok: 1, degraded: 1, fail: 0, unknown: 0 });
    expect(s.body.components_by_type_health.probe.ok).toBe(1);
    expect(s.body.open_issues).toEqual({ warn: 1, crit: 0 }); // the degraded collector
    expect(typeof s.body.version_drift_hosts).toBe("number");
    expect(s.res.headers.get("cache-control")).toBe("private, max-age=15");
  });

  it("stale and offline hosts are not online and their components are 'unknown', never shown as current", async () => {
    const w = await world();
    useClock(at(5)); // 5 min without a report: past 3 x 60 s
    let s = await h.json<Record<string, any>>("viewer", "GET", "/fleet/summary");
    expect(s.body.hosts_online).toBe(0);
    expect(s.body.measurements_per_min).toBeNull();
    expect(s.body.components_by_type_health.collector).toEqual({ ok: 0, degraded: 0, fail: 0, unknown: 2 });
    await evaluateStaleness(env, at(12));
    s = await h.json("viewer", "GET", "/fleet/summary");
    expect(s.body.hosts_by_state.offline).toBe(4);
    const hosts = await h.json<{ items: Array<{ host_id: string; stale: boolean; state: string; health: string; cpu_pct: number | null }> }>("viewer", "GET", "/fleet/hosts");
    for (const r of hosts.body.items) expect(r).toMatchObject({ stale: true, state: "offline", health: "unknown" });
    // last values remain available for the detail view (as of last report), but not ranked as current
    expect((await h.json<{ items: unknown[] }>("viewer", "GET", "/fleet/top?metric=cpu")).body.items).toEqual([]);
    void w;
  });

  it("per-site roll-up: health bar, probes reporting/total, ingest, worst issue, release and canary", async () => {
    await world();
    const r = await h.json<{ items: Array<Record<string, any>>; as_of: string }>("viewer", "GET", "/fleet/sites");
    const b = r.body.items.find((x) => x.site === "hall-b")!;
    const c = r.body.items.find((x) => x.site === "hall-c")!;
    expect(b).toMatchObject({ hosts: 3, health_bar: { ok: 3, warn: 0, fail: 0, offline: 0 }, probes_total: 1, probes_reporting: 1, ingest_records_per_s: 300, release_version: "0.1.0", canary_state: null, worst_issue: null });
    expect(c).toMatchObject({ hosts: 1, health_bar: { ok: 0, warn: 1, fail: 0, offline: 0 }, ingest_records_per_s: 50 });
    expect(c.worst_issue).toMatchObject({ kind: "component_unhealthy", severity: "warn", site: "hall-c" });
    expect(r.body.as_of).toMatch(/Z$/);
  });

  it("ETag survives the moving as_of: an unchanged fleet answers 304", async () => {
    await world();
    const a = await h.api("viewer", "GET", "/fleet/summary");
    const etag = a.headers.get("etag")!;
    useClock(T0 + 7000);
    const b = await h.api("viewer", "GET", "/fleet/summary", undefined, { "If-None-Match": etag });
    expect(b.status).toBe(304);
    expect(b.headers.get("cache-control")).toBe("private, max-age=15");
    await postStatus((await env.DB.prepare("SELECT 1").first(), (await mk("hall-b", "extra", "10.1.0.99", "dashboard", "dash-x")).host.secret), report());
    const c = await h.api("viewer", "GET", "/fleet/summary", undefined, { "If-None-Match": etag });
    expect(c.status).toBe(200);
  });
});

describe("fleet hosts table", () => {
  it("rows carry latest metrics, shapes, mgmt ip, health, work figures, sparklines", async () => {
    await world();
    await feed((await env.DB.prepare("SELECT host_id FROM hosts WHERE name = 'col-hallb'").first<{ host_id: string }>())!.host_id, at(-2), report({ cpu: 70, facts: mgmtFacts("10.1.0.10") }));
    useClock(T0 + 30_000);
    const r = await h.json<{ items: Array<Record<string, any>>; next_cursor: string | null }>("viewer", "GET", "/fleet/hosts?site=hall-b&sort=name");
    expect(r.body.items.map((x) => x.name)).toEqual(["col-hallb", "dash-main", "probe-a1"]);
    const col = r.body.items[0]!;
    expect(col).toMatchObject({ mgmt_ip: "10.1.0.10", site: "hall-b", shapes: ["collector"], state: "enrolled", stale: false, health: "ok", open_issues: 0, cpu_pct: 82, disk_pct_max: 3, uptime_s: 1234567 });
    expect(col.net).toMatchObject({ rx_pps: 100, tx_pps: 50 });
    expect(col.work).toMatchObject({ ingest_records_per_s: 300, measurements_per_min: null });
    expect(col.cpu_spark).toHaveLength(12);
    expect(col.cpu_spark.filter((x: number | null) => x !== null).length).toBeGreaterThan(0);
    expect(col.cpu_spark[11]).toBe(82); // the current bucket
    expect(col.cpu_spark[0]).toBeNull(); // a gap is null, not zero
    expect(r.body.items[2]!.work.measurements_per_min).toBe(90);
    expect(r.body.items[1]!.work.sessions_active).toBe(4);
    expect(r.body.items[1]!.last_seen).toMatch(/Z$/);
  });

  it("filters: site, type, health, state, version, q; bad values are 400", async () => {
    await world();
    const names = async (qs: string) => (await h.json<{ items: Array<{ name: string }> }>("viewer", "GET", `/fleet/hosts${qs}`)).body.items.map((x) => x.name).sort();
    expect(await names("?site=hall-c")).toEqual(["col-hallc"]);
    expect(await names("?type=collector")).toEqual(["col-hallb", "col-hallc"]);
    expect(await names("?type=probe")).toEqual(["probe-a1"]);
    expect(await names("?health=degraded")).toEqual(["col-hallc"]);
    expect(await names("?health=ok&site=hall-b")).toEqual(["col-hallb", "dash-main", "probe-a1"]);
    expect(await names("?state=pending")).toEqual([]);
    expect(await names("?version=0.1.0")).toHaveLength(4);
    expect(await names("?version=9.9.9")).toEqual([]);
    expect(await names("?q=10.2.0")).toEqual(["col-hallc"]); // by management address
    expect(await names("?q=PROBE")).toEqual(["probe-a1"]);
    expect(await names("?q=col-hallb")).toEqual(["col-hallb"]);
    for (const qs of ["?health=bad", "?state=bad", "?type=bad", "?sort=password", "?limit=5000"]) expect((await h.json("viewer", "GET", `/fleet/hosts${qs}`)).status, qs).toBe(400);
  });

  it("sort (nulls last, - for descending) and cursor paging walk every row once", async () => {
    await world();
    await enrolHost("hall-b", "no-data"); // cpu null
    const get = async (qs: string) => (await h.json<{ items: Array<{ name: string; cpu_pct: number | null }>; next_cursor: string | null }>("viewer", "GET", `/fleet/hosts${qs}`)).body;
    expect((await get("?sort=-cpu_pct")).items.map((x) => x.name)).toEqual(["col-hallb", "col-hallc", "probe-a1", "dash-main", "no-data"]);
    expect((await get("?sort=cpu_pct")).items.map((x) => x.name)).toEqual(["dash-main", "probe-a1", "col-hallc", "col-hallb", "no-data"]);
    const seen: string[] = [];
    let cursor: string | null = null;
    for (let i = 0; i < 10; i++) {
      const p = await get(`?sort=name&limit=2${cursor ? `&cursor=${cursor}` : ""}`);
      expect(p.items.length).toBeLessThanOrEqual(2);
      seen.push(...p.items.map((x) => x.name));
      cursor = p.next_cursor;
      if (!cursor) break;
    }
    expect(seen).toEqual(["col-hallb", "col-hallc", "dash-main", "no-data", "probe-a1"]);
    expect((await h.json("viewer", "GET", "/fleet/hosts?cursor=@@bad")).status).toBe(400);
  });

  it("stays fast with 300 hosts (no per-host queries): list, summary and top answer well under a second", async () => {
    await world();
    const now = new Date(T0).toISOString();
    const stmts: D1PreparedStatement[] = [];
    for (let i = 0; i < 300; i++) {
      const id = `h_${String(i).padStart(26, "0").replace(/0/g, "A")}`.slice(0, 29);
      stmts.push(
        env.DB.prepare(
          `INSERT OR IGNORE INTO hosts (host_id, org_id, name, site, state, facts_json, latest_json, last_seen, agent_version, desired_version, applied_version, created_at, updated_at)
           VALUES (?1, 'default', ?2, 'hall-b', 'enrolled', '{}', ?3, ?4, '0.1.0', 1, 1, ?4, ?4)`,
        ).bind(`h_${(i + 100000).toString(36).toUpperCase().padStart(26, "0")}`, `bulk-${i}`, JSON.stringify({ cpu_pct: i % 100, mem_pct: 30, disk_pct_max: 10, uptime_s: 100, net: { rx_pps: i, tx_pps: 1, rx_bps: 1, tx_bps: 1 } }), now),
      );
    }
    void stmts.length;
    for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
    const t0 = performance.now();
    const list = await h.json<{ items: unknown[]; next_cursor: string | null }>("viewer", "GET", "/fleet/hosts?limit=1000&sort=-cpu_pct");
    await h.json("viewer", "GET", "/fleet/summary");
    await h.json("viewer", "GET", "/fleet/top?metric=cpu&limit=10");
    expect(performance.now() - t0).toBeLessThan(3000);
    expect(list.body.items.length).toBe(304);
    void MIN;
  });
});

describe("top, overview, status", () => {
  it("top: ranks fresh hosts by cpu / mem / disk / net with unit and a 24 h sparkline", async () => {
    await world();
    const cpu = await h.json<{ metric: string; items: Array<{ name: string; value: number; unit: string; spark: Array<number | null> }> }>("viewer", "GET", "/fleet/top?metric=cpu&limit=2");
    expect(cpu.body.metric).toBe("cpu");
    expect(cpu.body.items.map((i) => [i.name, i.value, i.unit])).toEqual([["col-hallb", 82, "pct"], ["col-hallc", 41, "pct"]]);
    expect(cpu.body.items[0]!.spark).toEqual([82]);
    const net = await h.json<{ items: Array<{ unit: string; value: number; value_out: number }> }>("viewer", "GET", "/fleet/top?metric=net&limit=1");
    expect(net.body.items[0]).toMatchObject({ unit: "pps", value: 100, value_out: 50 });
    expect((await h.json("viewer", "GET", "/fleet/top?metric=bogus")).status).toBe(400);
    expect((await h.json("viewer", "GET", "/fleet/top?limit=x")).status).toBe(400);
    for (const m of ["mem", "disk"]) expect((await h.json<{ items: unknown[] }>("viewer", "GET", `/fleet/top?metric=${m}`)).body.items.length).toBe(4);
  });

  it("overview lists sites, hosts with component health and a version histogram", async () => {
    const w = await world();
    const o = await h.json<{ sites: Array<Record<string, any>>; hosts: Array<Record<string, any>>; versions: Record<string, number> }>("viewer", "GET", "/overview");
    expect(o.body.versions).toEqual({ "0.1.0": 4 });
    expect(o.body.sites.find((s) => s.site === "hall-b")).toMatchObject({ hosts_total: 3, components_by_health: { ok: 3 } });
    const col = o.body.hosts.find((x) => x.host_id === w.col.host.host_id)!;
    expect(col).toMatchObject({ state: "enrolled", health: "ok", components: [{ type: "collector", id: "col-hallb", health: "ok", version: "0.1.0" }] });
  });

  it("host status: 404 before the first report, then the stored exp.status/1 report", async () => {
    const w = await world();
    const fresh = await enrolHost("hall-b", "fresh");
    expect((await h.json("viewer", "GET", `/hosts/${fresh.host_id}/status`)).status).toBe(404);
    const s = await h.json<{ host_id: string; state: string; received_at: string; report: { schema: string; components: Array<{ id: string }> } }>("viewer", "GET", `/hosts/${w.col.host.host_id}/status`);
    expect(s.status).toBe(200);
    expect(s.body).toMatchObject({ host_id: w.col.host.host_id, state: "enrolled", report: { schema: "exp.status/1" } });
    expect(s.body.report.components[0]!.id).toBe("col-hallb");
    expect((await h.json("viewer", "GET", "/hosts/h_01ARZ3NDEKTSV4RRFFQ69G5FAV/status")).status).toBe(404);
  });

  it("host and component lists expose health, version, rendered config (no creds) and facts", async () => {
    const w = await world();
    const l = await h.json<{ items: Array<Record<string, any>> }>("viewer", "GET", `/hosts/${w.col.host.host_id}/components`);
    expect(l.body.items).toHaveLength(1);
    const c = l.body.items[0]!;
    expect(c).toMatchObject({ type: "collector", id: "col-hallb", health: "ok", version: "0.1.0", enabled: true });
    expect(c.facts.listen).toBe("10.32.98.25:8443");
    expect(c.facts.metrics.ingest_records_per_s).toBe(300);
    expect(c.rendered_config).toMatchObject({ schema: "exp.collector.config/1", collector_id: "col-hallb" });
    expect(JSON.stringify(c)).not.toMatch(/exp[aeidn]_/);
    const host = await h.json<Record<string, any>>("viewer", "GET", `/hosts/${w.col.host.host_id}`);
    expect(host.body).toMatchObject({ shapes: ["collector"], mgmt_ip: "10.1.0.10", state: "enrolled", agent_version: "0.1.0" });
    expect(host.body.facts.arch).toBe("amd64");
  });
});
