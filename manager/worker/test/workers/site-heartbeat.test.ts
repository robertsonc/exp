// POST /sites/{site}/probe-heartbeat (CR-heartbeat-cadence): one batch sets heartbeat.interval_s on every probe of a
// site, keeps the rest of each probe's config, leaves other sites and other component types alone, audits once.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Harness, harness } from "../admin-harness";
import { enrolHost, env, resetDb, seedSiteWithRelease } from "../helpers";

let h: Harness;
beforeEach(async () => {
  await resetDb();
  h = await harness();
});
afterEach(() => h.restore());

type Cfg = { heartbeat?: { interval_s?: number; gateway?: boolean }; label?: string; retention?: unknown };
const cfgOf = async (cid: string): Promise<Cfg> =>
  JSON.parse((await env.DB.prepare("SELECT config_json FROM components WHERE component_id = ?1").bind(cid).first<{ config_json: string }>())!.config_json) as Cfg;

async function addComponent(site: string, host: string, type: string, id: string, config: Record<string, unknown>): Promise<string> {
  const hh = await enrolHost(site, host);
  const c = await h.json<{ component_id: string }>("admin", "POST", `/hosts/${hh.host_id}/components`, { type, id, config });
  expect(c.status).toBe(201);
  return c.body.component_id;
}

describe("site probe heartbeat", () => {
  it("sets every probe of the site, keeps their other settings, and touches nothing else", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    expect((await h.json("admin", "POST", "/sites", { site: "hall-c", name: "Hall C", timezone: "UTC" })).status).toBe(201);
    const a = await addComponent("hall-b", "pa", "probe", "probe-a", { label: "A", heartbeat: { interval_s: 10, gateway: false } });
    const b = await addComponent("hall-b", "pb", "probe", "probe-b", { label: "B" });
    const other = await addComponent("hall-c", "pc", "probe", "probe-c", { label: "C", heartbeat: { interval_s: 10 } });
    const col = await addComponent("hall-b", "col", "collector", "col-1", { retention: { metrics_days: 30 } });

    const r = await h.json<{ site: string; interval_s: number; updated: number }>("admin", "POST", "/sites/hall-b/probe-heartbeat", { interval_s: 5 });
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ site: "hall-b", interval_s: 5, updated: 2 });
    expect(await cfgOf(a)).toMatchObject({ label: "A", heartbeat: { interval_s: 5, gateway: false } });
    expect((await cfgOf(b)).heartbeat?.interval_s).toBe(5);
    expect((await cfgOf(other)).heartbeat?.interval_s).toBe(10);
    expect(await cfgOf(col)).toEqual({ retention: { metrics_days: 30 } });

    const audit = await env.DB.prepare("SELECT action FROM audit WHERE action = 'site.probe_heartbeat'").all<{ action: string }>();
    expect(audit.results).toHaveLength(1);

    const again = await h.json<{ updated: number }>("admin", "POST", "/sites/hall-b/probe-heartbeat", { interval_s: 5 });
    expect(again.body.updated).toBe(0);
  });

  it("refuses an interval outside 5..60, a non-integer, an unknown site, and a non-admin", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    for (const bad of [4, 61, 7.5]) {
      expect((await h.json("admin", "POST", "/sites/hall-b/probe-heartbeat", { interval_s: bad })).status).toBe(400);
    }
    expect((await h.json("admin", "POST", "/sites/hall-b/probe-heartbeat", { interval_s: 10, extra: 1 })).status).toBe(400);
    expect((await h.json("admin", "POST", "/sites/nope/probe-heartbeat", { interval_s: 10 })).status).toBe(404);
    expect((await h.json("operator", "POST", "/sites/hall-b/probe-heartbeat", { interval_s: 10 })).status).toBe(403);
  });
});
