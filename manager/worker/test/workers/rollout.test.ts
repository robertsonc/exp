// Rollout (05-manager.md section 9): the canary compiles first; it is promoted automatically after its
// components report healthy for 10 minutes; a failed canary halts the rollout and is surfaced; rollback = set
// the previous version.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runEveryFiveMinutes } from "../../src/cron";
import { setClock } from "../../src/util/time";
import { type Harness, harness } from "../admin-harness";
import { MIN, T0, at, collectorComp, dashComp, probeComp, report, useClock } from "../fleet-helpers";
import { type Scenario, env, fullScenario, getDesired, postStatus, resetDb, seedRelease, seedSiteWithRelease } from "../helpers";

let h: Harness;
let sc: Scenario;
beforeEach(async () => {
  await resetDb();
  useClock(T0);
  h = await harness();
  await seedSiteWithRelease("hall-b", "0.1.0");
  sc = await fullScenario();
  await seedRelease("0.2.0");
  await env.DB.prepare("DELETE FROM audit").run();
});
afterEach(() => {
  h.restore();
  setClock(null);
});

const agentVersion = async (secret: string): Promise<string> => ((await (await getDesired(secret)).json()) as { agent: { version: string } }).agent.version;
const desiredVersion = async (secret: string): Promise<number> => ((await (await getDesired(secret)).json()) as { version: number }).version;
const site = async () => (await h.json<Record<string, unknown>>("viewer", "GET", "/sites/hall-b")).body;
const audit = async (action: string) => (await env.DB.prepare("SELECT actor, details_json FROM audit WHERE action = ?1").bind(action).all<{ actor: string; details_json: string }>()).results ?? [];

/** the canary (probe) host reports having applied its current document, with the given component health */
async function canaryReports(min: number, health = "ok", extra: Record<string, unknown> = {}): Promise<void> {
  useClock(at(min));
  const v = await desiredVersion(sc.probe.secret);
  const r = await postStatus(sc.probe.secret, report({ applied: v, comps: [probeComp({}, {}, { health })], ...extra }));
  expect(r.status).toBe(204);
}
const startCanary = async () => (await h.json("admin", "PATCH", "/sites/hall-b/release", { version: "0.2.0", canary_host_id: sc.probe.host_id })).body as Record<string, unknown>;

describe("canary", () => {
  it("the canary compiles first, everyone else stays; promoted after 10 healthy minutes; then everyone moves", async () => {
    const s = await startCanary();
    expect(s).toMatchObject({ release_version: "0.1.0", target_version: "0.2.0", canary_host_id: sc.probe.host_id, canary_state: "pending" });
    expect(await agentVersion(sc.probe.secret)).toBe("0.2.0");
    expect(await agentVersion(sc.col.secret)).toBe("0.1.0");
    await canaryReports(1);
    await runEveryFiveMinutes(env, at(1));
    expect((await site()).canary_state).toBe("healthy_waiting");
    for (const m of [3, 6, 10]) {
      await canaryReports(m);
      await runEveryFiveMinutes(env, at(m));
      expect(await agentVersion(sc.col.secret), `minute ${m}`).toBe("0.1.0");
    }
    await canaryReports(11);
    await runEveryFiveMinutes(env, at(11)); // exactly 10 minutes after the first healthy observation
    expect(await site()).toMatchObject({ release_version: "0.2.0", target_version: null, canary_state: "promoted" });
    for (const secret of [sc.col.secret, sc.dash.secret, sc.probe.secret]) expect(await agentVersion(secret)).toBe("0.2.0");
    const pr = await audit("site.promote");
    expect(pr).toHaveLength(1);
    expect(pr[0]!.actor).toBe("system");
    expect(JSON.parse(pr[0]!.details_json)).toMatchObject({ version: "0.2.0", auto: true });
    await runEveryFiveMinutes(env, at(16)); // nothing left to promote: no second audit event
    expect(await audit("site.promote")).toHaveLength(1);
  });

  it("an unhealthy moment resets the 10-minute hold; a canary that never applied is not promoted", async () => {
    await startCanary();
    await canaryReports(1);
    await runEveryFiveMinutes(env, at(1));
    await canaryReports(6, "degraded");
    await runEveryFiveMinutes(env, at(6));
    expect((await site()).canary_state).toBe("pending");
    await canaryReports(8);
    await runEveryFiveMinutes(env, at(8)); // hold restarts here
    await canaryReports(15);
    await runEveryFiveMinutes(env, at(15)); // only 7 minutes since
    expect((await site()).canary_state).toBe("healthy_waiting");
    await canaryReports(19);
    await runEveryFiveMinutes(env, at(19));
    expect((await site()).canary_state).toBe("promoted");
    // never applied: desired != applied
    await seedRelease("0.3.0");
    await h.json("admin", "PATCH", "/sites/hall-b/release", { version: "0.3.0", canary_host_id: sc.probe.host_id });
    useClock(at(30));
    await postStatus(sc.probe.secret, report({ applied: 0, comps: [probeComp()] }));
    await runEveryFiveMinutes(env, at(30));
    await runEveryFiveMinutes(env, at(50));
    expect((await site()).release_version).toBe("0.2.0");
  });

  it("a canary that rolls back halts the rollout (failed, audited, visible); rollback = set the previous version", async () => {
    await startCanary();
    await canaryReports(1);
    await canaryReports(3, "ok", { reconcile: { at: new Date(at(3)).toISOString(), result: "rolled_back", error: "health check failed" } });
    await runEveryFiveMinutes(env, at(3));
    expect(await site()).toMatchObject({ canary_state: "failed", release_version: "0.1.0", target_version: "0.2.0" });
    expect((await h.json<{ items: Array<{ site: string; canary_state: string }> }>("viewer", "GET", "/fleet/sites")).body.items[0]).toMatchObject({ site: "hall-b", canary_state: "failed" });
    const f = await audit("site.canary_failed");
    expect(f).toHaveLength(1);
    expect(JSON.parse(f[0]!.details_json).reason).toContain("rolled back");
    // later healthy reports never promote a failed canary
    await canaryReports(20);
    await runEveryFiveMinutes(env, at(20));
    await runEveryFiveMinutes(env, at(40));
    expect(await site()).toMatchObject({ canary_state: "failed", release_version: "0.1.0" });
    expect(await agentVersion(sc.col.secret)).toBe("0.1.0");
    // rollback
    const rb = await h.json("admin", "PATCH", "/sites/hall-b/release", { version: "0.1.0" });
    expect(rb.body).toMatchObject({ release_version: "0.1.0", target_version: null, canary_state: null });
    expect(await agentVersion(sc.probe.secret)).toBe("0.1.0");
  });

  it("a failing component after the canary applied, or an offline canary host, fails the canary", async () => {
    await startCanary();
    await canaryReports(1, "fail");
    await runEveryFiveMinutes(env, at(1));
    expect((await site()).canary_state).toBe("failed");
    await h.json("admin", "PATCH", "/sites/hall-b/release", { version: "0.1.0" });
    await h.json("admin", "PATCH", "/sites/hall-b/release", { version: "0.2.0", canary_host_id: sc.probe.host_id });
    expect((await site()).canary_state).toBe("pending");
    await canaryReports(30);
    await runEveryFiveMinutes(env, at(45)); // 15 minutes silent: offline
    expect((await site()).canary_state).toBe("failed");
    expect(JSON.stringify(await audit("site.canary_failed"))).toContain("offline");
    void MIN; void collectorComp; void dashComp;
  });

  it("manual promotion: PATCH the same version without a canary host; a canary host must belong to the site", async () => {
    await startCanary();
    const r = await h.json("admin", "PATCH", "/sites/hall-b/release", { version: "0.2.0" });
    expect(r.body).toMatchObject({ release_version: "0.2.0", target_version: null, canary_state: null });
    expect(await agentVersion(sc.col.secret)).toBe("0.2.0");
    await h.json("admin", "POST", "/sites", { site: "hall-c", name: "C", timezone: "UTC" });
    expect((await h.json("admin", "PATCH", "/sites/hall-c/release", { version: "0.2.0", canary_host_id: sc.probe.host_id })).status).toBe(400);
    expect((await audit("site.release")).length).toBe(2);
  });
});
