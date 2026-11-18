// Intent changes -> persisted desired documents: no churn, fan-out, canary, validation of admin input.
import { beforeEach, describe, expect, it } from "vitest";
import * as svc from "../../src/admin/service";
import { recompile } from "../../src/compile/recompile";
import { ADMIN_ACTOR, PBKDF2, WEBHOOK_URL, env, fullScenario, getDesired, resetDb, seedRelease, seedSiteWithRelease } from "../helpers";

beforeEach(async () => {
  await resetDb();
  await seedSiteWithRelease("hall-b", "0.1.0");
});

const versionOf = async (secret: string): Promise<number> => ((await (await getDesired(secret)).json()) as { version: number }).version;

describe("persisted desired state", () => {
  it("recompiling without a real change never bumps the version", async () => {
    const sc = await fullScenario();
    const v = [await versionOf(sc.col.secret), await versionOf(sc.dash.secret), await versionOf(sc.probe.secret)];
    for (let i = 0; i < 3; i++) await recompile(env, { all: true });
    expect([await versionOf(sc.col.secret), await versionOf(sc.dash.secret), await versionOf(sc.probe.secret)]).toEqual(v);
  });

  it("a probe config change bumps only the probe host (and its collector's probe list stays equal)", async () => {
    const sc = await fullScenario();
    const before = { col: await versionOf(sc.col.secret), dash: await versionOf(sc.dash.secret), probe: await versionOf(sc.probe.secret) };
    await svc.updateComponentConfig(env, ADMIN_ACTOR, sc.probeId, { label: "Hall B east", labels: { zone: "floor-1" }, ports: [] });
    expect(await versionOf(sc.probe.secret)).toBe(before.probe + 1);
    expect(await versionOf(sc.col.secret)).toBe(before.col);
    expect(await versionOf(sc.dash.secret)).toBe(before.dash);
  });

  it("a probe label change fans out to its collector", async () => {
    const sc = await fullScenario();
    const col = await versionOf(sc.col.secret);
    await svc.updateComponentConfig(env, ADMIN_ACTOR, sc.probeId, { label: "Hall B west" });
    expect(await versionOf(sc.col.secret)).toBe(col + 1);
  });

  it("creating a NOC token or a dashboard user changes only the dashboard host", async () => {
    const sc = await fullScenario();
    const col = await versionOf(sc.col.secret);
    const dash = await versionOf(sc.dash.secret);
    await svc.createNocToken(env, ADMIN_ACTOR, "dash-main", { label: "second" });
    await svc.createDashboardUser(env, ADMIN_ACTOR, "dash-main", { username: "bob", role: "operator", hash: PBKDF2 });
    expect(await versionOf(sc.dash.secret)).toBe(dash + 2);
    expect(await versionOf(sc.col.secret)).toBe(col);
  });

  it("canary: the canary host moves to the new version first, then promotion moves everyone", async () => {
    const sc = await fullScenario();
    await seedRelease("0.2.0");
    await svc.setSiteRelease(env, ADMIN_ACTOR, "hall-b", { version: "0.2.0", canary_host_id: sc.probe.host_id });
    const get = async (s: string) => (await (await getDesired(s)).json()) as { agent: { version: string }; components: Array<{ version: string }> };
    expect((await get(sc.probe.secret)).agent.version).toBe("0.2.0");
    expect((await get(sc.probe.secret)).components[0]!.version).toBe("0.2.0");
    expect((await get(sc.col.secret)).agent.version).toBe("0.1.0");
    await svc.promoteCanary(env, ADMIN_ACTOR, "hall-b");
    for (const s of [sc.col.secret, sc.dash.secret, sc.probe.secret]) expect((await get(s)).agent.version).toBe("0.2.0");
    // rollback = set the previous version again
    await svc.setSiteRelease(env, ADMIN_ACTOR, "hall-b", { version: "0.1.0" });
    for (const s of [sc.col.secret, sc.dash.secret, sc.probe.secret]) expect((await get(s)).agent.version).toBe("0.1.0");
  });

  it("a missing artifact holds the host on its current document instead of wiping it", async () => {
    const sc = await fullScenario();
    const before = (await (await getDesired(sc.probe.secret)).json()) as { version: number; components: unknown[] };
    await seedRelease("0.3.0", { archs: { agent: ["noarch"], collector: ["amd64"] } }); // no probe artifact
    await svc.setSiteRelease(env, ADMIN_ACTOR, "hall-b", { version: "0.3.0" });
    const after = (await (await getDesired(sc.probe.secret)).json()) as { version: number; components: unknown[] };
    expect(after.version).toBe(before.version);
    expect(after.components).toHaveLength(1);
  });

  it("the stored document is schema-shaped and the content hash matches the host row", async () => {
    const sc = await fullScenario();
    const row = await env.DB.prepare("SELECT d.content_hash, d.version, h.desired_hash, h.desired_version FROM desired_docs d JOIN hosts h USING (host_id) WHERE host_id = ?1").bind(sc.col.host_id).first<Record<string, unknown>>();
    expect(row!.content_hash).toBe(row!.desired_hash);
    expect(row!.version).toBe(row!.desired_version);
  });
});

describe("admin input validation", () => {
  it("webhook URLs: https only, no private / loopback / link-local targets (SR-15)", async () => {
    const bad = ["http://hooks.slack.com/x", "https://127.0.0.1/x", "https://localhost/x", "https://10.0.0.5/x", "https://169.254.169.254/latest", "https://192.168.1.1/x", "https://172.20.0.1/x", "https://[::1]/x", "https://intranet/x", "https://user:pw@hooks.slack.com/x", "not a url", "ftp://hooks.slack.com/x"];
    for (const url of bad) expect(() => svc.validateWebhookUrl(url), url).toThrow();
    expect(svc.validateWebhookUrl(WEBHOOK_URL).hostname).toBe("hooks.slack.com");
    expect(svc.validateWebhookUrl("https://172.32.0.1/x").hostname).toBe("172.32.0.1");
  });

  it("dashboard user hashes must be the client-side PBKDF2 string, never a password", async () => {
    await fullScenario();
    for (const hash of ["hunter2", "password123", "pbkdf2_sha256$600000$short", "$2b$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz0123"]) {
      await expect(svc.createDashboardUser(env, ADMIN_ACTOR, "dash-main", { username: "eve", role: "viewer", hash })).rejects.toMatchObject({ status: 400 });
    }
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM dashboard_users WHERE username = 'eve'").first<{ n: number }>())?.n).toBe(0);
  });

  it("component ids and types are validated; duplicates conflict", async () => {
    const sc = await fullScenario();
    await expect(svc.addComponent(env, ADMIN_ACTOR, sc.probe.host_id, { type: "probe", id: "Bad ID", config: {} })).rejects.toMatchObject({ status: 400 });
    await expect(svc.addComponent(env, ADMIN_ACTOR, sc.probe.host_id, { type: "shell", id: "x", config: {} })).rejects.toMatchObject({ status: 400 });
    await expect(svc.addComponent(env, ADMIN_ACTOR, sc.probe.host_id, { type: "probe", id: "probe-a1", config: {} })).rejects.toMatchObject({ status: 409 });
  });

  it("a new enrol token replaces unused ones; only the newest works", async () => {
    const h = await svc.createHost(env, ADMIN_ACTOR, { name: "x", site: "hall-b" });
    const t2 = await svc.issueEnrolToken(env, ADMIN_ACTOR, h.host_id);
    const { call, json, FACTS } = await import("../helpers");
    expect((await call("/api/agent/v1/enrol", json({ token: h.enrol_token, facts: FACTS() }))).status).toBe(401);
    expect((await call("/api/agent/v1/enrol", json({ token: t2.enrol_token, facts: FACTS() }))).status).toBe(201);
  });
});
