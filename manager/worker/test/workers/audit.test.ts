// 05-manager.md section 15 item 7: every mutation writes exactly one audit event, never with secret values.
import { beforeEach, describe, expect, it } from "vitest";
import * as svc from "../../src/admin/service";
import { scrub } from "../../src/audit/audit";
import { ADMIN_ACTOR, PBKDF2, WEBHOOK_URL, bearer, call, createSite, enrolHost, env, getDesired, resetDb, seedRelease } from "../helpers";

beforeEach(async () => {
  await resetDb();
});

const count = async (): Promise<number> => (await env.DB.prepare("SELECT COUNT(*) AS n FROM audit").first<{ n: number }>())!.n;

/** runs `fn`, asserts exactly one new audit event and returns it */
async function one<T>(fn: () => Promise<T>): Promise<{ result: T; action: string; actor: string; details: string; resource: string }> {
  const before = await count();
  const result = await fn();
  const after = await count();
  expect(after - before).toBe(1);
  const row = (await env.DB.prepare("SELECT action, actor, details_json, resource FROM audit ORDER BY ts DESC, rowid DESC LIMIT 1").first<{ action: string; actor: string; details_json: string; resource: string }>())!;
  return { result, action: row.action, actor: row.actor, details: row.details_json, resource: row.resource };
}

describe("audit: one event per mutation", () => {
  it("every service mutation and every agent mutation writes exactly one event, none with secrets", async () => {
    const seen: string[] = [];
    const rec = (e: { action: string; actor: string }, actor: string) => {
      expect(e.actor).toBe(actor);
      seen.push(e.action);
    };
    rec(await one(() => createSite(env, ADMIN_ACTOR, { site: "hall-b", name: "Hall B" })), ADMIN_ACTOR.email);
    await seedRelease("0.1.0");
    await seedRelease("0.2.0");
    rec(await one(() => svc.setSiteRelease(env, ADMIN_ACTOR, "hall-b", { version: "0.1.0" })), ADMIN_ACTOR.email);

    const created = await one(() => svc.createHost(env, ADMIN_ACTOR, { name: "srv-02", site: "hall-b" }));
    rec(created, ADMIN_ACTOR.email);
    const hostId = created.result.host_id;
    const enrol = await one(async () => call("/api/agent/v1/enrol", { method: "POST", body: JSON.stringify({ token: created.result.enrol_token, facts: (await import("../helpers")).FACTS() }), headers: { "content-type": "application/json" } }));
    expect(enrol.result.status).toBe(201);
    rec(enrol, `agent:${hostId}`);
    const secret = ((await enrol.result.json()) as { agent_secret: string }).agent_secret;

    rec(await one(() => svc.issueEnrolToken(env, ADMIN_ACTOR, hostId)), ADMIN_ACTOR.email);
    const comp = await one(() => svc.addComponent(env, ADMIN_ACTOR, hostId, { type: "probe", id: "probe-a1", config: {} }));
    rec(comp, ADMIN_ACTOR.email);
    const cid = comp.result.component_id;
    rec(await one(() => svc.updateComponentConfig(env, ADMIN_ACTOR, cid, { label: "x" })), ADMIN_ACTOR.email);
    rec(await one(() => svc.rotateComponentTokens(env, ADMIN_ACTOR, cid)), ADMIN_ACTOR.email);

    const dh = await svc.createHost(env, ADMIN_ACTOR, { name: "dash", site: "hall-b" });
    await call("/api/agent/v1/enrol", { method: "POST", body: JSON.stringify({ token: dh.enrol_token, facts: (await import("../helpers")).FACTS() }), headers: { "content-type": "application/json" } });
    await svc.addComponent(env, ADMIN_ACTOR, dh.host_id, { type: "dashboard", id: "dash-main", config: { url: "https://10.32.98.30" } });
    rec(await one(() => svc.createDashboardUser(env, ADMIN_ACTOR, "dash-main", { username: "alice", role: "viewer", hash: PBKDF2 })), ADMIN_ACTOR.email);
    const noc = await one(() => svc.createNocToken(env, ADMIN_ACTOR, "dash-main", { label: "wall" }));
    rec(noc, ADMIN_ACTOR.email);
    rec(await one(() => svc.revokeNocToken(env, ADMIN_ACTOR, noc.result.noc_id)), ADMIN_ACTOR.email);
    rec(await one(() => svc.addWebhook(env, ADMIN_ACTOR, "hall-b", { format: "slack", url: WEBHOOK_URL })), ADMIN_ACTOR.email);

    rec(await one(() => svc.setSiteRelease(env, ADMIN_ACTOR, "hall-b", { version: "0.2.0", canary_host_id: hostId })), ADMIN_ACTOR.email);
    rec(await one(() => svc.promoteCanary(env, ADMIN_ACTOR, "hall-b")), ADMIN_ACTOR.email);

    rec(await one(() => svc.requestAgentRotation(env, ADMIN_ACTOR, hostId)), ADMIN_ACTOR.email);
    const rot = await one(() => call("/api/agent/v1/rotate", { method: "POST", headers: bearer(secret), body: "{}" }));
    expect(rot.result.status).toBe(200);
    rec(rot, `agent:${hostId}`);
    const newSecret = ((await rot.result.json()) as { agent_secret: string }).agent_secret;

    rec(await one(() => svc.deleteComponent(env, ADMIN_ACTOR, cid)), ADMIN_ACTOR.email);
    rec(await one(() => svc.decommissionHost(env, ADMIN_ACTOR, hostId)), ADMIN_ACTOR.email);
    const done = await one(() => call("/api/agent/v1/decommissioned", { method: "POST", headers: bearer(newSecret), body: "{}" }));
    expect(done.result.status).toBe(204);
    rec(done, `agent:${hostId}`);

    // a rejected mutation writes nothing
    const before = await count();
    await expect(svc.createSite(env, ADMIN_ACTOR, { site: "hall-b", name: "dup" })).rejects.toMatchObject({ status: 409 });
    await expect(svc.addWebhook(env, ADMIN_ACTOR, "hall-b", { format: "slack", url: "http://127.0.0.1/x" })).rejects.toMatchObject({ status: 400 });
    expect(await count()).toBe(before);

    expect(new Set(seen).size).toBeGreaterThanOrEqual(17); // every mutation kind covered
    expect(seen.length).toBeGreaterThanOrEqual(18);

    // nothing secret in any audit row
    const all = JSON.stringify((await env.DB.prepare("SELECT * FROM audit").all()).results);
    expect(all).not.toMatch(/exp[aeidn]_[A-Za-z0-9_-]{8,}/);
    expect(all).not.toContain("https://hooks");
    expect(all).not.toContain("SECRETXXXX");
    expect(all).not.toContain(PBKDF2);
    for (const s of [created.result.enrol_token, secret, newSecret, noc.result.token]) expect(all).not.toContain(s);
    // reads write nothing
    const n = await count();
    await getDesired(newSecret);
    expect(await count()).toBe(n);
  }, 60000);

  it("plain reads, failed auth and status reports write no audit events", async () => {
    await createSite(env, ADMIN_ACTOR, { site: "hall-b", name: "Hall B" });
    await seedRelease("0.1.0");
    const h = await enrolHost("hall-b");
    const n = await count();
    await getDesired(h.secret);
    await getDesired("expa_" + "A".repeat(43));
    await call("/api/admin/v1/me");
    expect(await count()).toBe(n);
  });
});

describe("audit scrubbing (defence in depth)", () => {
  it("masks tokens and webhook URLs and drops secret-looking keys", () => {
    const s = JSON.stringify(
      scrub({ note: "token expi_" + "A".repeat(43) + " and https://hooks.slack.com/services/X/Y/Z", token: "abc", password: "p", url: "https://x", ok: "fine", secret_set: true, nested: { api_key: "k", list: ["expa_" + "B".repeat(43)] } }),
    );
    expect(s).not.toMatch(/exp[aeidn]_[A-Za-z0-9_-]{8,}/);
    expect(s).not.toContain("hooks.slack.com");
    expect(s).not.toContain('"abc"');
    expect(s).toContain('"ok":"fine"');
    expect(s).toContain('"secret_set":true');
  });
});
