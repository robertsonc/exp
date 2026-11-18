// 05-manager.md section 15 item 2 (and SR-7): enrolment is single-use, expiring, rate limited.
import { beforeEach, describe, expect, it } from "vitest";
import { createHost, createSite } from "../../src/admin/service";
import { newToken } from "../../src/secrets/tokens";
import { ADMIN_ACTOR, FACTS, auditActions, call, env, freshIp, json, resetDb } from "../helpers";

beforeEach(async () => {
  await resetDb();
  await createSite(env, ADMIN_ACTOR, { site: "hall-b", name: "Hall B" });
});

const enrol = (token: string, ip = freshIp(), facts: unknown = FACTS()) => call("/api/agent/v1/enrol", { ...json({ token, facts }), ip });

describe("POST /api/agent/v1/enrol", () => {
  it("creates the agent identity once and returns the secret, pubkey and manager time", async () => {
    const h = await createHost(env, ADMIN_ACTOR, { name: "srv-02", site: "hall-b" });
    const r = await enrol(h.enrol_token);
    expect(r.status).toBe(201);
    expect(r.headers.get("cache-control")).toBe("no-store");
    const b = (await r.json()) as Record<string, unknown>;
    expect(b.agent_id).toBe(h.host_id);
    expect(b.agent_secret).toMatch(/^expa_[A-Za-z0-9_-]{43}$/);
    expect(b.poll_interval_s).toBe(30);
    expect(String(b.release_pubkey_pem)).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(String(b.manager_time)).toMatch(/Z$/);
    // end state: host enrolled with facts, only the hash of the secret stored, one audit event
    const host = await env.DB.prepare("SELECT state, arch, facts_json FROM hosts WHERE host_id = ?1").bind(h.host_id).first<{ state: string; arch: string; facts_json: string }>();
    expect(host?.state).toBe("enrolled");
    expect(host?.arch).toBe("amd64");
    expect(JSON.parse(host!.facts_json).hostname).toBe("srv-02");
    const cred = await env.DB.prepare("SELECT secret_hash FROM agent_creds WHERE host_id = ?1").bind(h.host_id).first<{ secret_hash: string }>();
    expect(cred?.secret_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(cred)).not.toContain(String(b.agent_secret));
    expect((await auditActions()).filter((a) => a === "host.enrol")).toHaveLength(1);
    const desired = await env.DB.prepare("SELECT version FROM desired_docs WHERE host_id = ?1").bind(h.host_id).first<{ version: number }>();
    expect(desired?.version).toBe(1); // bare document: the agent has something to poll immediately
  });

  it("20 concurrent attempts with one token: exactly one 201, the rest 410", async () => {
    const h = await createHost(env, ADMIN_ACTOR, { name: "srv-02", site: "hall-b" });
    const results = await Promise.all(Array.from({ length: 20 }, () => enrol(h.enrol_token)));
    const codes = results.map((r) => r.status).sort();
    expect(codes.filter((c) => c === 201)).toHaveLength(1);
    expect(codes.filter((c) => c === 410)).toHaveLength(19);
    const creds = await env.DB.prepare("SELECT COUNT(*) AS n FROM agent_creds").first<{ n: number }>();
    expect(creds?.n).toBe(1);
    expect((await auditActions()).filter((a) => a === "host.enrol")).toHaveLength(1);
    for (const r of results.filter((x) => x.status === 410)) {
      expect(((await r.json()) as { error: { code: string } }).error.code).toBe("token_used_or_expired");
    }
  });

  it("reuse after success -> 410; unknown token -> 401; malformed -> 400", async () => {
    const h = await createHost(env, ADMIN_ACTOR, { name: "srv-02", site: "hall-b" });
    expect((await enrol(h.enrol_token)).status).toBe(201);
    const again = await enrol(h.enrol_token);
    expect(again.status).toBe(410);
    expect(((await again.json()) as { error: { code: string } }).error.code).toBe("token_used_or_expired");
    const unknown = await enrol(newToken("expe"));
    expect(unknown.status).toBe(401);
    expect(((await unknown.json()) as { error: { code: string } }).error.code).toBe("invalid_token");
    expect((await enrol("not-a-token")).status).toBe(400);
    expect((await enrol(newToken("expe"), freshIp(), { hostname: "x" })).status).toBe(400); // facts incomplete
    expect((await call("/api/agent/v1/enrol", { method: "POST", body: "{nope" })).status).toBe(400);
  });

  it("an expired token -> 410 and nothing is created", async () => {
    const h = await createHost(env, ADMIN_ACTOR, { name: "srv-02", site: "hall-b" });
    await env.DB.prepare("UPDATE enrol_tokens SET expires_at = '2020-01-01T00:00:00.000Z'").run();
    expect((await enrol(h.enrol_token)).status).toBe(410);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM agent_creds").first<{ n: number }>())?.n).toBe(0);
    expect((await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(h.host_id).first<{ state: string }>())?.state).toBe("pending");
  });

  it("tokens are bound to their pre-created host", async () => {
    const a = await createHost(env, ADMIN_ACTOR, { name: "a", site: "hall-b" });
    const b = await createHost(env, ADMIN_ACTOR, { name: "b", site: "hall-b" });
    const r = await enrol(a.enrol_token);
    expect(((await r.json()) as { agent_id: string }).agent_id).toBe(a.host_id);
    expect((await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(b.host_id).first<{ state: string }>())?.state).toBe("pending");
  });

  it("the 11th enrol attempt per minute from one IP -> 429", async () => {
    const ip = "198.51.100.77";
    const codes: number[] = [];
    for (let i = 0; i < 12; i++) codes.push((await enrol(newToken("expe"), ip)).status);
    expect(codes.slice(0, 10).every((c) => c === 401)).toBe(true);
    expect(codes[10]).toBe(429);
    expect(codes[11]).toBe(429);
    const r = await enrol(newToken("expe"), ip);
    expect(r.headers.get("retry-after")).toBeTruthy();
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe("rate_limited");
    // another IP is unaffected
    expect((await enrol(newToken("expe"))).status).toBe(401);
  });

  it("fails closed (503) without burning the token when EXP_MASTER_KEY is missing or invalid", async () => {
    const { app } = await import("../../src/index");
    const h = await createHost(env, ADMIN_ACTOR, { name: "srv-02", site: "hall-b" });
    for (const bad of [undefined, "", "not base64!!", btoa("short")]) {
      const r = await app.fetch(
        new Request("https://manager.example.test/api/agent/v1/enrol", { ...json({ token: h.enrol_token, facts: FACTS() }), headers: { "content-type": "application/json", "CF-Connecting-IP": freshIp() } }),
        { ...env, EXP_MASTER_KEY: bad },
      );
      expect(r.status).toBe(503);
      expect(await r.text()).not.toMatch(/exp[aeidn]_/);
    }
    expect((await enrol(h.enrol_token)).status).toBe(201); // token still usable
  });

  it("fails closed (503) without burning the token when RELEASE_PUBKEY_PEM is unset", async () => {
    const { app } = await import("../../src/index");
    const h = await createHost(env, ADMIN_ACTOR, { name: "srv-02", site: "hall-b" });
    for (const bad of [undefined, "", "  "]) {
      const r = await app.fetch(
        new Request("https://manager.example.test/api/agent/v1/enrol", { ...json({ token: h.enrol_token, facts: FACTS() }), headers: { "content-type": "application/json", "CF-Connecting-IP": freshIp() } }),
        { ...env, RELEASE_PUBKEY_PEM: bad as unknown as string },
      );
      expect(r.status).toBe(503);
    }
    expect((await enrol(h.enrol_token)).status).toBe(201);
  });

  it("a decommissioned host cannot be re-enrolled", async () => {
    const h = await createHost(env, ADMIN_ACTOR, { name: "srv-02", site: "hall-b" });
    await env.DB.prepare("UPDATE hosts SET state = 'removed' WHERE host_id = ?1").bind(h.host_id).run();
    expect((await enrol(h.enrol_token)).status).toBe(410);
  });
});
