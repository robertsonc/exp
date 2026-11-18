// Security fixes: SSO/board_url target, nested integration secrets, CSRF guard, anti-framing headers.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { app } from "../../src/index";
import { resetAccessCache } from "../../src/auth/access";
import { harness, type Harness } from "../admin-harness";
import { FACTS, enrolHost, env, resetDb, seedSiteWithRelease } from "../helpers";

let h: Harness;
beforeEach(async () => {
  await resetDb();
  h = await harness();
});
afterEach(() => {
  vi.unstubAllGlobals();
  resetAccessCache();
});

describe("CSRF guard", () => {
  const forged = { "content-type": "text/plain", origin: "https://evil.example", "sec-fetch-site": "cross-site", "X-Exp-Request": "" };
  const routes: Array<[string, string, string]> = [
    ["PUT", "/settings/fleet-thresholds", '{"offline_after_s":900}'],
    ["PUT", "/settings/platform-webhook", "{}"],
    ["PUT", "/integrations/ec", '{"config":{}}'],
    ["PATCH", "/settings", '{"org_name":"Acme"}'],
    ["POST", "/enrol-token", "{}"],
  ];
  for (const [m, p, b] of routes) {
    it(`cross-site text/plain ${m} ${p} -> 403 csrf_refused`, async () => {
      const r = await h.api("owner", m, p, b, forged);
      expect(r.status).toBe(403);
      expect(((await r.json()) as { error: { code: string } }).error.code).toBe("csrf_refused");
    });
  }

  it("each rule refuses on its own", async () => {
    const json = { "content-type": "application/json" };
    expect((await h.api("owner", "PATCH", "/settings", '{"org_name":"Acme"}', { ...json, "X-Exp-Request": "" })).status).toBe(403); // no header
    expect((await h.api("owner", "PATCH", "/settings", '{"org_name":"Acme"}', { "content-type": "text/plain" })).status).toBe(403); // wrong type
    expect((await h.api("owner", "PATCH", "/settings", '{"org_name":"Acme"}', { origin: "https://evil.example" })).status).toBe(403);
    expect((await h.api("owner", "PATCH", "/settings", '{"org_name":"Acme"}', { "sec-fetch-site": "same-site" })).status).toBe(403);
    expect((await h.api("owner", "PATCH", "/settings", '{"org_name":"Acme"}', { "sec-fetch-site": "cross-site" })).status).toBe(403);
  });

  it("same-origin JSON with the header passes; GETs are unaffected", async () => {
    const ok = await h.api("owner", "PATCH", "/settings", { org_name: "Acme" }, { origin: "https://manager.example.test", "sec-fetch-site": "same-origin" });
    expect(ok.status).toBeLessThan(300);
    const ct = await h.api("owner", "PATCH", "/settings", JSON.stringify({ org_name: "Acme" }), { "content-type": "application/json; charset=utf-8" });
    expect(ct.status).toBeLessThan(300);
    expect((await h.api("owner", "GET", "/me", undefined, { "X-Exp-Request": "", origin: "https://evil.example" })).status).toBe(200);
  });

  it("the multipart upload endpoint refuses JSON and a cross-site multipart post", async () => {
    const f = new FormData();
    f.set("x", "y");
    expect((await h.api("owner", "POST", "/releases/upload", { a: 1 })).status).toBe(403);
    expect((await h.api("owner", "POST", "/releases/upload", f, { origin: "https://evil.example" })).status).toBe(403);
    expect((await h.api("owner", "POST", "/releases/upload", f, { "X-Exp-Request": "" })).status).toBe(403);
  });
});

describe("anti-framing headers on Worker responses", () => {
  it("API JSON and the SSO page carry X-Frame-Options DENY and frame-ancestors none", async () => {
    const r = await h.api("owner", "GET", "/me");
    expect(r.headers.get("x-frame-options")).toBe("DENY");
    expect(r.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    const hz = await app.fetch(new Request("https://manager.example.test/healthz"), env);
    expect(hz.headers.get("x-frame-options")).toBe("DENY");
  });
});

describe("integration secrets at any depth", () => {
  it("nested config and allowlist secret keys are refused on PUT", async () => {
    const a = await h.json("owner", "PUT", "/integrations/ec", { config: { auth: { password: "hunter2" } } });
    expect(a.status).toBe(400);
    const b = await h.json("owner", "PUT", "/integrations/ec", { config: {}, allowlist: [{ name: "x", api_key: "k" }] });
    expect(b.status).toBe(400);
    const c = await h.json("owner", "PUT", "/integrations/ec", { config: { a: [{ b: { client_secret: "s" } }] } });
    expect(c.status).toBe(400);
    const ok = await h.json("owner", "PUT", "/integrations/ec", { config: { auth: { user: "bob" } }, allowlist: [{ name: "x" }] });
    expect(ok.status).toBeLessThan(300);
  });

  it("a row seeded with nested secrets is returned redacted to a viewer", async () => {
    await env.DB.prepare("INSERT OR REPLACE INTO integrations (kind, config_json, secret_id, allowlist_json, created_at, updated_at) VALUES ('mist', ?1, NULL, ?2, ?3, ?3)")
      .bind(JSON.stringify({ auth: { password: "hunter2", user: "bob" } }), JSON.stringify([{ name: "n", api_key: "KEY123" }]), new Date().toISOString())
      .run();
    const r = await h.json<{ config: { auth: { password: unknown; user: string } }; allowlist: Array<{ api_key: unknown }> }>("viewer", "GET", "/integrations/mist");
    expect(r.status).toBe(200);
    const text = JSON.stringify(r.body);
    expect(text).not.toContain("hunter2");
    expect(text).not.toContain("KEY123");
    expect(r.body.config.auth.user).toBe("bob");
  });
});

describe("dashboard url: admin-set or management IP, never agent-reported", () => {
  it("a host reporting facts.url=https://attacker.example does not change the SSO form action", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    const host = await enrolHost("hall-b", "dash-host", FACTS({ interfaces: [{ name: "eno1", mac: "18:66:da:00:00:09", state: "up", speed_mbps: 1000, addrs: ["10.32.98.30/23"], default_route: true, in_use_by: "mgmt" }] }));
    const c = await h.json<{ component_id: string }>("admin", "POST", `/hosts/${host.host_id}/components`, { type: "dashboard", id: "dash-main", config: {} });
    await env.DB.prepare("UPDATE components SET facts_json = ?1 WHERE component_id = ?2").bind(JSON.stringify({ facts: { url: "https://attacker.example" } }), c.body.component_id).run();
    const r = await h.api("viewer", "POST", "/dashboards/dash-main/sso", {});
    expect(r.status).toBe(200);
    const html = await r.text();
    expect(html).not.toContain("attacker.example");
    expect(html).toContain('action="https://10.32.98.30/auth/sso"');
    expect(r.headers.get("content-security-policy")).toContain("form-action https://10.32.98.30");
    expect(r.headers.get("content-security-policy")).not.toContain("attacker");
  });
});

describe("SSO launch nonce", () => {
  async function setup() {
    await seedSiteWithRelease("hall-b", "0.1.0");
    const host = await enrolHost("hall-b", "dash-host", FACTS({ interfaces: [{ name: "eno1", mac: "18:66:da:00:00:09", state: "up", speed_mbps: 1000, addrs: ["10.32.98.30/23"], default_route: true, in_use_by: "mgmt" }] }));
    await h.json("admin", "POST", `/hosts/${host.host_id}/components`, { type: "dashboard", id: "dash-main", config: {} });
  }
  it("launch needs the CSRF header; the GET page needs a valid nonce bound to the admin", async () => {
    await setup();
    const forged = await h.api("viewer", "POST", "/dashboards/dash-main/sso/launch", undefined, { "X-Exp-Request": "", origin: "https://evil.example" });
    expect(forged.status).toBe(403);
    expect((await h.api("viewer", "GET", "/dashboards/dash-main/sso/page")).status).toBe(403);
    expect((await h.api("viewer", "GET", "/dashboards/dash-main/sso/page?n=1999999999.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).status).toBe(403);
    const l = await h.json<{ url: string }>("viewer", "POST", "/dashboards/dash-main/sso/launch");
    expect(l.status).toBe(200);
    expect(l.body.url).toMatch(/^\/api\/admin\/v1\/dashboards\/dash-main\/sso\/page\?n=\d{10}\.[A-Za-z0-9_-]{43}$/);
    const path = l.body.url.replace("/api/admin/v1", "");
    expect((await h.api("operator", "GET", path)).status).toBe(403); // another admin cannot use it
    const ok = await h.api("viewer", "GET", path);
    expect(ok.status).toBe(200);
    expect(await ok.text()).toContain('action="https://10.32.98.30/auth/sso"');
    expect(ok.headers.get("content-security-policy")).toContain("form-action https://10.32.98.30");
    const tampered = path.replace(/n=\d{10}/, "n=1999999999");
    expect((await h.api("viewer", "GET", tampered)).status).toBe(403);
  });
});
