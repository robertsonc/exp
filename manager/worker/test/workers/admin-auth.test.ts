// 05-manager.md section 15 item 1: admin authentication fails closed.
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { OWNER, TEAM, call, env, goodClaims, makeKey, resetDb, serveJwks, signJwt, type TestKey } from "../helpers";
import { resetAccessCache } from "../../src/auth/access";

let key: TestKey;
let other: TestKey;

async function me(jwt: string | null, extra: Record<string, string> = {}): Promise<Response> {
  const headers: Record<string, string> = { ...extra };
  if (jwt !== null) headers["Cf-Access-Jwt-Assertion"] = jwt;
  return call("/api/admin/v1/me", { headers });
}

beforeEach(async () => {
  await resetDb();
  key = await makeKey("kid-1");
  other = await makeKey("kid-1"); // same kid, different key material: the forged-signature case
  serveJwks(key);
});
afterEach(() => {
  vi.unstubAllGlobals();
  resetAccessCache();
});

describe("admin JWT verification", () => {
  it("absent JWT -> 401 from the Worker", async () => {
    const r = await me(null);
    expect(r.status).toBe(401);
    expect((await r.json()) as unknown).toEqual({ error: { code: "unauthenticated", message: "unauthenticated", details: {} } });
  });

  it("Cf-Access-Authenticated-User-Email alone is never trusted", async () => {
    const r = await me(null, { "Cf-Access-Authenticated-User-Email": OWNER });
    expect(r.status).toBe(401);
  });

  it("garbage and truncated tokens -> 401", async () => {
    for (const t of ["x", "a.b.c", "....", "eyJhbGciOiJSUzI1NiJ9.e30."]) expect((await me(t)).status).toBe(401);
  });

  it("bad signature -> 401", async () => {
    const forged = await signJwt(other, goodClaims(OWNER));
    expect((await me(forged)).status).toBe(401);
  });

  it("alg none / HS256 -> 401", async () => {
    const claims = goodClaims(OWNER);
    const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    expect((await me(`${b64({ alg: "none", kid: "kid-1" })}.${b64(claims)}.`)).status).toBe(401);
    expect((await me(await signJwt(key, claims, { alg: "HS256" }))).status).toBe(401);
  });

  it("wrong aud -> 401", async () => {
    expect((await me(await signJwt(key, goodClaims(OWNER, { aud: ["someone-else"] })))).status).toBe(401);
  });

  it("wrong iss -> 401", async () => {
    expect((await me(await signJwt(key, goodClaims(OWNER, { iss: "https://evil.cloudflareaccess.com" })))).status).toBe(401);
  });

  it("expired -> 401, not-yet-valid -> 401", async () => {
    const now = Math.floor(Date.now() / 1000);
    expect((await me(await signJwt(key, goodClaims(OWNER, { exp: now - 600 })))).status).toBe(401);
    expect((await me(await signJwt(key, goodClaims(OWNER, { nbf: now + 600 })))).status).toBe(401);
  });

  it("unknown kid -> 401 (and the JWKS is refetched at most once per 30 s)", async () => {
    const j = serveJwks(key);
    const stranger = await makeKey("kid-unknown");
    expect((await me(await signJwt(stranger, goodClaims(OWNER)))).status).toBe(401);
    expect((await me(await signJwt(stranger, goodClaims(OWNER)))).status).toBe(401);
    expect(j.calls()).toBe(1);
  });

  it("missing configuration fails closed", async () => {
    const jwt = await signJwt(key, goodClaims(OWNER));
    const { app } = await import("../../src/index");
    for (const patch of [{ ACCESS_AUD: "" }, { ACCESS_TEAM_DOMAIN: "" }]) {
      const r = await app.fetch(
        new Request("https://manager.example.test/api/admin/v1/me", { headers: { "Cf-Access-Jwt-Assertion": jwt, "CF-Connecting-IP": "198.51.100.9" } }),
        { ...env, ...patch },
      );
      expect(r.status).toBe(401);
    }
  });

  it("authenticated but unknown email -> 403 unknown_admin", async () => {
    const r = await me(await signJwt(key, goodClaims("stranger@example.com")));
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe("unknown_admin");
  });

  it("valid JWT of EXP_OWNER_EMAIL -> 200 and the owner is created on first sign-in", async () => {
    const r = await me(await signJwt(key, goodClaims(OWNER)));
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ email: OWNER, role: "owner" });
    const row = await env.DB.prepare("SELECT role FROM admins WHERE email = ?1").bind(OWNER).first<{ role: string }>();
    expect(row?.role).toBe("owner");
    const audit = await env.DB.prepare("SELECT action FROM audit WHERE action = 'admin.owner_created'").all();
    expect(audit.results).toHaveLength(1);
    // a second sign-in does not create anything new
    expect((await me(await signJwt(key, goodClaims(OWNER.toUpperCase())))).status).toBe(200);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM admins").first<{ n: number }>())?.n).toBe(1);
  });

  it("known admins are mapped by email; disabled admins are refused", async () => {
    const now = new Date().toISOString();
    await env.DB.prepare("INSERT INTO admins (email, role, disabled, created_at, updated_at) VALUES ('op@example.com','operator',0,?1,?1), ('off@example.com','admin',1,?1,?1)").bind(now).run();
    const ok = await me(await signJwt(key, goodClaims("op@example.com")));
    expect(await ok.json()).toEqual({ email: "op@example.com", role: "operator" });
    const off = await me(await signJwt(key, goodClaims("off@example.com")));
    expect(off.status).toBe(403);
    expect(((await off.json()) as { error: { code: string } }).error.code).toBe("admin_disabled");
  });

  it("the JWKS is cached for an hour", async () => {
    const j = serveJwks(key);
    for (let i = 0; i < 3; i++) expect((await me(await signJwt(key, goodClaims(OWNER)))).status).toBe(200);
    expect(j.calls()).toBe(1);
  });

  it("unimplemented admin endpoints (drills: step 3) are still authenticated first", async () => {
    expect((await call("/api/admin/v1/drills")).status).toBe(401);
    const r = await call("/api/admin/v1/drills", { headers: { "Cf-Access-Jwt-Assertion": await signJwt(key, goodClaims(OWNER)) } });
    expect(r.status).toBe(501);
  });

  it("errors never carry stack traces; unknown paths are enveloped", async () => {
    const r = await call("/api/nope");
    expect(r.status).toBe(404);
    const t = await r.text();
    expect(t).not.toMatch(/at \w+|\.ts:\d+/);
    expect(JSON.parse(t).error.code).toBe("not_found");
    void TEAM;
  });
});
