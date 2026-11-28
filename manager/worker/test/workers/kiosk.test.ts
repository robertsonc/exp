// Read-only kiosk (/kiosk): no Access JWT, gated by the source address (KIOSK_ALLOW_CIDRS) and exposing device counts and
// the devices that are down (name, type, site, since) only.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../src/index";
import type { Env } from "../../src/env";
import { ipAllowed, parseCidrs } from "../../src/kiosk/kiosk";
import { resetCentralTokens } from "../../src/ops/devices";
import { sha256Hex } from "../../src/util/encoding";
import { harness, type Harness } from "../admin-harness";
import { env, resetDb } from "../helpers";

const MGMT = "37.34.66.15";
const ORG = "6f1d2c3b-aaaa-4bbb-8ccc-0123456789ab";
let h: Harness;

const withVars = (vars: Partial<Env>): Env => new Proxy(env, { get: (t, p, r) => (p in vars ? (vars as Record<string | symbol, unknown>)[p] : Reflect.get(t, p, r)) }) as Env;
async function get(path: string, ip: string | null, vars: Partial<Env> = { KIOSK_ALLOW_CIDRS: `${MGMT}/32` }, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (ip) headers.set("CF-Connecting-IP", ip);
  return app.fetch(new Request(`https://manager.example.test${path}`, { ...init, headers }), withVars(vars));
}

beforeEach(async () => {
  await resetDb();
  resetCentralTokens();
  h = await harness();
});
afterEach(() => h.restore());

describe("kiosk source allowlist", () => {
  it("does not exist until KIOSK_ALLOW_CIDRS is set (and not when it holds only garbage)", async () => {
    for (const v of ["", undefined, "not-an-ip, 10.0.0.0/33"]) {
      expect((await get("/kiosk", MGMT, { KIOSK_ALLOW_CIDRS: v })).status).toBe(404);
      expect((await get("/kiosk/api/devices", MGMT, { KIOSK_ALLOW_CIDRS: v })).status).toBe(404);
    }
  });

  it("serves only the allowed source address", async () => {
    expect((await get("/kiosk", MGMT)).status).toBe(200);
    expect((await get("/kiosk/api/devices", MGMT)).status).toBe(200);
    for (const ip of ["37.34.66.16", "37.34.66.14", "2001:db8::1", "unknown", "37.34.66.15.1"]) {
      expect((await get("/kiosk", ip)).status, ip).toBe(403);
      expect((await get("/kiosk/api/devices", ip)).status, ip).toBe(403);
    }
    expect((await get("/kiosk", null)).status).toBe(403);
  });

  it("only the edge-set CF-Connecting-IP counts, never X-Forwarded-For or True-Client-IP", async () => {
    const r = await get("/kiosk/api/devices", "198.51.100.7", undefined, { headers: { "X-Forwarded-For": MGMT, "True-Client-IP": MGMT, "X-Real-IP": MGMT } });
    expect(r.status).toBe(403);
  });

  it("answers nothing else under /kiosk, and no other method", async () => {
    for (const p of ["/kiosk/api/other", "/kiosk/assets/x.js", "/kiosk/api/devices/1"]) {
      const r = await get(p, MGMT);
      expect(r.status, p).toBe(404);
      expect(r.headers.get("content-type")).toMatch(/application\/json/);
    }
    expect((await get("/kiosk/api/devices", MGMT, undefined, { method: "POST" })).status).toBe(404);
  });

  it("does not open the admin API to the kiosk address", async () => {
    for (const p of ["/api/admin/v1/me", "/api/admin/v1/ops/devices", "/api/admin/v1/settings"]) expect((await get(p, MGMT)).status, p).toBe(401);
  });

  it("parses v4 / v6 CIDRs and host addresses; refuses ambiguous spellings", () => {
    const { cidrs, invalid } = parseCidrs("37.34.66.15/32, 10.1.0.0/16 2001:db8:10::/48 ::1 192.168.1.7 010.0.0.1 1.2.3.4/33 2001:db8::/129 1::2::3 x");
    expect(invalid).toEqual(["010.0.0.1", "1.2.3.4/33", "2001:db8::/129", "1::2::3", "x"]);
    expect(cidrs).toHaveLength(5);
    for (const ok of ["37.34.66.15", "10.1.255.3", "2001:db8:10:ffff::1", "::1", "192.168.1.7"]) expect(ipAllowed(ok, cidrs), ok).toBe(true);
    for (const no of ["37.34.66.16", "10.2.0.1", "2001:db8:11::1", "::2", "192.168.1.8", "", "1.2.3"]) expect(ipAllowed(no, cidrs), no).toBe(false);
    expect(ipAllowed("10.0.0.1", parseCidrs("0.0.0.0/0").cidrs)).toBe(true);
    expect(ipAllowed("2001:db8::1", parseCidrs("0.0.0.0/0").cidrs)).toBe(false);
  });
});

describe("kiosk page and data", () => {
  it("is a static page whose CSP pins its one script and one style by hash", async () => {
    const r = await get("/kiosk", MGMT);
    const html = await r.text();
    const csp = r.headers.get("content-security-policy") ?? "";
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(csp).toMatch(/default-src 'none'/);
    expect(csp).toMatch(/frame-ancestors 'none'/);
    expect(csp).not.toMatch(/unsafe/);
    const b64 = async (s: string) => btoa(String.fromCharCode(...(await sha256Hex(s)).match(/../g)!.map((x) => parseInt(x, 16))));
    const script = /<script>([\s\S]*)<\/script>/.exec(html)![1]!;
    const style = /<style>([\s\S]*)<\/style>/.exec(html)![1]!;
    expect(csp).toContain(`script-src 'sha256-${await b64(script)}'`);
    expect(csp).toContain(`style-src 'sha256-${await b64(style)}'`);
    expect(html).not.toMatch(/innerHTML/);
  });

  it("returns counts and down devices only: no connector state, no vendor error text, no credentials", async () => {
    expect((await h.json("owner", "PUT", "/integrations/mist", { config: { api_base: "https://api.mist.com", org_id: ORG }, credentials: { token: "mist-SECRET-token" } })).status).toBe(200);
    let status = 200;
    h.handlers.push((url) => {
      if (!url.startsWith("https://api.mist.com/")) return undefined;
      if (status !== 200) return new Response("{}", { status });
      return Response.json([{ mac: "a", type: "ap", status: "connected" }, { mac: "b", type: "switch", status: "disconnected" }], { headers: { "x-page-total": "2" } });
    });
    const r = await get("/kiosk/api/devices", MGMT);
    const b = (await r.json()) as { sources: Array<Record<string, unknown>> };
    const mist = b.sources.find((s) => s.kind === "mist")!;
    expect(mist).toMatchObject({ state: "ok", total: 2, online: 1, offline: 1, by_type: { ap: { total: 1, online: 1 }, switch: { total: 1, online: 0 } } });
    expect(Object.keys(mist).sort()).toEqual(["by_type", "counts_at", "down", "down_more", "kind", "label", "offline", "online", "state", "total"]);
    expect(mist.down).toEqual([{ name: null, type: "switch", site: null, since: expect.any(String) }]);
    expect(b.sources.find((s) => s.kind === "central")).toMatchObject({ state: "unconfigured", total: null });
    const text = JSON.stringify(b);
    expect(text).not.toMatch(/SECRET|missing|error|org_id|api\.mist\.com/);
    // a failing platform reads "stale" with the last counts, and still no error text
    await env.DB.prepare("UPDATE ops_device_status SET checked_at = '2000-01-01T00:00:00.000Z'").run();
    status = 401;
    const s2 = ((await (await get("/kiosk/api/devices", MGMT)).json()) as { sources: Array<Record<string, unknown>> }).sources.find((s) => s.kind === "mist")!;
    expect(s2).toMatchObject({ state: "stale", total: 2 });
    expect(JSON.stringify(s2)).not.toMatch(/401|credential/);
  });

  it("lists at most 200 down devices per platform by name, type, site and since; the rest only as a count", async () => {
    expect((await h.json("owner", "PUT", "/integrations/mist", { config: { api_base: "https://api.mist.com", org_id: ORG }, credentials: { token: "mist-token" } })).status).toBe(200);
    const devices = Array.from({ length: 230 }, (_, i) => ({ mac: `aa${String(i).padStart(10, "0")}`, serial: `SER${i}`, ip: `10.0.${i >> 8}.${i & 255}`, type: "ap", status: "disconnected", name: `ap-${i}` }));
    h.handlers.push((url) => {
      if (!url.startsWith("https://api.mist.com/")) return undefined;
      return Response.json(new URL(url).searchParams.get("page") === "1" ? devices : []);
    });
    const b = (await (await get("/kiosk/api/devices", MGMT)).json()) as { sources: Array<{ kind: string; down: Array<Record<string, unknown>>; down_more: number }> };
    const m = b.sources.find((s) => s.kind === "mist")!;
    expect(m.down).toHaveLength(200);
    expect(m.down_more).toBe(30);
    for (const d of m.down) expect(Object.keys(d).sort()).toEqual(["name", "since", "site", "type"]);
    expect(JSON.stringify(b)).not.toMatch(/SER[0-9]|aa0000|10\.0\./);
  });

  it("the page renders device names as text, never as markup", async () => {
    const html = await (await get("/kiosk", MGMT)).text();
    expect(html).toContain("Down now");
    expect(html).toMatch(/textContent/);
    expect(html).not.toMatch(/innerHTML|insertAdjacentHTML|outerHTML/);
  });
});
