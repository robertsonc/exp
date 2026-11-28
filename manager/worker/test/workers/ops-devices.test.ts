// Ops device status board: GET /ops/devices counts Mist and Central devices with read-only polls, a shared 60 s
// cache, last-good counts on failure, and never a credential in a response. Vendor APIs are faked by fetch handlers.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CENTRAL_TOKEN_URL, resetCentralTokens } from "../../src/ops/devices";
import { setClock } from "../../src/util/time";
import { harness, type Harness } from "../admin-harness";
import { resetDb } from "../helpers";

const ORG = "6f1d2c3b-aaaa-4bbb-8ccc-0123456789ab";
const MIST_TOKEN = "mist-token-SECRET-value-123";
const CENTRAL_ID = "central-client-id-1";
const CENTRAL_SECRET = "central-client-SECRET-456";
const CENTRAL = "https://us1.api.central.arubanetworks.com";

interface Src { kind: string; state: string; missing: string[]; total: number | null; online: number | null; offline: number | null; by_type: Record<string, { total: number; online: number }>; counts_at: string | null; error: string | null }
interface Board { as_of: string; ttl_s: number; sources: Src[] }

let h: Harness;
let t = Date.parse("2026-11-28T12:00:00.000Z");
const advance = (s: number) => {
  t += s * 1000;
};

beforeEach(async () => {
  await resetDb();
  resetCentralTokens();
  t = Date.parse("2026-11-28T12:00:00.000Z");
  setClock(() => t);
  h = await harness();
});
afterEach(() => {
  setClock(null);
  h.restore();
});

const board = async (): Promise<Board> => {
  const r = await h.json<Board>("viewer", "GET", "/ops/devices");
  expect(r.status).toBe(200);
  expect(JSON.stringify(r.body)).not.toMatch(/SECRET/);
  return r.body;
};
const src = (b: Board, kind: string): Src => b.sources.find((s) => s.kind === kind)!;
const vendorCalls = () => h.calls.filter((c) => /mist\.com|arubanetworks\.com|cloud\.hpe\.com/.test(c.url));

const mistDevices = (n: number, online: number) =>
  Array.from({ length: n }, (_, i) => ({ mac: `5c5b35${String(i).padStart(6, "0")}`, type: (["ap", "switch", "gateway"] as const)[i % 3], status: i < online ? "connected" : "disconnected", name: `d${i}` }));

/** Mist fake: serves `devices` in pages of at most `cap` (the API may cap below the limit we ask for). */
function serveMist(devices: () => unknown[], opts: { cap?: number; status?: () => number; header?: boolean } = {}) {
  h.handlers.push((url, init) => {
    if (!url.startsWith("https://api.mist.com/")) return undefined;
    const u = new URL(url);
    expect(u.pathname).toBe(`/api/v1/orgs/${ORG}/stats/devices`);
    expect(u.searchParams.get("type")).toBe("all");
    expect(u.searchParams.get("status")).toBe("all");
    expect(new Headers(init?.headers).get("authorization")).toBe(`Token ${MIST_TOKEN}`);
    expect(init?.method ?? "GET").toBe("GET");
    const st = opts.status?.() ?? 200;
    if (st !== 200) return new Response("{}", { status: st });
    const per = Math.min(Number(u.searchParams.get("limit")), opts.cap ?? 1000);
    const page = Number(u.searchParams.get("page"));
    const all = devices();
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (opts.header) headers["x-page-total"] = String(all.length);
    return new Response(JSON.stringify(all.slice((page - 1) * per, page * per)), { headers });
  });
}

async function configureMist(over: Record<string, unknown> = {}) {
  const r = await h.json("owner", "PUT", "/integrations/mist", { config: { api_base: "https://api.mist.com", org_id: ORG, ...over }, credentials: { token: MIST_TOKEN } });
  expect(r.status).toBe(200);
}

async function configureCentral() {
  const r = await h.json("owner", "PUT", "/integrations/central", { config: { api_base: CENTRAL }, credentials: { client_id: CENTRAL_ID, client_secret: CENTRAL_SECRET } });
  expect(r.status).toBe(200);
}

describe("ops board: connectors", () => {
  it("reports both platforms as unconfigured, with what is missing, and calls no vendor", async () => {
    const b = await board();
    expect(b.ttl_s).toBe(60);
    expect(src(b, "mist")).toMatchObject({ state: "unconfigured", missing: ["api_base", "org_id", "token"], total: null });
    expect(src(b, "central")).toMatchObject({ state: "unconfigured", missing: ["api_base", "client_id", "client_secret"], total: null });
    expect(vendorCalls()).toHaveLength(0);
  });

  it("a Mist connector without org_id (runner-only) stays unconfigured for the board", async () => {
    expect((await h.json("owner", "PUT", "/integrations/mist", { config: { api_base: "https://api.mist.com" }, credentials: { token: MIST_TOKEN } })).status).toBe(200);
    expect(src(await board(), "mist")).toMatchObject({ state: "unconfigured", missing: ["org_id"] });
  });

  it("validates the central connector and keeps its credentials write-only", async () => {
    const put = (body: unknown) => h.json("owner", "PUT", "/integrations/central", body);
    expect((await put({ config: { api_base: "https://evil.example.com" } })).status).toBe(400);
    expect((await put({ config: { api_base: "http://us1.api.central.arubanetworks.com" } })).status).toBe(400);
    expect((await put({ config: { api_base: CENTRAL }, credentials: { client_id: CENTRAL_ID } })).status).toBe(400);
    expect((await put({ config: { api_base: CENTRAL }, credentials: { api_key: "x" } })).status).toBe(400);
    expect((await h.json("owner", "PUT", "/integrations/mist", { config: { api_base: "https://api.mist.com", org_id: "not-a-uuid" } })).status).toBe(400);
    expect((await h.json("owner", "PUT", "/integrations/mist", { config: {}, credentials: { client_secret: "x" } })).status).toBe(400);
    expect((await h.json("admin", "PUT", "/integrations/central", { config: { api_base: CENTRAL } })).status).toBe(403);
    await configureCentral();
    const g = await h.json<{ kind: string; config: Record<string, unknown>; credentials: { set: boolean } }>("viewer", "GET", "/integrations/central");
    expect(g.body).toMatchObject({ kind: "central", config: { api_base: CENTRAL }, credentials: { set: true } });
    expect(JSON.stringify(g.body)).not.toMatch(/SECRET|central-client-id/);
  });
});

describe("ops board: Mist", () => {
  it("counts online and offline devices by type, across pages, even when the API caps the page size", async () => {
    await configureMist();
    serveMist(() => mistDevices(5, 3), { cap: 2 });
    const s = src(await board(), "mist");
    expect(s).toMatchObject({ state: "ok", total: 5, online: 3, offline: 2, error: null, counts_at: "2026-11-28T12:00:00.000Z" });
    expect(s.by_type).toEqual({ ap: { total: 2, online: 1 }, switch: { total: 2, online: 1 }, gateway: { total: 1, online: 1 } });
    expect(vendorCalls()).toHaveLength(3);
  });

  it("stops at the advertised X-Page-Total without an extra request", async () => {
    await configureMist({ api_base: "https://api.mist.com/api/v1/" }); // the runner spelling is accepted too
    serveMist(() => mistDevices(4, 4), { header: true });
    expect(src(await board(), "mist")).toMatchObject({ state: "ok", total: 4, online: 4, offline: 0 });
    expect(vendorCalls()).toHaveLength(1);
  });

  it("polls at most once per 60 s however many boards are open", async () => {
    await configureMist();
    serveMist(() => mistDevices(2, 1), { header: true });
    await Promise.all([board(), board(), board()]);
    await board();
    expect(vendorCalls()).toHaveLength(1);
    advance(61);
    await board();
    expect(vendorCalls()).toHaveLength(2);
  });

  it("keeps the last good counts when a poll fails, and says why without leaking the token", async () => {
    await configureMist();
    let status = 200;
    serveMist(() => mistDevices(3, 2), { header: true, status: () => status });
    await board();
    status = 401;
    advance(61);
    const s = src(await board(), "mist");
    expect(s).toMatchObject({ state: "error", total: 3, online: 2, offline: 1, counts_at: "2026-11-28T12:00:00.000Z" });
    expect(s.error).toMatch(/refused the credentials \(HTTP 401\)/);
    status = 200;
    advance(61);
    expect(src(await board(), "mist")).toMatchObject({ state: "ok", error: null, counts_at: "2026-11-28T12:02:02.000Z" });
  });

  it("a changed connector discards the cached counts and polls at once", async () => {
    await configureMist();
    serveMist(() => mistDevices(3, 3), { header: true });
    await board();
    await configureMist(); // new credential version
    await board();
    expect(vendorCalls()).toHaveLength(2);
  });

  it("refuses to follow redirects with the token", async () => {
    await configureMist();
    h.handlers.push((url) => (url.startsWith("https://api.mist.com/") ? new Response(null, { status: 302, headers: { location: "https://elsewhere.example/" } }) : undefined));
    const s = src(await board(), "mist");
    expect(s).toMatchObject({ state: "error", total: null });
    expect(s.error).toMatch(/redirect/);
    expect(h.calls.some((c) => c.url.startsWith("https://elsewhere.example"))).toBe(false);
  });
});

describe("ops board: Central", () => {
  function serveCentral(opts: { devicesStatus?: () => number } = {}) {
    let tokens = 0;
    h.handlers.push(async (url, init) => {
      if (url === CENTRAL_TOKEN_URL) {
        expect(init?.method).toBe("POST");
        expect(new Headers(init?.headers).get("content-type")).toBe("application/x-www-form-urlencoded");
        const f = new URLSearchParams(String(init?.body));
        expect(Object.fromEntries(f)).toEqual({ grant_type: "client_credentials", client_id: CENTRAL_ID, client_secret: CENTRAL_SECRET });
        tokens++;
        return Response.json({ access_token: `tok-${tokens}`, token_type: "Bearer", expires_in: 7199 });
      }
      if (!url.startsWith(`${CENTRAL}/`)) return undefined;
      const u = new URL(url);
      expect(u.pathname).toBe("/network-monitoring/v1/devices");
      expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer tok-${tokens}`);
      const st = opts.devicesStatus?.() ?? 200;
      if (st !== 200) return new Response("{}", { status: st });
      if (!u.searchParams.get("next"))
        return Response.json({ items: [{ serialNumber: "A1", deviceType: "ACCESS_POINT", status: "ONLINE" }, { serialNumber: "S1", deviceType: "SWITCH", status: "OFFLINE" }], count: 2, total: 3, next: "2" });
      expect(u.searchParams.get("next")).toBe("2");
      return Response.json({ items: [{ serialNumber: "G1", deviceType: "GATEWAY", status: "ONLINE" }], count: 1, total: 3, next: null });
    });
    return { tokens: () => tokens };
  }

  it("gets a client-credentials token, follows the next cursor and counts ONLINE / OFFLINE", async () => {
    await configureCentral();
    const f = serveCentral();
    const s = src(await board(), "central");
    expect(s).toMatchObject({ state: "ok", total: 3, online: 2, offline: 1 });
    expect(s.by_type).toEqual({ ap: { total: 1, online: 1 }, switch: { total: 1, online: 0 }, gateway: { total: 1, online: 1 } });
    advance(61);
    await board();
    expect(f.tokens()).toBe(1); // the 2 h token is reused
  });

  it("gets a new token once when the cached one is refused", async () => {
    await configureCentral();
    let n = 0;
    const f = serveCentral({ devicesStatus: () => (n++ === 0 ? 401 : 200) });
    expect(src(await board(), "central")).toMatchObject({ state: "ok", total: 3 });
    expect(f.tokens()).toBe(2);
  });

  it("the owner's integration test runs the same read-only poll", async () => {
    await configureCentral();
    serveCentral();
    const r = await h.json<{ ok: boolean; detail: string; inventory_count: number | null }>("owner", "POST", "/integrations/central/test");
    expect(r.body).toEqual({ ok: true, detail: "3 devices (2 online, 1 offline)", inventory_count: 3 });
  });

  it("only ever sends GETs to the Central API", async () => {
    await configureCentral();
    serveCentral();
    await board();
    const api = h.calls.filter((c) => c.url.startsWith(CENTRAL));
    expect(api.length).toBe(2);
    expect(api.every((c) => (c.init?.method ?? "GET") === "GET")).toBe(true);
  });
});
