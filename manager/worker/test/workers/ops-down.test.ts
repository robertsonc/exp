// Ops board: WHICH devices are down (name, type, site, down since), so the NOC and the kiosk know what to go and look
// at. Only down devices are stored and shown; a device's MAC / serial never reaches D1 or a response (a keyed hash
// carries "down since" from one poll to the next). Vendor APIs are faked by fetch handlers.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DOWN_STORE_MAX, label, mergeDown, resetCentralTokens } from "../../src/ops/devices";
import { setClock } from "../../src/util/time";
import { harness, type Harness } from "../admin-harness";
import { env, resetDb } from "../helpers";

const ORG = "6f1d2c3b-aaaa-4bbb-8ccc-0123456789ab";
const SITE_A = "11111111-1111-4111-8111-111111111111";
const SITE_B = "22222222-2222-4222-8222-222222222222";
const CENTRAL = "https://us1.api.central.arubanetworks.com";
const T0 = Date.parse("2026-11-28T12:00:00.000Z");

interface Down { name: string | null; type: string; site: string | null; since: string }
interface Src { kind: string; state: string; offline: number | null; down: Down[]; down_more: number }

let h: Harness;
let t = T0;
let mistDevs: Array<Record<string, unknown>> = [];
let sitesStatus = 200;
let siteCalls = 0;

beforeEach(async () => {
  await resetDb();
  resetCentralTokens();
  t = T0;
  setClock(() => t);
  h = await harness();
  sitesStatus = 200;
  siteCalls = 0;
  h.handlers.push((url) => {
    if (!url.startsWith("https://api.mist.com/")) return undefined;
    const u = new URL(url);
    if (u.pathname === `/api/v1/orgs/${ORG}/sites`) {
      siteCalls++;
      if (sitesStatus !== 200) return new Response("{}", { status: sitesStatus });
      return Response.json([{ id: SITE_A, name: "Hall B" }, { id: SITE_B, name: "Main\nstage" }]);
    }
    expect(u.pathname).toBe(`/api/v1/orgs/${ORG}/stats/devices`);
    return Response.json(Number(u.searchParams.get("page")) === 1 ? mistDevs : []);
  });
});
afterEach(() => {
  setClock(null);
  h.restore();
});

const mist = async (): Promise<Src> => {
  const r = await h.json<{ sources: Src[] }>("viewer", "GET", "/ops/devices");
  expect(r.status).toBe(200);
  return r.body.sources.find((s) => s.kind === "mist")!;
};
const tick = () => {
  t += 61_000;
};
async function configureMist() {
  expect((await h.json("owner", "PUT", "/integrations/mist", { config: { api_base: "https://api.mist.com", org_id: ORG }, credentials: { token: "mist-token-x" } })).status).toBe(200);
}
const dev = (mac: string, status: string, extra: Record<string, unknown> = {}) => ({ mac, type: "ap", status, ...extra });

describe("ops board: devices that are down", () => {
  it("lists only the down devices with name, type, site name and since; never a MAC, serial or address", async () => {
    await configureMist();
    mistDevs = [
      dev("aa0000000001", "connected", { name: "ap-up", site_id: SITE_A }),
      dev("aa0000000002", "disconnected", { name: "ap-hall-b-117", site_id: SITE_A, serial: "A12345", ip: "10.9.8.7", last_seen: T0 / 1000 - 600 }),
      { mac: "aa0000000003", type: "switch", status: "disconnected", hostname: "sw-stage-left", site_id: SITE_B, serial: "SW999" },
    ];
    const s = await mist();
    expect(s).toMatchObject({ state: "ok", offline: 2, down_more: 0 });
    expect(s.down).toEqual([
      { name: "ap-hall-b-117", type: "ap", site: "Hall B", since: "2026-11-28T11:50:00.000Z" }, // Mist's last_seen, 10 min ago
      { name: "sw-stage-left", type: "switch", site: "Main stage", since: "2026-11-28T12:00:00.000Z" }, // first seen down now; hostname fallback; newline flattened
    ]);
    const stored = await env.DB.prepare("SELECT down_json FROM ops_device_status WHERE kind = 'mist'").first<{ down_json: string }>();
    for (const text of [JSON.stringify(s), stored!.down_json]) expect(text).not.toMatch(/aa00000000|A12345|SW999|10\.9\.8\.7|ap-up/);
    expect(siteCalls).toBe(1);
  });

  it("keeps 'down since' across polls, drops a device that came back, and restarts the clock when it goes down again", async () => {
    await configureMist();
    mistDevs = [dev("aa01", "disconnected", { name: "ap-1" }), dev("aa02", "disconnected", { name: "ap-2" })];
    expect((await mist()).down.map((d) => d.since)).toEqual(["2026-11-28T12:00:00.000Z", "2026-11-28T12:00:00.000Z"]);
    tick();
    mistDevs = [dev("aa01", "disconnected", { name: "ap-1 renamed" }), dev("aa02", "connected", { name: "ap-2" })];
    expect((await mist()).down).toEqual([{ name: "ap-1 renamed", type: "ap", site: null, since: "2026-11-28T12:00:00.000Z" }]);
    tick();
    mistDevs = [dev("aa01", "disconnected", { name: "ap-1 renamed" }), dev("aa02", "disconnected", { name: "ap-2" })];
    expect((await mist()).down).toEqual([
      { name: "ap-1 renamed", type: "ap", site: null, since: "2026-11-28T12:00:00.000Z" },
      { name: "ap-2", type: "ap", site: null, since: "2026-11-28T12:02:02.000Z" },
    ]);
  });

  it("a failed site lookup leaves the site blank and does not fail the poll; no down device means no site lookup", async () => {
    await configureMist();
    sitesStatus = 500;
    mistDevs = [dev("aa01", "disconnected", { name: "ap-1", site_id: SITE_A })];
    expect(await mist()).toMatchObject({ state: "ok", down: [{ name: "ap-1", site: null }] });
    tick();
    mistDevs = [dev("aa01", "connected", { name: "ap-1", site_id: SITE_A })];
    const calls = siteCalls;
    expect((await mist()).down).toEqual([]);
    expect(siteCalls).toBe(calls);
  });

  it("a failing poll keeps the last good list; a connector change empties it", async () => {
    await configureMist();
    mistDevs = [dev("aa01", "disconnected", { name: "ap-1" })];
    await mist();
    tick();
    h.handlers.unshift((url) => (url.includes("/stats/devices") ? new Response("{}", { status: 503 }) : undefined));
    expect(await mist()).toMatchObject({ state: "error", down: [{ name: "ap-1" }] });
    h.handlers.shift();
    expect((await h.json("owner", "PUT", "/integrations/mist", { config: { api_base: "https://api.eu.mist.com", org_id: ORG } })).status).toBe(200);
    const s = await mist();
    expect(s.down).toEqual([]);
  });

  it("Central: reads deviceName / siteName (or name / site_name) and lists an unnamed device instead of dropping it", async () => {
    expect((await h.json("owner", "PUT", "/integrations/central", { config: { api_base: CENTRAL }, credentials: { client_id: "cid", client_secret: "csecret" } })).status).toBe(200);
    h.handlers.push((url) => {
      if (url.includes("sso.common.cloud.hpe.com")) return Response.json({ access_token: "tok", expires_in: 7199 });
      if (!url.startsWith(`${CENTRAL}/`)) return undefined;
      return Response.json({
        items: [
          { serialNumber: "CN1", deviceType: "ACCESS_POINT", status: "ONLINE", deviceName: "ap-ok" },
          { serialNumber: "CN2", deviceType: "SWITCH", status: "OFFLINE", deviceName: "sw-press", siteName: "Press centre" },
          { serialNumber: "CN3", deviceType: "GATEWAY", status: "OFFLINE", name: "gw-2", site_name: "Hall B" },
          { serialNumber: "CN4", deviceType: "ACCESS_POINT", status: "OFFLINE" },
        ],
        next: null,
      });
    });
    const r = await h.json<{ sources: Src[] }>("viewer", "GET", "/ops/devices");
    const c = r.body.sources.find((s) => s.kind === "central")!;
    expect(c.offline).toBe(3);
    expect(c.down.map((d) => [d.name, d.type, d.site])).toEqual([[null, "ap", null], ["gw-2", "gateway", "Hall B"], ["sw-press", "switch", "Press centre"]].sort((a, b) => String(a[0] ?? "￿").localeCompare(String(b[0] ?? "￿"))));
    expect(JSON.stringify(c)).not.toMatch(/CN[0-9]|ap-ok/);
  });
});

describe("ops board: down list rules", () => {
  it("labels are text only, one line, at most 64 characters", () => {
    expect(label("  ap\u0000-1\n\t x ")).toBe("ap -1 x");
    expect(label("a".repeat(80))).toHaveLength(64);
    expect(label(42)).toBeNull();
    expect(label(" \n ")).toBeNull();
  });

  it("orders longest down first and caps the stored list, counting the rest in down_more", async () => {
    const down = Array.from({ length: DOWN_STORE_MAX + 20 }, (_, i) => ({ key: `k${i}`, name: `d${i}`, type: "ap" as const, site: null, lastSeenMs: T0 - i * 1000 }));
    const out = await mergeDown("mist", null, down, T0);
    expect(out).toHaveLength(DOWN_STORE_MAX);
    expect(out[0]!.n).toBe(`d${DOWN_STORE_MAX + 19}`);
    expect(out.every((d) => /^[0-9a-f]{24}$/.test(d.k))).toBe(true);
    // a vendor last_seen in the future is ignored (now is used)
    expect((await mergeDown("mist", null, [{ key: "x", name: "x", type: "ap", site: null, lastSeenMs: T0 + 60_000 }], T0))[0]!.since).toBe("2026-11-28T12:00:00.000Z");
  });
});
