import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../.generated/ui-assets", () => ({
  UI_ASSETS: Object.freeze({
    "/index.html": { type: "text/html; charset=utf-8", b64: btoa("<!doctype html><title>exp</title>"), etag: '"idx"' },
    "/assets/app-abc.js": { type: "text/javascript; charset=utf-8", b64: btoa("console.log(1)"), etag: '"js1"' },
    "/robots.txt": { type: "text/plain; charset=utf-8", b64: btoa("User-agent: *"), etag: '"rb"' },
  }),
  UI_HEADERS: Object.freeze([
    ["Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"],
    ["X-Frame-Options", "DENY"],
    ["Referrer-Policy", "no-referrer"],
    ["Permissions-Policy", "camera=(), microphone=(), geolocation=()"],
  ]),
}));

const { app } = await import("../../src/index");
const get = (path: string, init: RequestInit = {}, e: unknown = { ...env, ASSETS: undefined }) => app.fetch(new Request(`https://m.test${path}`, init), e as never);

describe("embedded UI (no ASSETS binding)", () => {
  for (const p of ["/", "/fleet", "/hosts/h_x"]) {
    it(`serves index.html for ${p}`, async () => {
      const r = await get(p);
      expect(r.status).toBe(200);
      expect(r.headers.get("content-type")).toMatch(/^text\/html/);
      expect(r.headers.get("cache-control")).toBe("no-cache");
      expect(r.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
      expect(r.headers.get("x-frame-options")).toBe("DENY");
      expect(r.headers.get("x-content-type-options")).toBe("nosniff");
      expect(r.headers.get("permissions-policy")).toContain("camera=()");
      expect(await r.text()).toContain("<title>exp</title>");
    });
  }

  it("serves hashed assets as immutable JS", async () => {
    const r = await get("/assets/app-abc.js");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toMatch(/javascript/);
    expect(r.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(await r.text()).toBe("console.log(1)");
  });

  it("serves other known files with no-cache", async () => {
    const r = await get("/robots.txt");
    expect(r.headers.get("cache-control")).toBe("no-cache");
  });

  it("404s a missing asset instead of falling back to index.html", async () => {
    for (const p of ["/assets/missing.js", "/favicon.ico", "/assets/"]) {
      const r = p === "/assets/" ? await get(p) : await get(p);
      if (p === "/assets/") {
        expect(r.status).toBe(200); // extension-less path is an SPA route
        continue;
      }
      expect(r.status).toBe(404);
      expect(r.headers.get("content-type")).toMatch(/json/);
      expect(((await r.json()) as { error: { code: string } }).error.code).toBe("not_found");
    }
  });

  it("refuses traversal and malformed paths", async () => {
    for (const p of ["/..%2f..%2fetc", "/assets/..%2findex.html", "/%00", "//assets", "/a%5cb", "/%zz", "/assets/%2e%2e/index.html"]) {
      const r = await get(p);
      expect(r.status, p).toBe(404);
      expect(r.headers.get("content-type"), p).toMatch(/json/);
    }
  });

  it("HEAD has the headers and an empty body", async () => {
    const r = await get("/assets/app-abc.js", { method: "HEAD" });
    expect(r.status).toBe(200);
    expect(r.headers.get("etag")).toBe('"js1"');
    expect(r.headers.get("content-security-policy")).toContain("frame-ancestors");
    expect(await r.text()).toBe("");
  });

  it("answers 304 for a matching If-None-Match", async () => {
    const r = await get("/", { headers: { "If-None-Match": '"idx"' } });
    expect(r.status).toBe(304);
    expect(r.headers.get("etag")).toBe('"idx"');
    expect(await r.text()).toBe("");
    expect((await get("/", { headers: { "If-None-Match": '"other"' } })).status).toBe(200);
  });

  it("405s other methods with the error envelope", async () => {
    const r = await get("/", { method: "POST", body: "x" });
    expect(r.status).toBe(405);
    expect(r.headers.get("allow")).toBe("GET, HEAD");
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe("method_not_allowed");
  });

  it("does not shadow the API, /install.sh or /healthz", async () => {
    expect((await get("/api/admin/v1/me")).status).toBe(401);
    expect((await get("/api/nope")).status).toBe(404);
    expect((await get("/api/nope")).headers.get("content-type")).toMatch(/json/);
    expect(await (await get("/healthz")).text()).toBe("ok");
    expect((await get("/install.sh")).headers.get("content-type")).toMatch(/shellscript/);
  });

  it("never uses the embedded copy when an ASSETS binding exists", async () => {
    const seen: string[] = [];
    const assets = { fetch: async (r: Request) => (seen.push(new URL(r.url).pathname), new Response("from-assets", { status: 200 })) };
    const r = await get("/fleet", {}, { ...env, ASSETS: assets });
    expect(await r.text()).toBe("from-assets");
    expect(seen).toEqual(["/fleet"]);
  });
});

