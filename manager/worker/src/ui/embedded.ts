// Embedded admin UI (deploy.sh --embed-ui): serves the SPA from the Worker script when there is no ASSETS binding.
// Used by index.ts only for non-API paths. Pure function of (request, asset map, header rules) so tests can feed fixtures.
import type { Env } from "../env";
import { ApiError, errorResponse, notFound } from "../errors";

export interface EmbeddedAsset {
  readonly type: string;
  readonly b64: string;
  readonly etag: string;
}
export type EmbeddedAssets = Readonly<Record<string, EmbeddedAsset>>;
export type HeaderRules = readonly (readonly [string, string])[];

const IMMUTABLE = "public, max-age=31536000, immutable";

/** Decode once and validate; null = refuse (404). */
function cleanPath(rawPathname: string): string | null {
  let p: string;
  try {
    p = decodeURIComponent(rawPathname);
  } catch {
    return null;
  }
  if (p.includes("\0") || p.includes("\\") || !p.startsWith("/")) return null;
  const segs = p.split("/").slice(1);
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i]!;
    if (s === ".." || s === ".") return null;
    if (s === "" && i !== segs.length - 1) return null; // "//" inside the path
  }
  return p;
}

function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function etagMatches(header: string | null, etag: string): boolean {
  if (!header) return false;
  return header.split(",").some((t) => {
    const v = t.trim().replace(/^W\//, "");
    return v === "*" || v === etag;
  });
}

export function serveEmbedded(req: Request, assets: EmbeddedAssets, rules: HeaderRules): Response {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return errorResponse(new ApiError(405, "method_not_allowed", "method not allowed", {}, { allow: "GET, HEAD" }));
  }
  const p = cleanPath(new URL(req.url).pathname);
  if (p === null) return errorResponse(notFound("no such path"));
  const last = p.slice(p.lastIndexOf("/") + 1);
  let key: string;
  if (last.includes(".")) {
    key = p;
    if (!Object.prototype.hasOwnProperty.call(assets, key)) return errorResponse(notFound("no such path"));
  } else {
    key = "/index.html"; // "/", and every extension-less path, is a SPA route
  }
  const asset = assets[key];
  if (!asset) return errorResponse(notFound("no such path"));

  const h = new Headers();
  for (const [k, v] of rules) h.set(k, v);
  h.set("Content-Type", asset.type);
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Cache-Control", key.startsWith("/assets/") ? IMMUTABLE : "no-cache");
  h.set("ETag", asset.etag);
  if (etagMatches(req.headers.get("if-none-match"), asset.etag)) return new Response(null, { status: 304, headers: h });
  if (req.method === "HEAD") return new Response(null, { status: 200, headers: h });
  return new Response(b64ToBytes(asset.b64), { status: 200, headers: h });
}

/** Non-API fallthrough: the ASSETS binding when present, else the embedded copy, else null (caller answers 404 JSON). */
export function uiFallback(env: Env, req: Request, assets: EmbeddedAssets, rules: HeaderRules): Promise<Response> | Response | null {
  if (env.ASSETS) return env.ASSETS.fetch(req);
  if (Object.keys(assets).length > 0) return serveEmbedded(req, assets, rules);
  return null;
}
