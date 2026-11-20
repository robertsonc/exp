// CSRF defence in depth for /api/admin/v1/* state-changing methods (on top of the Access cookie + JWT check).
// A mutation must (a) carry the custom header X-Exp-Request (a cross-site form or "simple" request cannot set
// it), (b) use Content-Type application/json when it has a body (multipart/form-data for the release upload
// only), and (c) not be cross-site: an Origin header, if present, must equal the request's own origin, and
// Sec-Fetch-Site, if present, must be same-origin or none. Anything else is 403 csrf_refused.
import type { MiddlewareHandler } from "hono";
import type { AppBindings } from "../env";
import { ApiError } from "../errors";

export const CSRF_HEADER = "x-exp-request";
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const JSON_CT = /^application\/json\s*(;\s*charset=("?)utf-8\2\s*)?$/i;
const MULTIPART_CT = /^multipart\/form-data\s*;/i;
const MULTIPART_PATHS = new Set(["/api/admin/v1/releases/upload"]);
// the speedtest logo upload carries the raw image (admin.yaml uploadSpeedtestLogo): PNG, SVG or JPEG, nothing else
const LOGO_PATH = /^\/api\/admin\/v1\/sites\/[a-z0-9][a-z0-9-]{0,63}\/speedtest\/logo$/;

const refuse = (why: string): ApiError => new ApiError(403, "csrf_refused", `request refused: ${why}`);

export const csrfGuard: MiddlewareHandler<AppBindings> = async (c, next) => {
  const req = c.req.raw;
  if (!MUTATING.has(req.method)) return next();
  const url = new URL(req.url);
  const site = req.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin" && site !== "none") throw refuse("cross-site request");
  const origin = req.headers.get("origin");
  if (origin !== null && origin !== url.origin) throw refuse("cross-origin request");
  if (!req.headers.get(CSRF_HEADER)) throw refuse("missing X-Exp-Request header");
  const ct = req.headers.get("content-type");
  // "has a body" is decided from the headers: runtime request.body is non-null even for the empty POST a browser (or curl) sends
  // with Content-Length: 0, and the UI's body-less mutations (decommission, rotate, restart, enrol-token) must not be refused
  const len = req.headers.get("content-length");
  const hasBody = ct !== null || req.headers.has("transfer-encoding") || (len !== null && len !== "0");
  if (hasBody) {
    const path = url.pathname.replace(/\/+$/, "");
    if (LOGO_PATH.test(path)) {
      // the handler answers 415 for a wrong image type; here only "has a content type" and "not a form/JSON smuggle" matter
      if (!ct) throw refuse("the logo upload requires a content type");
    } else if (MULTIPART_PATHS.has(path)) {
      if (!ct || !MULTIPART_CT.test(ct)) throw refuse("this endpoint requires multipart/form-data");
    } else if (!ct || !JSON_CT.test(ct.trim())) throw refuse("a JSON content type is required");
  }
  return next();
};
