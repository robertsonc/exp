// Same-origin API client. The cookie is sent automatically; non-GET requests carry X-Exp-CSRF.
import { safeNext } from "./util.js";

let csrf = "";
export let session = null;

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function setSession(s) {
  session = s;
  csrf = s && typeof s.csrf === "string" ? s.csrf : "";
}

export const isOperator = () => !!session && (session.role === "operator" || session.role === "admin");

export function toLogin() {
  const here = location.pathname + location.search;
  location.replace("/login?next=" + encodeURIComponent(safeNext(here)));
}

async function parse(r) {
  let doc = null;
  try {
    doc = await r.json();
  } catch (e) {
    doc = null;
  }
  return doc;
}

export async function api(path, opts) {
  const o = opts || {};
  const method = o.method || "GET";
  const headers = { Accept: "application/json" };
  if (method !== "GET") headers["X-Exp-CSRF"] = csrf;
  let body;
  if (o.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(o.json);
  }
  let r;
  try {
    r = await fetch(path, { method, headers, body, credentials: "same-origin", cache: "no-store", signal: o.signal });
  } catch (e) {
    if (e && e.name === "AbortError") throw e;
    throw new ApiError(0, "network", "The dashboard could not be reached.");
  }
  if (r.status === 401 && !o.noRedirect) {
    toLogin();
    throw new ApiError(401, "unauthorized", "Signed out.");
  }
  if (r.status === 204) return null;
  const doc = await parse(r);
  if (!r.ok) {
    const e = doc && doc.error ? doc.error : {};
    throw new ApiError(r.status, String(e.code || "error"), String(e.message || "Request failed (" + r.status + ")"));
  }
  return doc;
}

export async function loadSession() {
  const r = await fetch("/auth/session", { credentials: "same-origin", cache: "no-store" });
  if (r.status === 401) return null;
  if (!r.ok) throw new ApiError(r.status, "session", "Could not load the session.");
  const doc = await r.json();
  setSession(doc);
  return doc;
}

export function qs(params) {
  const p = new URLSearchParams();
  for (const k of Object.keys(params)) {
    const v = params[k];
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? "?" + s : "";
}
