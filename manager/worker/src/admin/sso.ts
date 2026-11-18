// SSO handoff (01-contracts.md section 12): the manager mints a 120-second HS256 JWT for a dashboard and
// returns a self-contained HTML page whose auto-submitting form POSTs it to <dashboard>/auth/sso. The token
// is never placed in a URL. The page is CSP-safe: no inline handlers; the one inline script is allowed by
// its sha256 only, and form-action is pinned to the dashboard origin.
import { auditStmt } from "../audit/audit";
import { parseJson } from "../compile/load";
import { loadWorld } from "../compile/load";
import { SSO_KIND } from "../compile/wiring";
import type { Env, Role } from "../env";
import { DEFAULT_ORG } from "../env";
import { ApiError, ConfigError, unavailable } from "../errors";
import { mgmtIpOf } from "../fleet/query";
import { getSecretByOwner, readSecret } from "../secrets/store";
import { b64ToBytes, bytesToB64url, utf8 } from "../util/encoding";
import { nowMs } from "../util/time";
import { dashboardSlug } from "./read";

export const SSO_TTL_S = 120;
const SCRIPT = 'document.getElementById("sso").submit();';

export const dashboardRoleOf = (r: Role): "viewer" | "operator" | "admin" => (r === "owner" || r === "admin" ? "admin" : r === "operator" ? "operator" : "viewer");

const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/'/g, "&#39;");

async function hmacSha256(key: Uint8Array, data: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, utf8(data)));
}

export async function mintSsoToken(secretB64: string, claims: Record<string, unknown>): Promise<string> {
  let key: Uint8Array;
  try {
    key = b64ToBytes(secretB64);
  } catch {
    throw new ApiError(409, "conflict", "the dashboard sso secret is malformed");
  }
  const enc = (o: unknown): string => bytesToB64url(utf8(JSON.stringify(o)));
  const head = `${enc({ alg: "HS256", typ: "JWT" })}.${enc(claims)}`;
  return `${head}.${bytesToB64url(await hmacSha256(key, head))}`;
}

async function sha256B64(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(s)));
  let t = "";
  for (const b of d) t += String.fromCharCode(b);
  return btoa(t);
}

export interface SsoPage {
  html: string;
  csp: string;
}

export async function buildSsoPage(env: Env, admin: { email: string; role: Role }, ip: string | null, dashboardId: string): Promise<SsoPage> {
  const dash = await dashboardSlug(env, dashboardId);
  const row = await env.DB.prepare("SELECT c.config_json, c.facts_json, h.facts_json AS host_facts FROM components c JOIN hosts h ON h.host_id = c.host_id WHERE c.component_id = ?1")
    .bind(dash.component_id)
    .first<{ config_json: string; facts_json: string; host_facts: string }>();
  if (!row) throw new ApiError(404, "not_found", "no such dashboard");
  const cfg = parseJson<{ url?: string }>(row.config_json, {});
  const reported = parseJson<{ facts?: { url?: string } }>(row.facts_json, {}).facts?.url;
  const mgmt = mgmtIpOf(row.host_facts);
  const base = cfg.url ?? reported ?? (mgmt ? `https://${mgmt}` : null);
  if (!base) throw new ApiError(409, "dashboard_url_unknown", "the dashboard has no known URL yet (it has not reported one and has no management address)");
  let target: URL;
  try {
    target = new URL(`${base.replace(/\/+$/, "")}/auth/sso`);
  } catch {
    throw new ApiError(409, "dashboard_url_unknown", "the dashboard URL is not valid");
  }
  if (target.protocol !== "https:" || target.username || target.password) throw new ApiError(409, "dashboard_url_unknown", "the dashboard URL must be https");

  let sec = await getSecretByOwner(env, dash.component_id, SSO_KIND);
  if (!sec) {
    await loadWorld(env); // provisions any missing generated secrets
    sec = await getSecretByOwner(env, dash.component_id, SSO_KIND);
  }
  if (!sec) throw new ApiError(409, "conflict", "the dashboard sso secret is not provisioned yet");
  let secret: string;
  try {
    secret = await readSecret(env, sec);
  } catch (e) {
    if (e instanceof ConfigError) throw unavailable(e.message);
    throw e;
  }
  const iat = Math.floor(nowMs() / 1000);
  const role = dashboardRoleOf(admin.role);
  const token = await mintSsoToken(secret, {
    iss: `exp-manager:${DEFAULT_ORG}`,
    aud: dash.slug,
    sub: admin.email,
    name: admin.email,
    role,
    iat,
    exp: iat + SSO_TTL_S,
    jti: crypto.randomUUID(),
  });
  await auditStmt(env.DB, { actor: admin.email, action: "dashboard.sso", resource: `dashboard:${dash.slug}`, details: { role, ttl_s: SSO_TTL_S }, ip }).run();
  const html =
    `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<meta name="referrer" content="no-referrer"><title>Opening dashboard</title></head><body>` +
    `<p>Opening dashboard ${esc(dash.slug)}&hellip;</p>` +
    `<form id="sso" method="post" action="${esc(target.toString())}"><input type="hidden" name="token" value="${esc(token)}">` +
    `<noscript><button type="submit">Continue to the dashboard</button></noscript></form><script>${SCRIPT}</script></body></html>\n`;
  const csp = `default-src 'none'; script-src 'sha256-${await sha256B64(SCRIPT)}'; form-action ${target.origin}; base-uri 'none'; frame-ancestors 'none'`;
  return { html, csp };
}
