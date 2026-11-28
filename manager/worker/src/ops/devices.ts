// Ops device status board: total / online / offline devices in Juniper Mist and HPE Aruba Networking Central
// (GET /api/admin/v1/ops/devices). READ-ONLY against both platforms: the manager only ever issues GETs to the
// vendor APIs (plus Central's OAuth token request), never a write.
//
// Polling is on demand and shared: every open board reads ops_device_status, and at most one request per platform
// per TTL wins an atomic claim on the row and polls the vendor. Stored: the counts and the devices that are DOWN (name,
// type, site, down since; capped at DOWN_STORE_MAX), never the whole inventory, a serial, a MAC, an address or a
// credential. A device's identity is kept only as a keyed hash, so "down since" survives from poll to poll. A failed poll
// keeps the last good counts and list and says why it failed, so a wall screen degrades to "counts from 4 min ago, Mist
// answered 401" instead of going blank.
//
// Vendor facts this relies on:
//   Central  (verified, developer.arubanetworks.com/new-central, Nov 2026):
//     token   POST https://sso.common.cloud.hpe.com/as/token.oauth2, form grant_type=client_credentials, 2 h lifetime,
//             no refresh token; devices GET {base}/network-monitoring/v1/devices?limit<=1000&next=<cursor>,
//             body {items[], count, total?, next|null}; items[].status ONLINE|OFFLINE, items[].deviceType
//             ACCESS_POINT|SWITCH|GATEWAY. Rate limit 10 requests/s per Central account.
//             NOT verified (the reference page was unreachable, Nov 2026): the device name and site fields. Read as
//             deviceName | name and siteName | site_name (the spelling of Central's other monitoring APIs); a device
//             without them is listed as "(unnamed)" / no site, never dropped.
//   Mist     (verified against Juniper's Mist OpenAPI, mistapi 0.64.1, the reference CI pins): listOrgDevicesStats
//             GET {base}/api/v1/orgs/{org_id}/stats/devices?type=all&status=all&limit&page (limit default 100, no
//             documented maximum: we ask 1000 and cope with a smaller cap), body = JSON array of stats_ap | stats_switch |
//             stats_gateway discriminated by `type`, `status` "connected" when up; status=all is sent explicitly because
//             the OAS documents no default. X-Page-Total is used when sent (not in the OAS). Authorization: Token <token>.
//             Down devices: name (switches/gateways may only carry hostname), site_id, last_seen (epoch seconds). Site
//             names: listOrgSites GET {base}/api/v1/orgs/{org_id}/sites?limit=1000 -> [{id, name}], fetched only when a
//             device is down; a failure there leaves the site blank, it never fails the poll.
import { parseJson } from "../compile/load";
import type { Env } from "../env";
import { getSecretRow, readSecret } from "../secrets/store";
import { sha256Hex } from "../util/encoding";
import { isoAt, nowMs } from "../util/time";

export type OpsKind = "mist" | "central";
export const OPS_KINDS: readonly OpsKind[] = ["mist", "central"];
export const OPS_TTL_S = 60;
const REQUEST_TIMEOUT_MS = 8000;
/** Worker subrequest budget: a poll never issues more than this many vendor requests. */
const MAX_PAGES = 40;
const PAGE_LIMIT = 1000;
export const CENTRAL_TOKEN_URL = "https://sso.common.cloud.hpe.com/as/token.oauth2";
/** New Central API gateways (us1, de2, gb1, ... and cn1.api.central.arubanetworks.com.cn). */
export const CENTRAL_HOST_RE = /^[a-z0-9-]{1,32}\.api\.central\.arubanetworks\.com(\.cn)?$/;
export const MIST_ORG_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const LABEL: Record<OpsKind, string> = { mist: "Juniper Mist", central: "HPE Aruba Networking Central" };
type DeviceType = "ap" | "switch" | "gateway" | "other";
type ByType = Partial<Record<DeviceType, { total: number; online: number }>>;
export interface Counts { total: number; online: number; offline: number; by_type: ByType }
/** A device that is down, as a poll saw it. `key` (MAC / serial / id) never leaves this module unhashed. */
export interface RawDown { key: string; name: string | null; type: DeviceType; site: string | null; lastSeenMs: number | null }
export interface Poll extends Counts { down: RawDown[] }
/** A down device as the board shows it: no identifier beyond its name. */
export interface DownDevice { name: string | null; type: DeviceType; site: string | null; since: string }
/** stored per platform (longest down first); the admin board shows all of them, the kiosk KIOSK_DOWN_MAX */
export const DOWN_STORE_MAX = 500;

export interface OpsSource {
  kind: OpsKind;
  label: string;
  /** unconfigured: connector incomplete; pending: first poll not finished; ok: last poll succeeded; error: last poll failed */
  state: "unconfigured" | "pending" | "ok" | "error";
  missing: string[];
  total: number | null;
  online: number | null;
  offline: number | null;
  by_type: ByType;
  /** when the counts were taken (last successful poll) */
  counts_at: string | null;
  checked_at: string | null;
  error: string | null;
  /** devices down at the last successful poll, longest down first (at most DOWN_STORE_MAX) */
  down: DownDevice[];
  /** offline devices not in `down` (beyond the cap, or counted before the list existed) */
  down_more: number;
}

/** A failure we can show to an operator: never carries a credential or a raw vendor body. */
export class PollError extends Error {}

interface Resolved {
  kind: OpsKind;
  missing: string[];
  fp: string;
  base: string;
  orgId: string;
  creds: Record<string, string>;
  credError: string | null;
}

// ---- connector resolution ---------------------------------------------------------------------------------

/** Normalised API base (https origin + path, no trailing slash) or null when unusable. */
export function apiBaseOf(kind: OpsKind, raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length > 512) return null;
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash) return null;
  const host = u.hostname.toLowerCase();
  if (kind === "central" && !CENTRAL_HOST_RE.test(host)) return null;
  if (!host.includes(".") || host.includes(":")) return null;
  let path = u.pathname.replace(/\/+$/, "");
  if (kind === "mist") path = path.replace(/\/api\/v1$/, ""); // the runner accepts both spellings; so do we
  return `https://${u.host.toLowerCase()}${path}`;
}

async function resolve(env: Env, kind: OpsKind): Promise<Resolved> {
  const r = await env.DB.prepare("SELECT config_json, secret_id FROM integrations WHERE kind = ?1").bind(kind).first<{ config_json: string; secret_id: string | null }>();
  const config = parseJson<Record<string, unknown>>(r?.config_json, {});
  const row = r?.secret_id ? await getSecretRow(env, r.secret_id) : null;
  const missing: string[] = [];
  const base = apiBaseOf(kind, config.api_base ?? config.url ?? config.base_url);
  if (!base) missing.push("api_base");
  const orgId = typeof config.org_id === "string" && MIST_ORG_RE.test(config.org_id) ? config.org_id.toLowerCase() : "";
  if (kind === "mist" && !orgId) missing.push("org_id");
  const need = kind === "mist" ? ["token"] : ["client_id", "client_secret"];
  let creds: Record<string, string> = {};
  let credError: string | null = null;
  if (row) {
    try {
      const j = parseJson<Record<string, unknown>>(await readSecret(env, row), {});
      creds = Object.fromEntries(Object.entries(j).filter(([, v]) => typeof v === "string" && v.length > 0)) as Record<string, string>;
    } catch (e) {
      // e.g. sealed by a master key this Worker no longer holds: report it on the board, do not fail the page
      credError = `the stored ${LABEL[kind]} credentials cannot be decrypted (${e instanceof Error ? e.name : "error"}); save them again`;
    }
  }
  for (const k of need) if (!creds[k] && !credError) missing.push(k);
  // the fingerprint names WHICH config and credential version the cached counts came from, never their value
  const fp = (await sha256Hex(JSON.stringify([kind, base, orgId, row?.secret_id ?? null, row?.version ?? null, row?.updated_at ?? null]))).slice(0, 32);
  return { kind, missing, fp, base: base ?? "", orgId, creds, credError };
}

// ---- vendor polls -----------------------------------------------------------------------------------------

async function vendorFetch(platform: string, url: string, init: RequestInit): Promise<Response> {
  let res: Response;
  try {
    // redirect: manual so a credential is never replayed to wherever a 3xx points
    res = await fetch(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch (e) {
    const timeout = e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError");
    throw new PollError(timeout ? `${platform} did not answer within ${REQUEST_TIMEOUT_MS / 1000} s` : `${platform} is not reachable from the manager`);
  }
  if (res.ok) return res;
  await res.body?.cancel().catch(() => undefined);
  throw new PollError(httpProblem(platform, res.status));
}

function httpProblem(platform: string, status: number): string {
  if (status === 401 || status === 403) return `${platform} refused the credentials (HTTP ${status}): check that they are valid and have read access to the org`;
  if (status === 404) return `${platform} answered HTTP 404: check the API base URL${platform === "Mist" ? " and the org ID" : ""}`;
  if (status === 429) return `${platform} rate-limited the manager (HTTP 429); the board retries after ${OPS_TTL_S} s`;
  if (status >= 300 && status < 400) return `${platform} answered with a redirect (HTTP ${status}): use the API base URL itself`;
  if (status >= 500) return `${platform} is having trouble (HTTP ${status})`;
  return `${platform} answered HTTP ${status}`;
}

async function jsonOf(platform: string, res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    throw new PollError(`${platform} answered with something that is not JSON`);
  }
}

/** A vendor-provided label: text only, no control characters, at most 64 characters; empty -> null. */
export function label(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const t = v.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ").replace(/\s+/g, " ").trim();
  return t ? (t.length > 64 ? `${t.slice(0, 63)}\u2026` : t) : null;
}

interface SeenDevice { type: DeviceType; online: boolean; name: string | null; site: string | null; siteId: string | null; lastSeenMs: number | null }

function pollOf(seen: Map<string, SeenDevice>): Poll {
  const down: RawDown[] = [];
  for (const [key, d] of seen) if (!d.online) down.push({ key, name: d.name, type: d.type, site: d.site, lastSeenMs: d.lastSeenMs });
  return { ...tally([...seen.values()]), down };
}

function tally(items: Array<{ type: DeviceType; online: boolean }>): Counts {
  const by_type: ByType = {};
  let online = 0;
  for (const d of items) {
    const t = (by_type[d.type] ??= { total: 0, online: 0 });
    t.total++;
    if (d.online) (t.online++, online++);
  }
  return { total: items.length, online, offline: items.length - online, by_type };
}

const MIST_TYPES: Record<string, DeviceType> = { ap: "ap", switch: "switch", gateway: "gateway" };

const mistHeaders = (r: Pick<Resolved, "creds">) => ({ authorization: `Token ${r.creds.token}`, accept: "application/json", "user-agent": "exp-manager" });

/** Site id -> name for the sites of down devices. Best effort: any failure leaves the sites blank. */
async function mistSiteNames(r: Pick<Resolved, "base" | "orgId" | "creds">): Promise<Map<string, string>> {
  const names = new Map<string, string>();
  try {
    const res = await vendorFetch("Mist", `${r.base}/api/v1/orgs/${encodeURIComponent(r.orgId)}/sites?limit=${PAGE_LIMIT}`, { headers: mistHeaders(r) });
    const body = await jsonOf("Mist", res);
    if (Array.isArray(body)) {
      for (const s of body as Array<Record<string, unknown>>) {
        const n = s && typeof s === "object" ? label(s.name) : null;
        if (n && typeof s.id === "string") names.set(s.id, n);
      }
    }
  } catch {
    // the counts and names are still right; only the site column stays empty
  }
  return names;
}

export async function pollMist(r: Pick<Resolved, "base" | "orgId" | "creds">): Promise<Poll> {
  const seen = new Map<string, SeenDevice>();
  let firstLen = -1;
  for (let page = 1; page <= MAX_PAGES; page++) {
    const url = `${r.base}/api/v1/orgs/${encodeURIComponent(r.orgId)}/stats/devices?type=all&status=all&limit=${PAGE_LIMIT}&page=${page}`;
    const res = await vendorFetch("Mist", url, { headers: mistHeaders(r) });
    const pageTotal = Number(res.headers.get("x-page-total"));
    const body = await jsonOf("Mist", res);
    if (!Array.isArray(body)) throw new PollError("Mist answered with an unexpected shape (expected a device list)");
    for (const d of body as Array<Record<string, unknown>>) {
      if (!d || typeof d !== "object") continue;
      const key = String(d.mac ?? d.id ?? d.serial ?? `${page}:${seen.size}`);
      const online = d.status === "connected";
      const ls = typeof d.last_seen === "number" && Number.isFinite(d.last_seen) && d.last_seen > 0 ? Math.round(d.last_seen * 1000) : null;
      seen.set(key, {
        type: MIST_TYPES[String(d.type)] ?? "other", online,
        name: online ? null : label(d.name) ?? label(d.hostname), site: null,
        siteId: !online && typeof d.site_id === "string" ? d.site_id : null, lastSeenMs: online ? null : ls,
      });
    }
    if (firstLen < 0) firstLen = body.length;
    // last page: empty, short (compared with the first page, in case the API caps limit below what we asked), or
    // the advertised total reached
    if (body.length === 0 || body.length < firstLen || (Number.isFinite(pageTotal) && pageTotal > 0 && seen.size >= pageTotal)) {
      if ([...seen.values()].some((d) => d.siteId)) {
        const sites = await mistSiteNames(r);
        for (const d of seen.values()) if (d.siteId) d.site = sites.get(d.siteId) ?? null;
      }
      return pollOf(seen);
    }
  }
  throw new PollError(`Mist has more than ${MAX_PAGES * PAGE_LIMIT} devices; the board stops counting there`);
}

// Central access tokens live for 2 h and have no refresh token: request one with the client credentials and keep it
// in this isolate's memory only (never in D1), keyed by the credential fingerprint so a credential change drops it.
const centralTokens = new Map<string, { token: string; until: number }>();
export function resetCentralTokens(): void {
  centralTokens.clear();
}

async function centralToken(r: Pick<Resolved, "fp" | "creds">, fresh: boolean): Promise<string> {
  const c = centralTokens.get(r.fp);
  if (!fresh && c && c.until > nowMs()) return c.token;
  const res = await vendorFetch("Central token service", CENTRAL_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json", "user-agent": "exp-manager" },
    body: new URLSearchParams({ grant_type: "client_credentials", client_id: r.creds.client_id ?? "", client_secret: r.creds.client_secret ?? "" }).toString(),
  });
  const j = (await jsonOf("Central token service", res)) as { access_token?: unknown; expires_in?: unknown };
  if (typeof j?.access_token !== "string" || !j.access_token) throw new PollError("Central token service answered without an access token");
  const life = typeof j.expires_in === "number" && j.expires_in > 0 ? j.expires_in : 7199;
  centralTokens.set(r.fp, { token: j.access_token, until: nowMs() + Math.max(30, life - 300) * 1000 });
  return j.access_token;
}

const CENTRAL_TYPES: Record<string, DeviceType> = { ACCESS_POINT: "ap", SWITCH: "switch", GATEWAY: "gateway" };

export async function pollCentral(r: Pick<Resolved, "base" | "fp" | "creds">): Promise<Poll> {
  let token = await centralToken(r, false);
  let retried = false;
  const seen = new Map<string, SeenDevice>();
  let next: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const url = `${r.base}/network-monitoring/v1/devices?limit=${PAGE_LIMIT}${next ? `&next=${encodeURIComponent(next)}` : ""}`;
    let res: Response;
    try {
      res = await vendorFetch("Central", url, { headers: { authorization: `Bearer ${token}`, accept: "application/json", "user-agent": "exp-manager" } });
    } catch (e) {
      // a cached token can be revoked early (credentials reset): get a new one once, then give up
      if (!retried && e instanceof PollError && /HTTP 401/.test(e.message)) {
        retried = true;
        token = await centralToken(r, true);
        page--;
        continue;
      }
      throw e;
    }
    const body = (await jsonOf("Central", res)) as { items?: unknown; next?: unknown };
    if (!body || !Array.isArray(body.items)) throw new PollError("Central answered with an unexpected shape (expected {items, next})");
    for (const d of body.items as Array<Record<string, unknown>>) {
      if (!d || typeof d !== "object") continue;
      const key = String(d.serialNumber ?? d.id ?? d.macAddress ?? `${page}:${seen.size}`);
      const online = d.status === "ONLINE";
      seen.set(key, {
        type: CENTRAL_TYPES[String(d.deviceType)] ?? "other", online,
        name: online ? null : label(d.deviceName) ?? label(d.name), site: online ? null : label(d.siteName) ?? label(d.site_name),
        siteId: null, lastSeenMs: null,
      });
    }
    const n = body.next;
    if (n === null || n === undefined || n === "" || body.items.length === 0) return pollOf(seen);
    if (typeof n !== "string" && typeof n !== "number") throw new PollError("Central answered with an unexpected pagination cursor");
    if (String(n) === next) throw new PollError("Central returned the same page cursor twice");
    next = String(n);
  }
  throw new PollError(`Central has more than ${MAX_PAGES * PAGE_LIMIT} devices; the board stops counting there`);
}

/** Polls one platform with an already-resolved connector. Exposed for the integrations "test" action. */
export async function pollPlatform(env: Env, kind: OpsKind): Promise<{ missing: string[]; counts?: Poll; error?: string }> {
  const r = await resolve(env, kind);
  if (r.missing.length) return { missing: r.missing };
  if (r.credError) return { missing: [], error: r.credError };
  try {
    return { missing: [], counts: kind === "mist" ? await pollMist(r) : await pollCentral(r) };
  } catch (e) {
    if (e instanceof PollError) return { missing: [], error: e.message };
    console.error("ops poll failed", kind, e instanceof Error ? e.name : "error");
    return { missing: [], error: `${LABEL[kind]}: the poll failed unexpectedly` };
  }
}

// ---- the board ------------------------------------------------------------------------------------------

interface StatusRow {
  kind: OpsKind;
  checked_at: string;
  ok_at: string | null;
  total: number | null;
  online: number | null;
  offline: number | null;
  by_type_json: string;
  error: string | null;
  config_fp: string;
  down_json: string;
}

/** stored form of a down device: `k` is a keyed hash of the vendor identity (MAC / serial / id), never the identity */
interface StoredDown { k: string; n: string | null; t: DeviceType; s: string | null; since: string }

/** Merge a poll's down devices with the stored list: a device down at the last poll keeps its "down since"; a newly
 * down one starts at the vendor's last-seen time when it is earlier than now, else now. Longest down first, capped. */
export async function mergeDown(kind: OpsKind, prevJson: string | null, down: RawDown[], now: number): Promise<StoredDown[]> {
  const prev = new Map<string, string>();
  for (const p of parseJson<StoredDown[]>(prevJson, [])) if (p && typeof p.k === "string" && typeof p.since === "string") prev.set(p.k, p.since);
  const out: StoredDown[] = [];
  for (const d of down) {
    const k = (await sha256Hex(`exp-ops-device/v1|${kind}|${d.key}`)).slice(0, 24);
    const first = d.lastSeenMs !== null && d.lastSeenMs < now ? d.lastSeenMs : now;
    const kept = prev.get(k);
    const since = kept !== undefined && Date.parse(kept) <= now ? kept : isoAt(first);
    out.push({ k, n: d.name, t: d.type, s: d.site, since });
  }
  out.sort((a, b) => (a.since < b.since ? -1 : a.since > b.since ? 1 : (a.n ?? "\uffff").localeCompare(b.n ?? "\uffff")));
  return out.slice(0, DOWN_STORE_MAX);
}

const EPOCH = "1970-01-01T00:00:00.000Z";

async function sourceStatus(env: Env, kind: OpsKind): Promise<OpsSource> {
  const r = await resolve(env, kind);
  const empty: OpsSource = { kind, label: LABEL[kind], state: "unconfigured", missing: r.missing, total: null, online: null, offline: null, by_type: {}, counts_at: null, checked_at: null, error: null, down: [], down_more: 0 };
  if (r.missing.length) return empty;
  const now = nowMs();
  await env.DB.prepare("INSERT OR IGNORE INTO ops_device_status (kind, checked_at, config_fp) VALUES (?1, ?2, ?3)").bind(kind, EPOCH, r.fp).run();
  // atomic claim: only the request that moves checked_at forward polls; the others read what is there. A changed
  // connector (fingerprint) discards the old counts and error at claim time: they described another config.
  const claim = await env.DB.prepare(
    `UPDATE ops_device_status SET checked_at = ?2,
       ok_at = CASE WHEN config_fp = ?4 THEN ok_at END, total = CASE WHEN config_fp = ?4 THEN total END,
       online = CASE WHEN config_fp = ?4 THEN online END, offline = CASE WHEN config_fp = ?4 THEN offline END,
       by_type_json = CASE WHEN config_fp = ?4 THEN by_type_json ELSE '{}' END,
       down_json = CASE WHEN config_fp = ?4 THEN down_json ELSE '[]' END,
       error = CASE WHEN config_fp = ?4 THEN error END, config_fp = ?4
     WHERE kind = ?1 AND (checked_at < ?3 OR config_fp != ?4)`,
  ).bind(kind, isoAt(now), isoAt(now - OPS_TTL_S * 1000), r.fp).run();
  if ((claim.meta.changes ?? 0) === 1) {
    const out = await pollPlatform(env, kind);
    const at = isoAt(nowMs());
    if (out.counts) {
      const prev = await env.DB.prepare("SELECT down_json FROM ops_device_status WHERE kind = ?1 AND config_fp = ?2").bind(kind, r.fp).first<{ down_json: string }>();
      const down = await mergeDown(kind, prev?.down_json ?? null, out.counts.down, nowMs());
      await env.DB.prepare("UPDATE ops_device_status SET checked_at = ?2, ok_at = ?2, total = ?3, online = ?4, offline = ?5, by_type_json = ?6, error = NULL, down_json = ?8 WHERE kind = ?1 AND config_fp = ?7")
        .bind(kind, at, out.counts.total, out.counts.online, out.counts.offline, JSON.stringify(out.counts.by_type), r.fp, JSON.stringify(down))
        .run();
    } else {
      // the last good counts stay (same config): the board shows them with their age and this error
      await env.DB.prepare("UPDATE ops_device_status SET checked_at = ?2, error = ?3 WHERE kind = ?1 AND config_fp = ?4").bind(kind, at, (out.error ?? "poll failed").slice(0, 300), r.fp).run();
    }
  }
  const row = await env.DB.prepare("SELECT * FROM ops_device_status WHERE kind = ?1").bind(kind).first<StatusRow>();
  if (!row || row.config_fp !== r.fp) return { ...empty, state: "pending", missing: [] };
  const hasCounts = row.ok_at !== null && row.total !== null;
  const down = hasCounts ? parseJson<StoredDown[]>(row.down_json, []).map((d) => ({ name: d.n ?? null, type: d.t, site: d.s ?? null, since: d.since })) : [];
  return {
    ...empty,
    state: row.error ? "error" : hasCounts ? "ok" : "pending",
    missing: [],
    total: hasCounts ? row.total : null,
    online: hasCounts ? row.online : null,
    offline: hasCounts ? row.offline : null,
    by_type: hasCounts ? parseJson<ByType>(row.by_type_json, {}) : {},
    counts_at: row.ok_at,
    checked_at: row.checked_at === EPOCH ? null : row.checked_at,
    error: row.error,
    down,
    down_more: hasCounts ? Math.max(0, (row.offline ?? 0) - down.length) : 0,
  };
}

export async function opsDevices(env: Env): Promise<{ as_of: string; ttl_s: number; sources: OpsSource[] }> {
  const sources = await Promise.all(OPS_KINDS.map((k) => sourceStatus(env, k)));
  return { as_of: isoAt(nowMs()), ttl_s: OPS_TTL_S, sources };
}
