// Cloudflare Access JWT verification (05-manager.md section 5). Fail closed.
//  - RS256 only, signature against https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs
//  - JWKS cached 1 h, refetched on an unknown kid (at most once per 30 s)
//  - aud contains ACCESS_AUD, iss == https://<ACCESS_TEAM_DOMAIN>, exp / nbf with small skew
//  - the email comes from the verified JWT only; Cf-Access-Authenticated-User-Email is never read.
import type { Context, MiddlewareHandler } from "hono";
import { writeAudit } from "../audit/audit";
import type { AdminIdentity, AppBindings, Env, Role } from "../env";
import { DEFAULT_ORG } from "../env";
import { ApiError, unauthenticated } from "../errors";
import { enforce } from "../ratelimit";
import { b64urlToBytes, fromUtf8 } from "../util/encoding";
import { isoNow, nowMs } from "../util/time";

const JWKS_TTL_MS = 3600_000;
const JWKS_MIN_REFETCH_MS = 30_000;
const SKEW_S = 60;
const MAX_JWT_LEN = 8192;

interface Jwk {
  kid?: string;
  kty?: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
}

interface JwksCache {
  domain: string;
  fetchedAt: number;
  keys: Map<string, CryptoKey>;
}

let cache: JwksCache | null = null;
let lastFetchAttempt = 0;

export function resetAccessCache(): void {
  cache = null;
  lastFetchAttempt = 0;
}

function teamDomain(env: Env): string {
  const d = (env.ACCESS_TEAM_DOMAIN ?? "").trim().toLowerCase();
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(d) || !d.includes(".")) throw unauthenticated();
  return d;
}

async function loadJwks(domain: string): Promise<JwksCache> {
  lastFetchAttempt = nowMs();
  let res: Response;
  try {
    res = await fetch(`https://${domain}/cdn-cgi/access/certs`, {
      signal: AbortSignal.timeout(5000),
      headers: { accept: "application/json" },
    });
  } catch {
    throw unauthenticated();
  }
  if (!res.ok) throw unauthenticated();
  let body: { keys?: Jwk[] };
  try {
    body = (await res.json()) as { keys?: Jwk[] };
  } catch {
    throw unauthenticated();
  }
  const keys = new Map<string, CryptoKey>();
  for (const jwk of (body.keys ?? []).slice(0, 20)) {
    if (!jwk || jwk.kty !== "RSA" || !jwk.kid || !jwk.n || !jwk.e) continue;
    try {
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
      keys.set(jwk.kid, key);
    } catch {
      /* skip malformed key */
    }
  }
  const c = { domain, fetchedAt: nowMs(), keys };
  cache = c;
  return c;
}

async function keyFor(domain: string, kid: string): Promise<CryptoKey> {
  let c = cache && cache.domain === domain && nowMs() - cache.fetchedAt < JWKS_TTL_MS ? cache : null;
  if (c?.keys.has(kid)) return c.keys.get(kid) as CryptoKey;
  // unknown kid or expired cache: refetch, but not more than once per 30 s (kid-spam must not become fetch-spam)
  if (c === null || nowMs() - lastFetchAttempt >= JWKS_MIN_REFETCH_MS) c = await loadJwks(domain);
  const k = c.keys.get(kid);
  if (!k) throw unauthenticated();
  return k;
}

export interface VerifiedJwt {
  email: string;
  sub?: string;
}

function parseJson(part: string): Record<string, unknown> {
  const v = JSON.parse(fromUtf8(b64urlToBytes(part))) as unknown;
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("not an object");
  return v as Record<string, unknown>;
}

export async function verifyAccessJwt(env: Env, token: string | null | undefined): Promise<VerifiedJwt> {
  if (!token || token.length > MAX_JWT_LEN) throw unauthenticated();
  const aud = (env.ACCESS_AUD ?? "").trim();
  if (!aud) throw unauthenticated(); // missing config -> fail closed
  const domain = teamDomain(env);
  const parts = token.split(".");
  if (parts.length !== 3) throw unauthenticated();
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  let sig: Uint8Array;
  try {
    header = parseJson(parts[0] as string);
    claims = parseJson(parts[1] as string);
    sig = b64urlToBytes(parts[2] as string);
  } catch {
    throw unauthenticated();
  }
  if (header.alg !== "RS256" || typeof header.kid !== "string" || header.kid.length > 128) throw unauthenticated();

  const key = await keyFor(domain, header.kid);
  const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  let ok = false;
  try {
    ok = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig, signed);
  } catch {
    ok = false;
  }
  if (!ok) throw unauthenticated();

  if (claims.iss !== `https://${domain}`) throw unauthenticated();
  const tokenAud = claims.aud;
  const auds = typeof tokenAud === "string" ? [tokenAud] : Array.isArray(tokenAud) ? tokenAud : [];
  if (!auds.includes(aud)) throw unauthenticated();
  const now = Math.floor(nowMs() / 1000);
  if (typeof claims.exp !== "number" || claims.exp + SKEW_S < now) throw unauthenticated();
  if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || claims.nbf - SKEW_S > now)) throw unauthenticated();
  if (claims.iat !== undefined && (typeof claims.iat !== "number" || claims.iat - SKEW_S > now)) throw unauthenticated();
  const email = claims.email;
  if (typeof email !== "string" || !/^[^\s@]{1,128}@[^\s@]{1,253}$/.test(email) || email.length > 254) throw unauthenticated();
  return { email: email.toLowerCase(), sub: typeof claims.sub === "string" ? claims.sub : undefined };
}

// ---- roles (05-manager.md section 4) ---------------------------------------------------------
const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3, owner: 4 };

export function roleAtLeast(role: Role, min: Role): boolean {
  return RANK[role] >= RANK[min];
}

interface AdminRow {
  email: string;
  role: Role;
  disabled: number;
  last_seen: string | null;
}

async function resolveAdmin(env: Env, email: string, ip: string): Promise<AdminIdentity> {
  let row = await env.DB.prepare("SELECT email, role, disabled, last_seen FROM admins WHERE email = ?1")
    .bind(email)
    .first<AdminRow>();
  const owner = (env.EXP_OWNER_EMAIL ?? "").trim().toLowerCase();
  if (!row) {
    if (owner && email === owner) {
      // first sign-in of EXP_OWNER_EMAIL creates the owner (INSERT OR IGNORE: races create one row)
      const now = isoNow();
      await env.DB.batch([
        env.DB.prepare(
          `INSERT OR IGNORE INTO admins (org_id, email, role, disabled, last_seen, created_at, updated_at)
           VALUES (?1, ?2, 'owner', 0, ?3, ?3, ?3)`,
        ).bind(DEFAULT_ORG, email, now),
      ]);
      row = await env.DB.prepare("SELECT email, role, disabled, last_seen FROM admins WHERE email = ?1")
        .bind(email)
        .first<AdminRow>();
      if (row) {
        await writeAudit(env.DB, { actor: email, action: "admin.owner_created", resource: `admin:${email}`, ip });
      }
    }
    if (!row) throw new ApiError(403, "unknown_admin", "unknown admin");
  }
  if (row.disabled) throw new ApiError(403, "admin_disabled", "admin disabled");
  const lastSeenMs = row.last_seen ? Date.parse(row.last_seen) : 0;
  if (nowMs() - lastSeenMs > 300_000) {
    await env.DB.prepare("UPDATE admins SET last_seen = ?1 WHERE email = ?2").bind(isoNow(), email).run();
  }
  return { email: row.email, role: row.role };
}

/** Authenticates every admin request: verified JWT -> admins row -> rate limit per identity. */
export const accessAuth: MiddlewareHandler<AppBindings> = async (c, next) => {
  const jwt = c.req.header("Cf-Access-Jwt-Assertion");
  const v = await verifyAccessJwt(c.env, jwt);
  const admin = await resolveAdmin(c.env, v.email, c.get("ip"));
  await enforce(c.env.RL_ADMIN, `admin:${admin.email}`);
  c.set("admin", admin);
  await next();
};

export function requireRole(min: Role): MiddlewareHandler<AppBindings> {
  return async (c, next) => {
    const a = c.get("admin");
    if (!a) throw unauthenticated();
    if (!roleAtLeast(a.role, min)) throw new ApiError(403, "insufficient_role", "insufficient role", { required: min });
    await next();
  };
}

export function adminOf(c: Context<AppBindings>): AdminIdentity {
  const a = c.get("admin");
  if (!a) throw unauthenticated();
  return a;
}
