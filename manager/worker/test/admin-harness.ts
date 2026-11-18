// Admin API test harness: Access JWT signing, role identities, a routable fetch stub (JWKS + test handlers).
import { vi } from "vitest";
import { app } from "../src/index";
import { resetAccessCache } from "../src/auth/access";
import type { Env, Role } from "../src/env";
import { OWNER, TEAM, env, freshIp, goodClaims, makeKey, signJwt, type TestKey } from "./helpers";
import { DEFAULT_ORG } from "../src/env";
import { nowMs } from "../src/util/time";

export type FetchHandler = (url: string, init: RequestInit | undefined) => Response | Promise<Response> | undefined;
export interface FetchCall {
  url: string;
  init?: RequestInit;
}

export interface Harness {
  key: TestKey;
  calls: FetchCall[];
  handlers: FetchHandler[];
  api: (role: Role, method: string, path: string, body?: unknown, headers?: Record<string, string>) => Promise<Response>;
  json: <T = Record<string, unknown>>(role: Role, method: string, path: string, body?: unknown) => Promise<{ status: number; body: T; res: Response }>;
  /** run with env bindings overridden (e.g. RELEASE_PUBKEY_PEM) */
  withEnv: (over: Partial<Env>) => void;
  restore: () => void;
}

export const emailOf = (role: Role): string => (role === "owner" ? OWNER : `${role}@example.com`);

export async function harness(): Promise<Harness> {
  const key = await makeKey("kid-admin");
  resetAccessCache();
  const calls: FetchCall[] = [];
  const handlers: FetchHandler[] = [];
  let over: Partial<Env> = {};
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `https://${TEAM}/cdn-cgi/access/certs`) {
      return new Response(JSON.stringify({ keys: [{ ...key.jwk, kid: key.kid, alg: "RS256", use: "sig" }], public_cert: {} }), { headers: { "content-type": "application/json" } });
    }
    calls.push({ url, init });
    for (const h of handlers) {
      const r = await h(url, init);
      if (r) return r;
    }
    return new Response("no test handler", { status: 599 });
  });
  const seen = new Set<string>();
  const ensureAdmin = async (role: Role): Promise<void> => {
    if (seen.has(role) || role === "owner") return;
    const now = new Date().toISOString();
    await env.DB.prepare("INSERT OR IGNORE INTO admins (org_id, email, role, disabled, created_at, updated_at) VALUES (?1, ?2, ?3, 0, ?4, ?4)").bind(DEFAULT_ORG, emailOf(role), role, now).run();
    seen.add(role);
  };
  const effective = (): Env => (Object.keys(over).length ? (new Proxy(env, { get: (t, p, r) => (p in over ? (over as Record<string | symbol, unknown>)[p] : Reflect.get(t, p, r)) }) as Env) : env);
  const api: Harness["api"] = async (role, method, path, body, headers = {}) => {
    await ensureAdmin(role);
    const h = new Headers({ "Cf-Access-Jwt-Assertion": await signJwt(key, goodClaims(emailOf(role), { iat: Math.floor(nowMs() / 1000) - 5, nbf: Math.floor(nowMs() / 1000) - 5, exp: Math.floor(nowMs() / 1000) + 3600 })), "CF-Connecting-IP": freshIp(), "X-Exp-Request": "1", ...headers });
    let payload: BodyInit | undefined;
    if (body instanceof FormData) payload = body;
    else if (body !== undefined) {
      if (!h.has("content-type")) h.set("content-type", "application/json");
      payload = typeof body === "string" ? body : JSON.stringify(body);
    }
    return app.fetch(new Request(`https://manager.example.test/api/admin/v1${path}`, { method, headers: h, body: payload }), effective());
  };
  return {
    key,
    calls,
    handlers,
    api,
    json: async (role, method, path, body) => {
      const res = await api(role, method, path, body);
      const text = await res.text();
      let parsed: unknown = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        parsed = text;
      }
      return { status: res.status, body: parsed as never, res };
    },
    withEnv: (o) => {
      over = { ...over, ...o };
    },
    restore: () => {
      vi.unstubAllGlobals();
      resetAccessCache();
      over = {};
    },
  };
}
