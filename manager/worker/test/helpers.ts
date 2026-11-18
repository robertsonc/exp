// Shared helpers for the workers-pool tests (local D1 / R2 / rate-limit bindings).
import { env as rawEnv } from "cloudflare:workers";
import { vi } from "vitest";
import { app } from "../src/index";
import { resetAccessCache } from "../src/auth/access";
import type { Env } from "../src/env";
import { addComponent, createHost, createSite } from "../src/admin/service";
import { recompile } from "../src/compile/recompile";
import { sha256Hex, bytesToB64url } from "../src/util/encoding";
import { newId } from "../src/util/ids";
import { isoNow } from "../src/util/time";

export const env = rawEnv as unknown as Env;
export const TEAM = "exp-test.cloudflareaccess.com";
export const AUD = "test-aud-0123456789";
export const OWNER = "owner@example.com";
export const ADMIN_ACTOR = { email: "admin@example.com", ip: "198.51.100.1" };

let ipCounter = 0;
/** a unique client IP per call so per-IP rate limit budgets never leak between tests */
export const freshIp = (): string => `203.0.${(Math.floor(ipCounter / 250) % 250) + 1}.${(ipCounter++ % 250) + 1}`;

export async function call(path: string, init: RequestInit & { ip?: string } = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (!headers.has("CF-Connecting-IP")) headers.set("CF-Connecting-IP", init.ip ?? freshIp());
  return await app.fetch(new Request(`https://manager.example.test${path}`, { ...init, headers }), env);
}

export const json = (o: unknown): RequestInit => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(o) });

export async function tableNames(): Promise<string[]> {
  const r = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name != 'd1_migrations'").all<{ name: string }>();
  return r.results.map((x) => x.name);
}

/** Wipes all tables (the local D1 persists across tests of a file). */
export async function resetDb(): Promise<void> {
  for (const t of await tableNames()) await env.DB.prepare(`DELETE FROM ${t}`).run();
  const objs = await env.ARTIFACTS.list();
  for (const o of objs.objects) await env.ARTIFACTS.delete(o.key);
}

// ---- Access JWT ---------------------------------------------------------------------------------
export interface TestKey {
  kid: string;
  privateKey: CryptoKey;
  jwk: JsonWebKey;
}

export async function makeKey(kid = "kid-1"): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return { kid, privateKey: pair.privateKey, jwk };
}

const b64u = (o: unknown): string => bytesToB64url(new TextEncoder().encode(JSON.stringify(o)));

export async function signJwt(key: TestKey, claims: Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
  const h = { alg: "RS256", kid: key.kid, typ: "JWT", ...header };
  const signing = `${b64u(h)}.${b64u(claims)}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key.privateKey, new TextEncoder().encode(signing));
  return `${signing}.${bytesToB64url(new Uint8Array(sig))}`;
}

export const goodClaims = (email: string, over: Record<string, unknown> = {}): Record<string, unknown> => {
  const now = Math.floor(Date.now() / 1000);
  return { iss: `https://${TEAM}`, aud: [AUD], email, sub: "user-1", iat: now - 5, nbf: now - 5, exp: now + 3600, type: "app", ...over };
};

/** Serve `keys` as the team JWKS via a fetch mock; returns a call counter. */
export function serveJwks(...keys: TestKey[]): { calls: () => number } {
  resetAccessCache();
  let n = 0;
  const real = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `https://${TEAM}/cdn-cgi/access/certs`) {
      n++;
      return new Response(JSON.stringify({ keys: keys.map((k) => ({ ...k.jwk, kid: k.kid, alg: "RS256", use: "sig" })), public_cert: {} }), {
        headers: { "content-type": "application/json" },
      });
    }
    return real(input, init);
  });
  return { calls: () => n };
}

// ---- releases / artifacts -------------------------------------------------------------------------
export interface SeededRelease {
  version: string;
  artifacts: Record<string, { artifact_id: string; sha256: string; bytes: Uint8Array; name: string }>;
}

/** Stores a release directly (verification belongs to import, step 2). Fake bytes, real sha256. */
export async function seedRelease(version: string, opts: { archs?: Record<string, string[]> } = {}): Promise<SeededRelease> {
  const archs = opts.archs ?? { agent: ["noarch"], probe: ["noarch"], collector: ["amd64", "arm64"], dashboard: ["noarch"], runner: ["noarch"] };
  const now = isoNow();
  const manifest = new TextEncoder().encode(JSON.stringify({ schema: "exp.manifest/1", version, artifacts: [] }, null, 2) + "\n");
  const mKey = `releases/${version}/manifest.json`;
  await env.ARTIFACTS.put(mKey, manifest);
  await env.DB.prepare(
    `INSERT OR REPLACE INTO releases (version, manifest_r2_key, signature, verified_at, source, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 'test', ?4, ?4)`,
  ).bind(version, mKey, "A".repeat(86) + "==", now).run();
  const out: SeededRelease = { version, artifacts: {} };
  for (const [component, list] of Object.entries(archs)) {
    for (const arch of list) {
      const name = `exp-${component}-${version}-${arch}.tar.gz`;
      const bytes = new TextEncoder().encode(`fake artifact bytes for ${name}\n`);
      const sha = await sha256Hex(bytes);
      const id = newId("art_");
      const key = `artifacts/${id}`;
      await env.ARTIFACTS.put(key, bytes);
      await env.DB.prepare(
        `INSERT INTO artifacts (artifact_id, version, name, component, arch, sha256, size, r2_key, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)`,
      ).bind(id, version, name, component, arch, sha, bytes.length, key, now).run();
      out.artifacts[`${component}/${arch}`] = { artifact_id: id, sha256: sha, bytes, name };
    }
  }
  return out;
}

export const FACTS = (over: Record<string, unknown> = {}) => ({
  hostname: "srv-02",
  machine_id: "0123456789abcdef0123456789abcdef",
  os: { id: "ubuntu", version: "24.04" },
  kernel: "6.8.0-1",
  arch: "amd64",
  cpus: 8,
  mem_mb: 32000,
  disk_free_mb: 400000,
  python: "3.12.3",
  time: { synced: true, source: "systemd-timesyncd", offset_ms: 1.2 },
  interfaces: [
    { name: "eno1", mac: "18:66:da:00:00:01", state: "up", speed_mbps: 1000, driver: "tg3", addrs: ["10.32.98.25/23"], default_route: true, in_use_by: "mgmt" },
    { name: "enp10s0f0", mac: "18:66:da:00:00:02", state: "up", speed_mbps: 1000, driver: "ixgbe", addrs: [], default_route: false, in_use_by: "none" },
  ],
  ...over,
});

export interface EnrolledHost {
  host_id: string;
  secret: string;
}

/** createHost + enrol through the real endpoint. */
export async function enrolHost(site: string, name = "srv-02", facts: Record<string, unknown> = FACTS()): Promise<EnrolledHost> {
  const h = await createHost(env, ADMIN_ACTOR, { name, site });
  const r = await call("/api/agent/v1/enrol", json({ token: h.enrol_token, facts }));
  if (r.status !== 201) throw new Error(`enrol failed: ${r.status} ${await r.text()}`);
  const b = (await r.json()) as { agent_id: string; agent_secret: string };
  return { host_id: b.agent_id, secret: b.agent_secret };
}

export const bearer = (secret: string): Record<string, string> => ({ authorization: `Bearer ${secret}` });

export async function seedSiteWithRelease(site = "hall-b", version = "0.1.0"): Promise<SeededRelease> {
  await createSite(env, ADMIN_ACTOR, { site, name: "Hall B", timezone: "America/Chicago" });
  const rel = await seedRelease(version);
  await env.DB.prepare("UPDATE sites SET release_version = ?2 WHERE site = ?1").bind(site, version).run();
  return rel;
}

export { addComponent, createSite, createHost, recompile };

export function statusReport(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "exp.status/1",
    agent: { version: "0.1.0", desired_version: 1, applied_version: 1, uptime_s: 86400, last_poll: "2026-11-18T20:00:00.000Z" },
    facts: FACTS(),
    metrics: {
      interval_s: 60,
      uptime_s: 1234567,
      cpu: { pct: 23.4, iowait_pct: 1.2, steal_pct: 0, load1: 0.8, load5: 0.6, load15: 0.5 },
      mem: { total_mb: 32000, used_mb: 8200, available_mb: 23800, pct: 25.6, swap_used_mb: 0 },
      disk: [{ mount: "/", total_gb: 437, used_gb: 13.1, pct: 3 }],
      net: [{ iface: "eno1", role: "mgmt", link: "up", speed_mbps: 1000, rx_pps: 120.5, tx_pps: 98.2, rx_bps: 340000, tx_bps: 120000, rx_errors: 0, tx_errors: 0, rx_drops: 0, tx_drops: 0 }],
    },
    components: [],
    reconcile: { at: "2026-11-18T20:00:00.000Z", result: "ok", error: null, duration_ms: 5400 },
    events: [],
    ...over,
  };
}

export const FINGERPRINT = "DC:2B:CE:95:F2:A0:0C:B9:5B:3A:CF:F5:00:CB:0C:DE:E7:BD:CA:AC:63:CC:83:95:F6:30:EA:F1:27:34:6D:C6";

export async function getDesired(secret: string, headers: Record<string, string> = {}): Promise<Response> {
  return call("/api/agent/v1/desired", { headers: { ...bearer(secret), ...headers } });
}

export async function postStatus(secret: string, body: unknown): Promise<Response> {
  return call("/api/agent/v1/status", { method: "POST", headers: { ...bearer(secret), "content-type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body) });
}

export async function auditActions(): Promise<string[]> {
  const r = await env.DB.prepare("SELECT action FROM audit ORDER BY ts, evt_id").all<{ action: string }>();
  return r.results.map((x) => x.action);
}

export const WEBHOOK_URL = "https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX";
export const PBKDF2 = "pbkdf2_sha256$600000$Tr4XuAwCFH7YD/2V/36QoA==$bJc8Pe3nYnc4c1g1Hx7qwAcWynGWZnTS42MUPGXZZoE=";

export interface Scenario {
  col: EnrolledHost;
  dash: EnrolledHost;
  probe: EnrolledHost;
  cols: string;
  dashId: string;
  probeId: string;
  colId: string;
}

/** collector + dashboard + probe on hall-b, collector reported listen + pin, webhook, NOC token, local user. */
export async function fullScenario(): Promise<Scenario & { nocToken: string }> {
  const s = await import("../src/admin/service");
  const col = await enrolHost("hall-b", "col-host");
  const dash = await enrolHost("hall-b", "dash-host", FACTS({ interfaces: [{ name: "eno1", mac: "18:66:da:00:00:09", state: "up", speed_mbps: 1000, addrs: ["10.32.98.30/23"], default_route: true, in_use_by: "mgmt" }] }));
  const probe = await enrolHost("hall-b", "probe-host");
  const c1 = await s.addComponent(env, ADMIN_ACTOR, col.host_id, { type: "collector", id: "col-hallb", config: {} });
  const d1 = await s.addComponent(env, ADMIN_ACTOR, dash.host_id, { type: "dashboard", id: "dash-main", config: {} });
  const p1 = await s.addComponent(env, ADMIN_ACTOR, probe.host_id, {
    type: "probe",
    id: "probe-a1",
    config: { label: "Hall B east", ports: [{ id: "c01", iface: "enp10s0f0", role: "client", vlan: null, dhcp: { hostname: "exp-hallb-c01", vendor_class: "exp-probe", client_id: "mac" } }] },
  });
  await postStatus(col.secret, statusReport({ components: [{ type: "collector", id: "col-hallb", state: "running", health: "ok", facts: { listen: "10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT } }] }));
  await s.addWebhook(env, ADMIN_ACTOR, "hall-b", { format: "slack", url: WEBHOOK_URL });
  const noc = await s.createNocToken(env, ADMIN_ACTOR, "dash-main", { label: "wall display" });
  await s.createDashboardUser(env, ADMIN_ACTOR, "dash-main", { username: "admin", role: "admin", hash: PBKDF2 });
  return { col, dash, probe, cols: c1.component_id, dashId: d1.component_id, probeId: p1.component_id, colId: c1.component_id, nocToken: noc.token };
}
