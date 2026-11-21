// Wiring rules (05-manager.md section 7) as pure functions over the World. Shared by the compiler
// and by the secret pre-provisioning step (which must know which token pairs exist).
import type { WComponent, WHost, World } from "./types";

export const componentsOf = (w: World, type: WComponent["type"]): WComponent[] =>
  w.components.filter((c) => c.type === type && c.enabled);

const byCreated = (a: WComponent, b: WComponent): number =>
  a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : a.slug < b.slug ? -1 : a.slug > b.slug ? 1 : 0;

export const hostOf = (w: World, c: WComponent): WHost | undefined => w.hosts[c.host_id];

/** First IPv4 address (no mask) of the default-route / management interface, from host facts. */
export function mgmtIp(h: WHost | undefined): string | null {
  const ifaces = h?.facts.interfaces ?? [];
  const m = ifaces.find((i) => i.default_route) ?? ifaces.find((i) => i.in_use_by === "mgmt");
  for (const a of m?.addrs ?? []) {
    const ip = a.split("/")[0] ?? "";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip;
  }
  return null;
}

export function mgmtIface(h: WHost | undefined): string | null {
  const ifaces = h?.facts.interfaces ?? [];
  return (ifaces.find((i) => i.default_route) ?? ifaces.find((i) => i.in_use_by === "mgmt"))?.name ?? null;
}

/** The collector a probe/runner reports to: config.collector_id, default the site's first collector. */
export function collectorFor(w: World, c: WComponent): WComponent | null {
  const want = typeof c.config.collector_id === "string" ? c.config.collector_id : null;
  const cols = componentsOf(w, "collector").sort(byCreated);
  if (want) return cols.find((x) => x.slug === want) ?? null;
  const site = hostOf(w, c)?.site;
  return cols.find((x) => hostOf(w, x)?.site === site) ?? null;
}

/**
 * Collectors a dashboard federates (CR-wp5-admin-ui-intent): config.collector_ids (slugs, the admin UI's intent), else
 * config.collectors as slugs or as full-document entries `{collector_id, ...}` (url/pin are always taken from the
 * collector's reported facts, never from the stored entry), else all collectors of its site(s).
 */
export function collectorsOfDashboard(w: World, d: WComponent): WComponent[] {
  const cols = componentsOf(w, "collector").sort(byCreated);
  const ids = Array.isArray(d.config.collector_ids) ? d.config.collector_ids : d.config.collectors;
  if (Array.isArray(ids)) {
    const wanted = ids
      .map((x) => (typeof x === "string" ? x : x && typeof x === "object" && typeof (x as { collector_id?: unknown }).collector_id === "string" ? (x as { collector_id: string }).collector_id : null))
      .filter((x): x is string => x !== null);
    return cols.filter((c) => wanted.includes(c.slug));
  }
  const sites = Array.isArray(d.config.sites)
    ? d.config.sites.filter((x): x is string => typeof x === "string")
    : [hostOf(w, d)?.site ?? ""];
  return cols.filter((c) => sites.includes(hostOf(w, c)?.site ?? ""));
}

export const dashboardsOfCollector = (w: World, col: WComponent): WComponent[] =>
  componentsOf(w, "dashboard")
    .filter((d) => collectorsOfDashboard(w, d).some((c) => c.component_id === col.component_id))
    .sort(byCreated);

export const probesOfCollector = (w: World, col: WComponent): WComponent[] =>
  componentsOf(w, "probe")
    .filter((p) => collectorFor(w, p)?.component_id === col.component_id)
    .sort(byCreated);

export const runnersOfCollector = (w: World, col: WComponent): WComponent[] =>
  componentsOf(w, "runner")
    .filter((p) => collectorFor(w, p)?.component_id === col.component_id)
    .sort(byCreated);

export const speedtestsOfCollector = (w: World, col: WComponent): WComponent[] =>
  componentsOf(w, "speedtest")
    .filter((p) => collectorFor(w, p)?.component_id === col.component_id)
    .sort(byCreated);

/** The runner a speedtest talks to over the localhost channel: the first enabled runner on the same host. */
export const runnerOfSpeedtest = (w: World, st: WComponent): WComponent | null =>
  componentsOf(w, "runner").filter((r) => r.host_id === st.host_id).sort(byCreated)[0] ?? null;

/** The speedtest a runner pushes to over the localhost channel: the first enabled speedtest on the same host. */
export const speedtestOfRunner = (w: World, r: WComponent): WComponent | null =>
  componentsOf(w, "speedtest").filter((s) => s.host_id === r.host_id).sort(byCreated)[0] ?? null;

/** `https://<listen>` and the pin, only once the collector has reported both (else null: probes spool). */
export function collectorEndpoint(col: WComponent | null): { url: string; pin: string } | null {
  if (!col) return null;
  const listen = col.facts.listen;
  const pin = col.facts.tls_fingerprint_sha256;
  if (!listen || !pin) return null;
  return { url: `https://${listen}`, pin };
}

// ---- secret owner conventions ---------------------------------------------------------------
export const INGEST_KIND = "ingest_token";
export const DASH_TOKEN_KIND = "dashboard_token";
export const SSO_KIND = "sso_secret";
export const WEBHOOK_KIND = "webhook_url";
/** admin-provided dashboard TLS: JSON {cert_pem, key_pem}, owner = the dashboard component id (write-only) */
export const TLS_KIND = "dashboard_tls";
/** M6 (01-contracts.md section 14.2): speedtest -> collector token (exps_), owner = the speedtest component */
export const SPEEDTEST_TOKEN_KIND = "speedtest_token";
/** runner -> collector token (expr_), owner = the runner component */
export const RUNNER_TOKEN_KIND = "runner_token";
/** runner -> speedtest localhost channel token (expl_), owner = pairOwner(runner, speedtest) */
export const CHANNEL_TOKEN_KIND = "channel_token";
/** per-org device_key secret (expk_, 32 random bytes): owner DEVICE_KEY_OWNER, never hashed, never returned by an API */
export const DEVICE_KEY_KIND = "device_key";
export const DEVICE_KEY_OWNER = "org";
/** provided TLS pair of the site's speedtest: JSON {cert_pem, key_pem}, owner = speedtestTlsOwner(site) (write-only) */
export const SPEEDTEST_TLS_KIND = "speedtest_tls";
export const speedtestTlsOwner = (site: string): string => `speedtest:${site}`;
/** stored connector credentials (admin/intent.ts INTEGRATION_KIND) */
export const INTEGRATION_SECRET_KIND = "integration_credentials";
export const pairOwner = (dashCmp: string, colCmp: string): string => `${dashCmp}:${colCmp}`;

export interface RequiredSecret {
  ownerRef: string;
  kind: string;
}

/** Every generated secret the current intent needs (created idempotently before compiling). */
export function requiredSecrets(w: World): RequiredSecret[] {
  const out: RequiredSecret[] = [];
  for (const c of w.components) {
    if (!c.enabled) continue;
    if (c.type === "probe" || c.type === "runner") out.push({ ownerRef: c.component_id, kind: INGEST_KIND });
    if (c.type === "runner") {
      out.push({ ownerRef: c.component_id, kind: RUNNER_TOKEN_KIND });
      out.push({ ownerRef: DEVICE_KEY_OWNER, kind: DEVICE_KEY_KIND });
      const st = speedtestOfRunner(w, c);
      if (st) out.push({ ownerRef: pairOwner(c.component_id, st.component_id), kind: CHANNEL_TOKEN_KIND });
    }
    if (c.type === "speedtest") out.push({ ownerRef: c.component_id, kind: SPEEDTEST_TOKEN_KIND });
    if (c.type === "dashboard") {
      out.push({ ownerRef: c.component_id, kind: SSO_KIND });
      for (const col of collectorsOfDashboard(w, c)) {
        out.push({ ownerRef: pairOwner(c.component_id, col.component_id), kind: DASH_TOKEN_KIND });
      }
    }
  }
  return out;
}
