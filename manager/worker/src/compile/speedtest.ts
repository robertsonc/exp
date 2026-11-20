// M6 compile helpers (CR-m6-manager): the speedtest / runner-correlation / collector-speedtests documents and the
// host-wide port-collision check. PURE (no I/O): everything arrives through the World.
import { canonicalJson } from "../util/canonical";
import type { WComponent, WHost, WSecret, WSpeedtest, World } from "./types";
import { secretKey } from "./types";
import {
  CHANNEL_TOKEN_KIND,
  DEVICE_KEY_KIND,
  DEVICE_KEY_OWNER,
  RUNNER_TOKEN_KIND,
  SPEEDTEST_TLS_KIND,
  SPEEDTEST_TOKEN_KIND,
  componentsOf,
  mgmtIp,
  pairOwner,
  runnerOfSpeedtest,
  speedtestOfRunner,
  speedtestTlsOwner,
} from "./wiring";

type Obj = Record<string, unknown>;
export const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

/** The consent text a site shows until an admin saves one (version 1). */
export const DEFAULT_CONSENT_TEXT =
  "We measure your connection speed and record technical details of this device and its network path (Wi-Fi signal, access point, traffic metadata) to diagnose problems. No name or email address is collected.";

/** 127.0.0.1:8480 (01-contracts.md section 14.9): the runner -> speedtest channel. */
export const CHANNEL_HOST = "127.0.0.1";
export const CHANNEL_PORT = 8480;
export const CHANNEL_LISTEN = `${CHANNEL_HOST}:${CHANNEL_PORT}`;
export const CHANNEL_URL = `http://${CHANNEL_HOST}:${CHANNEL_PORT}/local/v1`;

export const DEFAULT_SYSLOG_LISTEN = ["udp:5514", "tcp:5514", "tls:6514"];

export const siteSpeedtest = (w: World, site: string): WSpeedtest | undefined => w.speedtest?.[site];
const deviceKey = (w: World): WSecret | undefined => w.secrets[secretKey(DEVICE_KEY_OWNER, DEVICE_KEY_KIND)];
export { deviceKey };

/** Does this site run the M6 speedtest analytics (a speedtest component or saved settings)? */
export function speedtestSiteActive(w: World, site: string): boolean {
  return !!siteSpeedtest(w, site) || componentsOf(w, "speedtest").some((c) => w.hosts[c.host_id]?.site === site);
}

/** `serve` of a speedtest: the site's settings with the component's own config on top (the host's serve addresses). */
export function effectiveServe(w: World, c: WComponent): Obj {
  const site = w.hosts[c.host_id]?.site ?? "";
  const fromSite = isObj(siteSpeedtest(w, site)?.settings.serve) ? (siteSpeedtest(w, site)?.settings.serve as Obj) : {};
  const own = isObj(c.config.serve) ? c.config.serve : {};
  const merged: Obj = { ...fromSite, ...own };
  if (typeof merged.hostname !== "string" && typeof merged.listen_ip === "string") merged.hostname = merged.listen_ip;
  return merged;
}

const tlsMode = (w: World, c: WComponent): "none" | "provided" => {
  const site = w.hosts[c.host_id]?.site ?? "";
  const own = isObj(c.config.tls) ? c.config.tls.mode : undefined;
  const st = siteSpeedtest(w, site)?.settings.tls;
  const m = own ?? (isObj(st) ? st.mode : undefined);
  return m === "provided" ? "provided" : "none";
};
export { tlsMode as speedtestTlsMode };

/** The site's stored provided-TLS pair, or null (absent or unreadable). */
export function speedtestTlsPair(w: World, site: string): { cert_pem: string; key_pem: string } | null {
  const s = w.secrets[secretKey(speedtestTlsOwner(site), SPEEDTEST_TLS_KIND)];
  if (!s) return null;
  try {
    const j = JSON.parse(s.plaintext) as { cert_pem?: unknown; key_pem?: unknown };
    return typeof j.cert_pem === "string" && typeof j.key_pem === "string" ? { cert_pem: j.cert_pem, key_pem: j.key_pem } : null;
  } catch {
    return null;
  }
}

// ---- port bindings (all-in-one profile: no collisions) -------------------------------------------------------
export interface Binding {
  component: string;
  proto: "tcp" | "udp";
  ip: string;
  port: number;
  what: string;
}

const ANY = "0.0.0.0";
function hostPort(s: unknown): { ip: string; port: number } | null {
  if (typeof s !== "string") return null;
  const i = s.lastIndexOf(":");
  if (i < 0) return null;
  const port = Number(s.slice(i + 1));
  return Number.isInteger(port) ? { ip: s.slice(0, i), port } : null;
}

export function bindingsOf(w: World, c: WComponent, host: WHost): Binding[] {
  const out: Binding[] = [];
  const add = (proto: "tcp" | "udp", ip: string, port: number, what: string) => out.push({ component: `${c.type} ${c.slug}`, proto, ip, port, what });
  if (c.type === "collector") {
    const l = hostPort(typeof c.config.listen === "string" && c.config.listen ? c.config.listen : mgmtIp(host) ? `${mgmtIp(host)}:8443` : null);
    if (l) add("tcp", l.ip, l.port, "api");
    const refl = isObj(c.config.reflector) ? c.config.reflector : {};
    if (refl.enabled === true) {
      const p = typeof refl.port === "number" ? refl.port : 8862;
      add("tcp", ANY, p, "reflector");
      add("udp", ANY, p, "reflector");
    }
    const ip3 = isObj(c.config.iperf3) ? c.config.iperf3 : {};
    if (ip3.enabled === true) add("tcp", ANY, typeof ip3.port === "number" ? ip3.port : 5201, "iperf3");
  } else if (c.type === "dashboard") {
    const l = isObj(c.config.listen) ? c.config.listen : { https: "0.0.0.0:443", http_redirect: "0.0.0.0:80" };
    for (const k of ["https", "http_redirect"]) {
      const hp = hostPort(l[k]);
      if (hp) add("tcp", hp.ip, hp.port, k);
    }
  } else if (c.type === "speedtest") {
    const serve = effectiveServe(w, c);
    const ip = typeof serve.listen_ip === "string" ? serve.listen_ip : null;
    if (ip) {
      const provided = tlsMode(w, c) === "provided";
      const port = typeof serve.port === "number" ? serve.port : provided ? 443 : 80;
      add("tcp", ip, port, provided ? "https" : "http");
      if (provided && typeof serve.port !== "number") add("tcp", ip, 80, "http redirect");
      const site = host.site;
      const dns = isObj(c.config.dns_leg) ? c.config.dns_leg : isObj(siteSpeedtest(w, site)?.settings.dns_leg) ? (siteSpeedtest(w, site)?.settings.dns_leg as Obj) : {};
      if (dns.enabled === true) {
        const dp = typeof dns.port === "number" ? dns.port : 53;
        add("udp", ip, dp, "dns leg");
        add("tcp", ip, dp, "dns leg");
      }
    }
    add("tcp", CHANNEL_HOST, CHANNEL_PORT, "runner channel");
  } else if (c.type === "runner" && speedtestSiteActive(w, host.site)) {
    const corr = isObj(c.config.correlation) ? c.config.correlation : {};
    const sys = isObj(corr.sources) && isObj(corr.sources.syslog) ? corr.sources.syslog : {};
    const bind = typeof sys.bind === "string" ? sys.bind : ANY;
    for (const e of Array.isArray(sys.listen) ? sys.listen : DEFAULT_SYSLOG_LISTEN) {
      const m = /^(udp|tcp|tls):(\d{1,5})$/.exec(String(e));
      if (m) add(m[1] === "udp" ? "udp" : "tcp", bind, Number(m[2]), `syslog ${m[1]}`);
    }
  }
  return out;
}

const overlaps = (a: string, b: string): boolean => a === b || a === ANY || b === ANY;

/** Human-readable collisions among the components of one host (empty = fine). Deterministic order. */
export function portConflicts(w: World, hostId: string): string[] {
  const host = w.hosts[hostId];
  if (!host) return [];
  const all = w.components
    .filter((c) => c.host_id === hostId && c.enabled)
    .sort((a, b) => (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : a.slug < b.slug ? -1 : 1))
    .flatMap((c) => bindingsOf(w, c, host));
  const out: string[] = [];
  for (let i = 0; i < all.length; i++) {
    for (let j = i + 1; j < all.length; j++) {
      const a = all[i] as Binding;
      const b = all[j] as Binding;
      if (a.proto === b.proto && a.port === b.port && overlaps(a.ip, b.ip) && a.component !== b.component) {
        out.push(`${a.proto}/${a.port}: ${a.component} (${a.what}, ${a.ip}) collides with ${b.component} (${b.what}, ${b.ip})`);
      }
    }
  }
  return out;
}

// ---- documents --------------------------------------------------------------------------------------------------
const pick = (src: Obj, keys: string[]): Obj => {
  const out: Obj = {};
  for (const k of keys) if (src[k] !== undefined) out[k] = src[k];
  return out;
};

const SPEEDTEST_KEYS = ["zones", "zone_labels", "branding", "display", "targets", "limits", "internet_leg", "dns_leg", "path", "privacy", "core_guard"];

/**
 * exp.speedtest.config/1 of one speedtest component. `collector` is the already resolved reference (url + pin).
 * Returns the config or a reason string (component not compiled).
 */
export function speedtestConfig(
  w: World,
  c: WComponent,
  host: WHost,
  collector: { url: string; pin: string },
): { config: Obj } | { error: string } {
  const st = siteSpeedtest(w, host.site);
  const settings = st?.settings ?? {};
  const serve = effectiveServe(w, c);
  if (typeof serve.listen_ip !== "string" || !serve.listen_ip) return { error: "serve.listen_ip is required (the box's routed interface address)" };
  if (typeof serve.hostname !== "string") return { error: "serve.hostname is required" };
  const mode = tlsMode(w, c);
  const branding: Obj = isObj(settings.branding) ? { ...settings.branding } : {};
  if (st?.logo) branding.logo_artifact = st.logo.artifact.artifact_id;
  else delete branding.logo_artifact;
  const zones = Array.isArray(settings.zone_labels && (settings.zone_labels as Obj).subnets) ? ((settings.zone_labels as Obj).subnets as Obj[]) : [];
  const serveOut: Obj = { ...serve };
  // NAT guard input (12 section 3, CR-m6-spec-resolutions A.6): attendee subnets default to the zone-label subnets
  if (serveOut.client_subnets === undefined && zones.length > 0) serveOut.client_subnets = zones.map((z) => z.cidr).slice(0, 64);
  const internet: Obj = { ...(isObj(settings.internet_leg) ? settings.internet_leg : {}), paused: st?.paused === true };
  const config: Obj = {
    schema: "exp.speedtest.config/1",
    speedtest_id: c.slug,
    site: host.site,
    ...pick({ ...settings, branding: Object.keys(branding).length ? branding : undefined, internet_leg: internet }, SPEEDTEST_KEYS),
    consent: { text: st?.consent.text || DEFAULT_CONSENT_TEXT, version: st && st.consent.text ? st.consent.version : 1 },
    serve: serveOut,
    tls: { mode },
    collector: { url: collector.url, tls_fingerprint_sha256: collector.pin, fallback: [] },
    local_channel: { listen: CHANNEL_LISTEN },
  };
  return { config };
}

/** Credentials of a speedtest (the caller checked the speedtest token exists). */
export function speedtestCreds(w: World, c: WComponent, host: WHost): { creds: Record<string, string>; error?: string } {
  const creds: Record<string, string> = {};
  const tok = w.secrets[secretKey(c.component_id, SPEEDTEST_TOKEN_KIND)];
  if (tok) creds.collector_token = tok.plaintext;
  const r = runnerOfSpeedtest(w, c);
  const ch = r ? w.secrets[secretKey(pairOwner(r.component_id, c.component_id), CHANNEL_TOKEN_KIND)] : undefined;
  if (ch?.hash) creds.runner_channel_token_sha256 = ch.hash;
  if (tlsMode(w, c) === "provided") {
    const pair = speedtestTlsPair(w, host.site);
    if (!pair) return { creds, error: "tls.mode is provided but no certificate pair was uploaded (PUT sites/{site}/speedtest/tls)" };
    creds["tls.crt"] = pair.cert_pem;
    creds["tls.key"] = pair.key_pem;
  }
  return { creds };
}

const CORR_KEYS = ["window_before_s", "window_after_s", "poll_interval_s"];

/**
 * The runner's `correlation` block, or null when the site runs no speedtest analytics (a plain M5/M3 runner is
 * left exactly as before). Connector sources come from the runner component's own config; SSE is forced off
 * (CR-m6-spec-resolutions A.8); the privacy setting is the site's one org setting; the channel is localhost.
 */
export function runnerCorrelation(w: World, c: WComponent, host: WHost): Obj | null {
  if (!speedtestSiteActive(w, host.site)) return null;
  const base = isObj(c.config.correlation) ? c.config.correlation : {};
  const srcIn = isObj(base.sources) ? base.sources : {};
  const sources: Obj = { ...pick(srcIn, ["mist", "ec", "syslog"]), sse: { enabled: false } };
  const st = siteSpeedtest(w, host.site);
  const privacy = isObj(st?.settings.privacy) ? (st?.settings.privacy as Obj) : {};
  const sp = speedtestOfRunner(w, c);
  return {
    enabled: base.enabled === false ? false : true,
    ...pick(base, CORR_KEYS),
    sources,
    privacy: { scrub_after_diagnosis: privacy.scrub_after_diagnosis === true },
    ...(sp ? { speedtest_channel: { url: CHANNEL_URL } } : {}),
  };
}

/** integrations.json of the runner: `{ec: {url, api_key}, mist: {api_base, token}}`, only complete connectors (01-contracts.md section 9.4). */
export function integrationsJson(w: World): string {
  const out: Obj = {};
  const ec = w.integrations?.ec;
  const ecUrl = ec && (ec.config.url ?? ec.config.api_base ?? ec.config.base_url);
  if (ec && typeof ecUrl === "string" && ec.credentials.api_key) out.ec = { url: ecUrl, api_key: ec.credentials.api_key };
  const mist = w.integrations?.mist;
  const mistUrl = mist && (mist.config.api_base ?? mist.config.url ?? mist.config.base_url);
  if (mist && typeof mistUrl === "string" && mist.credentials.token) out.mist = { api_base: mistUrl, token: mist.credentials.token };
  return canonicalJson(out);
}

/** collector.config `speedtests` block for the speedtests + runners attached to a collector. */
export function collectorSpeedtests(w: World, site: string, speedtests: WComponent[], runners: WComponent[]): Obj {
  const st = siteSpeedtest(w, site);
  const s = st?.settings ?? {};
  const privacy = isObj(s.privacy) ? s.privacy : {};
  return {
    enabled: true,
    speedtests: speedtests.map((x) => x.slug).slice(0, 8),
    runners: runners.map((x) => x.slug).slice(0, 8),
    ...pick(privacy, ["retention_days"]),
    scrub_after_diagnosis: privacy.scrub_after_diagnosis === true,
    ...(isObj(s.targets) ? { targets: s.targets } : {}),
  };
}
