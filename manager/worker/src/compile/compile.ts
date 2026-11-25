// compile(world, host_id): the desired-state compiler (05-manager.md section 7). PURE: no I/O, no clock,
// no randomness; the same World always yields the same body. version / generated_at are assigned by
// the persister only when the canonical-JSON hash of the body changes (no churn on no-op changes).
import { canonicalJson } from "../util/canonical";
import {
  type CompileResult,
  type DesiredBody,
  type DesiredComponent,
  type WArtifact,
  type WComponent,
  type WHost,
  type WSecret,
  type WSite,
  type World,
  secretKey,
} from "./types";
import {
  CHANNEL_TOKEN_KIND,
  DASH_TOKEN_KIND,
  DEVICE_KEY_KIND,
  DEVICE_KEY_OWNER,
  INGEST_KIND,
  RUNNER_TOKEN_KIND,
  SPEEDTEST_TOKEN_KIND,
  SSO_KIND,
  TLS_KIND,
  WEBHOOK_KIND,
  collectorEndpoint,
  collectorFor,
  collectorsOfDashboard,
  componentsOf,
  dashboardsOfCollector,
  hostOf,
  mgmtIface,
  mgmtIp,
  pairOwner,
  probesOfCollector,
  runnersOfCollector,
  speedtestOfRunner,
  speedtestsOfCollector,
} from "./wiring";
import { collectorSpeedtests, integrationsJson, portConflicts, runnerCorrelation, speedtestConfig, speedtestCreds } from "./speedtest";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

/** Version a host should run: the canary host gets the target version first. */
export function effectiveVersion(site: WSite, hostId: string): string | null {
  if (site.canary_state === "canary" && site.target_version && site.canary_host_id === hostId) return site.target_version;
  return site.release_version;
}

/** Artifact by component + host arch, `noarch` as fallback. */
export function pickArtifact(arts: WArtifact[], version: string, component: string, arch: string | null): WArtifact | null {
  const cands = arts.filter((a) => a.version === version && a.component === component);
  return (arch ? cands.find((a) => a.arch === arch) : undefined) ?? cands.find((a) => a.arch === "noarch") ?? null;
}

const artifactRef = (a: WArtifact) => ({
  id: a.artifact_id,
  name: a.name,
  url: `/api/agent/v1/artifacts/${a.artifact_id}`,
  sha256: a.sha256,
  size: a.size,
});

/** `{owner: hash}`; during a rotation overlap the value is the list [current, previous]. */
function hashMap(entries: Array<[string, WSecret | undefined]>): Obj {
  const out: Obj = {};
  for (const [k, s] of entries) {
    if (!s || !s.hash) continue;
    out[k] = s.previous_hash ? [s.hash, s.previous_hash] : s.hash;
  }
  return out;
}

const pick = (src: Obj, keys: string[]): Obj => {
  const out: Obj = {};
  for (const k of keys) if (src[k] !== undefined) out[k] = src[k];
  return out;
};

interface Ctx {
  w: World;
  host: WHost;
  site: WSite;
  version: string;
  warnings: string[];
}

function dashboardUrl(ctx: Ctx, d: WComponent): string | null {
  if (typeof d.config.url === "string") return d.config.url;
  // agent-reported facts.url is informational only: it is never a handoff or alert-link target
  const ip = mgmtIp(hostOf(ctx.w, d));
  return ip ? `https://${ip}` : null;
}

// ---- per-type config builders ----------------------------------------------------------------
function probePeers(ctx: Ctx, cfg: Obj, collector: WComponent | null): Obj {
  const tests = isObj(cfg.tests) ? { ...cfg.tests } : null;
  if (!tests) return cfg;
  // target ports (with serve.reflector / iperf3) of probes in the same site
  const targets: Array<{ id: string; ip: string; reflector: boolean; iperf3: boolean }> = [];
  for (const p of componentsOf(ctx.w, "probe")) {
    if (hostOf(ctx.w, p)?.site !== ctx.host.site) continue;
    for (const port of Array.isArray(p.config.ports) ? p.config.ports : []) {
      if (!isObj(port) || port.role !== "target" || typeof port.address !== "string" || typeof port.id !== "string") continue;
      const serve = isObj(port.serve) ? port.serve : {};
      targets.push({
        id: port.id,
        ip: port.address.split("/")[0] ?? "",
        reflector: serve.reflector === true,
        iperf3: serve.iperf3 === true,
      });
    }
  }
  if (isObj(tests.path)) {
    const path = { ...tests.path };
    const peers = Array.isArray(path.peers) ? path.peers : [];
    if (peers.length === 0) {
      const t = targets.find((x) => x.reflector);
      if (t) {
        path.peers = [{ peer: t.id, address: t.ip, port: 8862, proto: ["udp", "tcp"], duration_s: 10, rate_kbps: 256 }];
      } else if (ctx.site.event_net_reaches_mgmt && collector?.facts.listen) {
        const rp = isObj(collector.config.reflector) && typeof collector.config.reflector.port === "number" ? collector.config.reflector.port : 8862;
        path.peers = [
          { peer: collector.slug, address: collector.facts.listen.split(":")[0] ?? "", port: rp, proto: ["udp", "tcp"], duration_s: 10, rate_kbps: 256 },
        ];
      } else {
        path.peers = [];
      }
    }
    tests.path = path;
  }
  if (isObj(tests.throughput) && isObj(tests.throughput.iperf3) && !tests.throughput.iperf3.server) {
    const t = targets.find((x) => x.iperf3);
    if (t) tests.throughput = { ...tests.throughput, iperf3: { ...tests.throughput.iperf3, server: t.id } };
  }
  return { ...cfg, tests };
}

/** The ports the probe gets: without the manager-only board fields (CR-site-lines-board). */
function probePorts(ports: unknown): unknown {
  if (!Array.isArray(ports)) return ports;
  return ports.map((p) => {
    if (!isObj(p)) return p;
    const { network: _n, reference: _r, ...rest } = p;
    return rest;
  });
}

/** The collector's board map of one probe: ports that carry a network label (CR-site-lines-board). */
export function boardPorts(cfg: Obj): Array<{ id: string; network: string; media: "wired" | "wireless"; reference: boolean }> {
  const ports = Array.isArray(cfg.ports) ? cfg.ports : [];
  const out: Array<{ id: string; network: string; media: "wired" | "wireless"; reference: boolean }> = [];
  for (const p of ports) {
    if (!isObj(p) || typeof p.id !== "string" || typeof p.network !== "string" || !p.network) continue;
    if (p.role !== "client" && p.role !== "wifi") continue;          // target ports serve tests, they are not attendees
    out.push({ id: p.id, network: p.network, media: p.role === "wifi" ? "wireless" : "wired", reference: p.reference === true });
  }
  return out.slice(0, 64);
}

function buildProbe(ctx: Ctx, c: WComponent): { config: Obj; creds: Obj } | null {
  const { w, host } = ctx;
  const cfg = c.config;
  const iface = (typeof cfg.mgmt_iface === "string" && cfg.mgmt_iface) || mgmtIface(host);
  if (!iface) {
    ctx.warnings.push(`probe ${c.slug}: management interface unknown (no facts, no mgmt_iface); component not compiled`);
    return null;
  }
  const collector = collectorFor(w, c);
  const ep = collectorEndpoint(collector);
  let ports = Array.isArray(cfg.ports) ? cfg.ports : [];
  // defence in depth: the management interface is never handed to the probe as a test port
  const kept = ports.filter((p) => !(isObj(p) && p.iface === iface));
  if (kept.length !== ports.length) ctx.warnings.push(`probe ${c.slug}: dropped port(s) on management interface ${iface}`);
  ports = kept;
  if (ports.length === 0) {
    // CR-wp5-admin-ui-intent: ports are assigned after enrolment; exp.probe.config/1 needs >= 1 port, so the probe is not started yet
    ctx.warnings.push(`probe ${c.slug}: no test ports assigned yet; component not compiled`);
    return null;
  }
  const base = probePeers(ctx, { ...cfg, ports }, collector);
  const config: Obj = {
    schema: "exp.probe.config/1",
    probe_id: c.slug,
    site: host.site,
    collector: ep ? { url: ep.url, tls_fingerprint_sha256: ep.pin, fallback: [] } : null,
    mode: typeof cfg.mode === "string" ? cfg.mode : "netns",
    mgmt_iface: iface,
    ports: probePorts(base.ports),
    ...pick(base, ["heartbeat", "tests", "spool", "labels", "drills"]),
  };
  const tok = w.secrets[secretKey(c.component_id, INGEST_KIND)];
  if (!tok) {
    ctx.warnings.push(`probe ${c.slug}: ingest token not provisioned`);
    return null;
  }
  return { config, creds: { ingest_token: tok.plaintext } };
}

function buildCollector(ctx: Ctx, c: WComponent): { config: Obj; creds: Obj } | null {
  const { w, site } = ctx;
  const cfg = c.config;
  const ip = mgmtIp(ctx.host);
  const listen = (typeof cfg.listen === "string" && cfg.listen) || (ip ? `${ip}:8443` : null);
  if (!listen) {
    ctx.warnings.push(`collector ${c.slug}: listen address unknown (no facts, no listen); component not compiled`);
    return null;
  }
  const probes = probesOfCollector(w, c).sort((a, b) => (a.slug < b.slug ? -1 : 1));
  const runners = runnersOfCollector(w, c).sort((a, b) => (a.slug < b.slug ? -1 : 1));
  const speedtests = speedtestsOfCollector(w, c).sort((a, b) => (a.slug < b.slug ? -1 : 1));
  const dashes = dashboardsOfCollector(w, c).sort((a, b) => (a.slug < b.slug ? -1 : 1));
  const withUrl = dashes.map((d) => dashboardUrl(ctx, d)).find((u) => !!u) ?? null;
  const rulesCfg = isObj(cfg.rules) ? cfg.rules : {};
  const alerts: Obj = {
    ...(isObj(site.alerts) ? pick(site.alerts, ["enabled", "board_url", "timezone", "voice", "hold_down_s", "hold_back_s", "reopen_s", "calm_s", "webhook_allow"]) : {}),
    ...(isObj(cfg.alerts) ? cfg.alerts : {}),
  };
  if (Array.isArray(alerts.webhook_allow) && alerts.webhook_allow.length === 0) delete alerts.webhook_allow;
  if (alerts.board_url === undefined && withUrl) alerts.board_url = withUrl;
  if (alerts.timezone === undefined) alerts.timezone = site.timezone;
  const config: Obj = {
    schema: "exp.collector.config/1",
    collector_id: c.slug,
    site: ctx.host.site,
    listen,
    probes: probes.map((p) => {
      const label = typeof p.config.label === "string" ? p.config.label : undefined;
      const ports = boardPorts(p.config);
      return {
        probe_id: p.slug, site: hostOf(w, p)?.site ?? ctx.host.site,
        ...(label !== undefined ? { label } : {}),
        ...(ports.length ? { ports } : {}),
      };
    }),
    dashboards: dashes.map((d) => d.slug),
    ...(isObj(cfg.retention) || Object.keys(site.retention).length
      ? { retention: { ...pick(site.retention, ["metrics_days", "records_days"]), ...(isObj(cfg.retention) ? cfg.retention : {}) } }
      : {}),
    ...pick(cfg, ["vm", "reflector", "iperf3", "ingest"]),
    rules: { edge_label: site.edge_label, ...(Array.isArray(rulesCfg.lines) ? { lines: rulesCfg.lines } : {}) },
    alerts,
    // M6: the speedtest block exists only when a speedtest reports here; it is what makes the collector accept exps_/expr_
    ...(speedtests.length > 0 ? { speedtests: collectorSpeedtests(w, ctx.host.site, speedtests, runners) } : {}),
  };
  const ingest: Array<[string, WSecret | undefined]> = [
    ...probes.map((p): [string, WSecret | undefined] => [p.slug, w.secrets[secretKey(p.component_id, INGEST_KIND)]]),
    ...runners.map((p): [string, WSecret | undefined] => [p.slug, w.secrets[secretKey(p.component_id, INGEST_KIND)]]),
  ];
  const dash: Array<[string, WSecret | undefined]> = dashes.map((d) => [
    d.slug,
    w.secrets[secretKey(pairOwner(d.component_id, c.component_id), DASH_TOKEN_KIND)],
  ]);
  const hooks = w.webhooks
    .filter((h) => h.site === ctx.host.site)
    .sort((a, b) => (a.webhook_id < b.webhook_id ? -1 : 1))
    .flatMap((h) => {
      const url = w.secrets[secretKey(h.webhook_id, WEBHOOK_KIND)];
      return url ? [{ id: h.webhook_id, format: h.format, url: url.plaintext }] : [];
    });
  const devKey = w.secrets[secretKey(DEVICE_KEY_OWNER, DEVICE_KEY_KIND)];
  const m6: Record<string, string> =
    speedtests.length > 0
      ? {
          "speedtest_tokens.json": canonicalJson(hashMap(speedtests.map((p): [string, WSecret | undefined] => [p.slug, w.secrets[secretKey(p.component_id, SPEEDTEST_TOKEN_KIND)]]))),
          "runner_tokens.json": canonicalJson(hashMap(runners.map((p): [string, WSecret | undefined] => [p.slug, w.secrets[secretKey(p.component_id, RUNNER_TOKEN_KIND)]]))),
          // optional: lets purge-by-MAC reach rows whose raw MAC was scrubbed (CR-m6-spec-resolutions B.8)
          ...(devKey ? { device_key_secret: devKey.plaintext } : {}),
        }
      : {};
  return {
    config,
    creds: {
      "ingest_tokens.json": canonicalJson(hashMap(ingest)),
      "dashboard_tokens.json": canonicalJson(hashMap(dash)),
      "webhooks.json": canonicalJson(hooks),
      ...m6,
    },
  };
}

function buildDashboard(ctx: Ctx, c: WComponent): { config: Obj; creds: Obj } | null {
  const { w, site } = ctx;
  const cfg = c.config;
  const url = dashboardUrl(ctx, c);
  if (!url) {
    ctx.warnings.push(`dashboard ${c.slug}: url unknown (no url, no management address); component not compiled`);
    return null;
  }
  const collectors: Obj[] = [];
  const tokens: Obj = {};
  for (const col of collectorsOfDashboard(w, c)) {
    const ep = collectorEndpoint(col);
    if (!ep) continue; // not yet reported listen + pin: left out until it has
    const tok = w.secrets[secretKey(pairOwner(c.component_id, col.component_id), DASH_TOKEN_KIND)];
    if (!tok) continue;
    collectors.push({ collector_id: col.slug, site: hostOf(w, col)?.site ?? ctx.host.site, url: ep.url, tls_fingerprint_sha256: ep.pin });
    tokens[col.slug] = tok.plaintext;
  }
  const sso = w.secrets[secretKey(c.component_id, SSO_KIND)];
  if (!sso) {
    ctx.warnings.push(`dashboard ${c.slug}: sso_secret not provisioned`);
    return null;
  }
  const authCfg = isObj(cfg.auth) ? cfg.auth : {};
  const auth: Obj = {
    ...(w.manager_url ? { sso: { manager_url: w.manager_url, issuer: `exp-manager:${w.org.id}` } } : {}),
    session_hours: typeof authCfg.session_hours === "number" ? authCfg.session_hours : 12,
    local_users: typeof authCfg.local_users === "boolean" ? authCfg.local_users : true,
    noc_tokens: typeof authCfg.noc_tokens === "boolean" ? authCfg.noc_tokens : true,
  };
  if (!w.manager_url) ctx.warnings.push(`dashboard ${c.slug}: manager URL unknown, SSO handoff not configured`);
  // Provided TLS (CR p2): the admin-uploaded pair is the only thing that selects tls.mode = provided. A config
  // that merely says "provided" without a stored pair would leave the dashboard without a certificate, so it
  // stays self_signed (with a warning) until a pair is uploaded.
  const tlsSecret = w.secrets[secretKey(c.component_id, TLS_KIND)];
  let provided: { cert_pem: string; key_pem: string } | null = null;
  if (tlsSecret) {
    try {
      const j = JSON.parse(tlsSecret.plaintext) as { cert_pem?: unknown; key_pem?: unknown };
      if (typeof j.cert_pem === "string" && typeof j.key_pem === "string") provided = { cert_pem: j.cert_pem, key_pem: j.key_pem };
    } catch {
      /* fall through to the warning */
    }
    if (!provided) ctx.warnings.push(`dashboard ${c.slug}: stored TLS pair is unreadable; using a self-signed certificate`);
  } else if (isObj(cfg.tls) && cfg.tls.mode === "provided") {
    ctx.warnings.push(`dashboard ${c.slug}: tls.mode is provided but no certificate was uploaded; using a self-signed certificate`);
  }
  const config: Obj = {
    schema: "exp.dashboard.config/1",
    dashboard_id: c.slug,
    title: typeof cfg.title === "string" ? cfg.title : `${w.org.name || "EXP"} - ${site.name}`,
    url,
    listen: isObj(cfg.listen) ? cfg.listen : { https: "0.0.0.0:443", http_redirect: "0.0.0.0:80" },
    collectors,
    ...(typeof cfg.voice === "string" ? { voice: cfg.voice } : {}),
    timezone: typeof cfg.timezone === "string" ? cfg.timezone : site.timezone,
    auth,
    tls: { mode: provided ? "provided" : "self_signed" },
  };
  const users = w.dashboard_users
    .filter((u) => u.dashboard_slug === c.slug)
    .sort((a, b) => (a.username < b.username ? -1 : 1))
    .map((u) => ({ username: u.username, role: u.role, hash: u.hash }));
  const nocs = w.noc_tokens
    .filter((t) => t.dashboard_slug === c.slug && !t.revoked_at && (!t.expires_at || t.expires_at > w.now))
    .sort((a, b) => (a.noc_id < b.noc_id ? -1 : 1))
    .map((t) => ({ id: t.noc_id, sha256: t.hash, label: t.label, role: "viewer", expires: t.expires_at }));
  return {
    config,
    creds: {
      "collector_tokens.json": canonicalJson(tokens),
      sso_secret: sso.plaintext,
      "local_users.json": canonicalJson(users),
      "noc_tokens.json": canonicalJson(nocs),
      ...(provided ? { "tls.crt": provided.cert_pem, "tls.key": provided.key_pem } : {}),
    },
  };
}

function buildRunner(ctx: Ctx, c: WComponent): { config: Obj; creds: Obj } | null {
  const { w, host } = ctx;
  const ep = collectorEndpoint(collectorFor(w, c));
  if (!ep) {
    ctx.warnings.push(`runner ${c.slug}: collector has not reported listen + TLS pin yet; component not compiled`);
    return null;
  }
  const tok = w.secrets[secretKey(c.component_id, INGEST_KIND)];
  if (!tok) {
    ctx.warnings.push(`runner ${c.slug}: ingest token not provisioned`);
    return null;
  }
  const cfg = c.config;
  const correlation = runnerCorrelation(w, c, host);
  const creds: Record<string, string> = { ingest_token: tok.plaintext, "integrations.json": integrationsJson(w) };
  // M6: the runner's own collector token (expr_), the org device_key secret and the localhost channel token
  const rt = w.secrets[secretKey(c.component_id, RUNNER_TOKEN_KIND)];
  const dk = w.secrets[secretKey(DEVICE_KEY_OWNER, DEVICE_KEY_KIND)];
  const sp = speedtestOfRunner(w, c);
  const ch = sp ? w.secrets[secretKey(pairOwner(c.component_id, sp.component_id), CHANNEL_TOKEN_KIND)] : undefined;
  if (rt) creds.collector_token = rt.plaintext;
  if (dk) creds.device_key_secret = dk.plaintext;
  if (ch) creds.speedtest_channel_token = ch.plaintext;
  if (correlation && (!rt || !dk || (sp && !ch))) {
    ctx.warnings.push(`runner ${c.slug}: correlation credentials not provisioned yet; component not compiled`);
    return null;
  }
  return {
    config: {
      schema: "exp.runner.config/1",
      runner_id: c.slug,
      site: host.site,
      collector: { url: ep.url, tls_fingerprint_sha256: ep.pin, fallback: [] },
      drills_enabled: cfg.drills_enabled === true,
      pullers: Array.isArray(cfg.pullers) ? cfg.pullers : [],
      allowlist: isObj(cfg.allowlist) ? cfg.allowlist : {},
      drills: Array.isArray(cfg.drills) ? cfg.drills : [],
      ...(correlation ? { correlation } : {}),
    },
    creds,
  };
}

function buildSpeedtest(ctx: Ctx, c: WComponent): { config: Obj; creds: Obj; assets: NonNullable<DesiredComponent["assets"]> } | null {
  const { w, host } = ctx;
  const ep = collectorEndpoint(collectorFor(w, c));
  if (!ep) {
    ctx.warnings.push(`speedtest ${c.slug}: collector has not reported listen + TLS pin yet; component not compiled`);
    return null;
  }
  if (!w.secrets[secretKey(c.component_id, SPEEDTEST_TOKEN_KIND)]) {
    ctx.warnings.push(`speedtest ${c.slug}: collector token not provisioned`);
    return null;
  }
  const cfg = speedtestConfig(w, c, host, ep);
  if ("error" in cfg) {
    ctx.warnings.push(`speedtest ${c.slug}: ${cfg.error}; component not compiled`);
    return null;
  }
  const cr = speedtestCreds(w, c, host);
  if (cr.error) {
    ctx.warnings.push(`speedtest ${c.slug}: ${cr.error}; component not compiled`);
    return null;
  }
  const logo = w.speedtest?.[host.site]?.logo ?? null;
  return { config: cfg.config, creds: cr.creds, assets: logo ? [{ name: "logo", content_type: logo.content_type, artifact: artifactRef(logo.artifact) }] : [] };
}

/** Minimal document for an enrolled host with nothing to run yet: no release, no components. */
export function bareBody(world: World, hostId: string): DesiredBody | null {
  const host = world.hosts[hostId];
  const site = host ? world.sites[host.site] : undefined;
  if (!host || !site || host.state === "pending" || host.state === "removed") return null;
  return {
    schema: "exp.desired/1",
    host_id: hostId,
    org: { id: world.org.id, name: world.org.name },
    site: { id: site.site, name: site.name, timezone: site.timezone },
    components: [],
    actions: host.state === "decommissioning" ? [] : host.actions.map((a) => ({ ...a })),
    decommission: host.state === "decommissioning",
  };
}

const TYPE_ORDER: Record<string, number> = { collector: 0, dashboard: 1, probe: 2, runner: 3, speedtest: 4 };

export function compile(world: World, hostId: string): CompileResult {
  const warnings: string[] = [];
  const host = world.hosts[hostId];
  if (!host) return { doc: null, warnings: [`unknown host ${hostId}`] };
  if (host.state === "pending" || host.state === "removed") return { doc: null, warnings: [`host ${hostId} is ${host.state}`] };
  const site = world.sites[host.site];
  if (!site) return { doc: null, warnings: [`host ${hostId}: unknown site ${host.site}`] };

  const arch = host.arch ?? host.facts.arch ?? null;
  const decommission = host.state === "decommissioning";
  const comps = world.components
    .filter((c) => c.host_id === hostId && c.enabled)
    .sort((a, b) => (TYPE_ORDER[a.type] ?? 9) - (TYPE_ORDER[b.type] ?? 9) || (a.slug < b.slug ? -1 : a.slug > b.slug ? 1 : 0));

  const version = effectiveVersion(site, hostId);
  const body: DesiredBody = {
    schema: "exp.desired/1",
    host_id: hostId,
    org: { id: world.org.id, name: world.org.name },
    site: { id: site.site, name: site.name, timezone: site.timezone },
    components: [],
    actions: decommission ? [] : host.actions.map((a) => ({ ...a })),
    decommission,
  };

  if (!version) {
    // No release chosen for this site. Hosts without components get a bare document (the agent just
    // idles); a host that already has components is held rather than told to remove them.
    if (comps.length > 0 && !decommission) {
      return { doc: null, warnings: [...warnings, `site ${site.site}: no release version set; host ${hostId} held`] };
    }
    return { doc: body, warnings };
  }

  const agentArt = pickArtifact(world.artifacts, version, "agent", arch);
  if (!agentArt) {
    return { doc: null, warnings: [...warnings, `release ${version}: no agent artifact for arch ${arch ?? "unknown"}; host ${hostId} held`] };
  }
  body.agent = {
    version,
    artifact: agentArt.artifact_id,
    poll_interval_s: world.settings.agent_poll_interval_s,
    status_interval_s: world.settings.agent_status_interval_s,
  };
  body.release = {
    version,
    manifest_url: `/api/agent/v1/releases/${version}/manifest`,
    signature_url: `/api/agent/v1/releases/${version}/manifest.sig`,
  };
  if (decommission) return { doc: body, warnings };

  const ctx: Ctx = { w: world, host, site, version, warnings };
  // all-in-one profile (D15): one host runs probe + collector + runner + speedtest; their listeners must not collide.
  // A colliding speedtest is left out (fail closed) with the reason; the admin API refuses such a layout up front.
  const collisions = comps.some((c) => c.type === "speedtest") ? portConflicts(world, hostId) : [];
  for (const m of collisions) warnings.push(`host ${hostId}: port collision, speedtest not compiled: ${m}`);
  for (const c of comps) {
    if (c.type === "speedtest" && collisions.length > 0) continue;
    const art = pickArtifact(world.artifacts, version, c.type, arch);
    if (!art) {
      return { doc: null, warnings: [...warnings, `release ${version}: no ${c.type} artifact for arch ${arch ?? "unknown"}; host ${hostId} held`] };
    }
    const built =
      c.type === "probe" ? buildProbe(ctx, c)
      : c.type === "collector" ? buildCollector(ctx, c)
      : c.type === "dashboard" ? buildDashboard(ctx, c)
      : c.type === "speedtest" ? buildSpeedtest(ctx, c)
      : buildRunner(ctx, c);
    if (!built) continue;
    const comp: DesiredComponent = {
      type: c.type,
      id: c.slug,
      component_id: c.component_id,
      version,
      artifact: artifactRef(art),
      config: built.config,
      creds: built.creds as Record<string, string>,
    };
    const assets = (built as { assets?: DesiredComponent["assets"] }).assets;
    if (assets && assets.length > 0) comp.assets = assets;
    body.components.push(comp);
  }
  return { doc: body, warnings };
}
