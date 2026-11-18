// Deterministic demo / perf fleet for LOCAL D1 (docs/spec/11-manager-ui.md section 10).
// Pure: buildSeed({scale, nowMs}) -> single-line SQL statements. No randomness, no clock reads: the same inputs
// give byte-identical output. Entities (sites, hosts, components, issues) are literal INSERTs; roll-ups are
// generated INSIDE SQLite with recursive CTEs from a small per-host profile, so 500 hosts x 30 days does not need a
// 100 MB SQL file. Erasable TypeScript only (it also runs under `node --experimental-strip-types`).

export interface SeedOptions {
  /** number of hosts (default 48). 500 is the perf scale. */
  scale: number;
  /** "now" the data is anchored to (ms since epoch) */
  nowMs: number;
}

export interface SeedResult {
  /** DELETE statements that empty every table the seed writes (and the tables holding state derived from it) */
  reset: string[];
  /** INSERT statements, each a single line of at most MAX_STMT bytes */
  statements: string[];
  summary: SeedSummary;
}

export interface SeedSummary {
  hosts: number;
  sites: number;
  components: number;
  probes: number;
  issues_open: number;
  /** names of the hosts that carry the scenarios (for tests and the README) */
  scenarios: Record<string, string>;
  host_ids: string[];
}

export const MAX_STMT = 90_000;
const STEP_5M = 300;
const STEP_1H = 3600;
const HOUR_BUCKETS = 720; // 30 days of hourly roll-ups
const FIVE_BUCKETS = 576; // 48 h of 5-minute roll-ups (plus the current partial bucket)

const AGENT_NEW = "0.1.1";
const AGENT_OLD = "0.1.0";
const DESIRED_VERSION = 12;

// ---- small helpers ------------------------------------------------------------------------------------
const sq = (s: string): string => `'${s.replace(/'/g, "''")}'`;
const jq = (v: unknown): string => sq(JSON.stringify(v));
const num = (n: number | null | undefined): string => (n === null || n === undefined || !Number.isFinite(n) ? "NULL" : String(Math.round(n * 1000) / 1000));
const iso = (ms: number): string => new Date(ms).toISOString();
const pad = (n: number, w: number): string => String(n).padStart(w, "0");

/** ids that satisfy the Worker's ULID patterns (Crockford base32, 26 chars) and are recognisably seeded */
const hostId = (i: number): string => `h_${"0".repeat(12)}SEED${pad(i, 10)}`;
const compId = (i: number): string => `cmp_${"0".repeat(12)}SEED${pad(i, 10)}`;
const issueId = (i: number): string => `iss_${"0".repeat(12)}SEED${pad(i, 10)}`;
const artId = (i: number): string => `art_${"0".repeat(12)}SEED${pad(i, 10)}`;
const relId = (i: number): string => `rel_${"0".repeat(12)}SEED${pad(i, 10)}`;

const sha = (seed: string): string => {
  // not cryptographic: a stable 64-hex string derived from a seed (FNV-1a stretched), for demo hashes
  let h = 0x811c9dc5;
  let out = "";
  for (let r = 0; out.length < 64; r++) {
    for (let i = 0; i < seed.length; i++) h = Math.imul(h ^ seed.charCodeAt(i), 0x01000193) >>> 0;
    h = Math.imul(h ^ r, 0x01000193) >>> 0;
    out += h.toString(16).padStart(8, "0");
  }
  return out.slice(0, 64);
};
const fingerprint = (seed: string): string => (sha(seed) + sha(seed + "x")).toUpperCase().slice(0, 64).replace(/(..)(?!$)/g, "$1:");

interface SiteDef {
  site: string;
  name: string;
  tz: string;
  edge: string;
  octet: number;
}
const SITES: SiteDef[] = [
  { site: "hall-a", name: "Hall A", tz: "UTC", edge: "EC", octet: 31 },
  { site: "hall-b", name: "Hall B", tz: "Europe/Berlin", edge: "EC", octet: 32 },
  { site: "hall-c", name: "Hall C", tz: "America/New_York", edge: "EC", octet: 33 },
];

type Shape = "collector" | "dashboard" | "probe" | "runner" | "combo";
interface CompDef {
  id: string;
  type: "probe" | "collector" | "dashboard" | "runner";
  slug: string;
  config: Record<string, unknown>;
  health: "ok" | "degraded" | "fail";
  detail: string;
  metrics: Record<string, number>;
  process: Record<string, number>;
  facts: Record<string, string>;
  keys: string[];
}
interface HostDef {
  idx: number;
  id: string;
  name: string;
  site: SiteDef;
  shape: Shape;
  ip: string;
  state: "enrolled" | "stale" | "offline";
  lastSeenMs: number;
  agentVersion: string;
  appliedVersion: number;
  cpu: number;
  mem: number;
  diskPct: number;
  uptime: number;
  comps: CompDef[];
  ifaces: Array<{ name: string; in_use_by: string }>;
  timeSynced: boolean;
  offsetMs: number;
  reconcile: { result: "ok" | "error" | "rolled_back"; error: string | null };
  // roll-up profile
  cpuB: number;
  cpuA: number;
  memB: number;
  d0: number;
  d1: number;
  netS: number;
  wrB: number;
  endMs: number;
}

// ---- the fleet --------------------------------------------------------------------------------------------
export function buildSeed(opts: SeedOptions): SeedResult {
  const scale = Math.floor(opts.scale);
  if (!Number.isInteger(scale) || scale < 24 || scale > 5000) throw new Error("scale must be an integer between 24 and 5000");
  const now = opts.nowMs;
  const nowIso = iso(now);
  const hosts: HostDef[] = [];
  let nextComp = 1;
  const perSiteCount = [0, 0, 0];

  // scenario hosts are picked by (site, position in site); at least 4 positions exist at scale >= 24
  const scen: Record<string, string> = {};

  for (let i = 0; i < scale; i++) {
    const s = i % 3;
    const site = SITES[s] as SiteDef;
    const j = perSiteCount[s] as number;
    perSiteCount[s] = j + 1;
    let shape: Shape;
    // positions: 0 collector, 1 dashboard, 2 runner (hall-a only), every 40th position repeats collector/dashboard
    if (j % 40 === 0) shape = s === 1 && j === 0 ? "combo" : "collector";
    else if (j % 40 === 1) shape = "dashboard";
    else if (j === 2 && s === 0) shape = "runner";
    else shape = "probe";
    const slugBase = `${site.site}-${shape === "combo" ? "edge" : shape}-${pad(j, 2)}`;
    const id = hostId(i + 1);
    const ip = `10.${site.octet}.${Math.floor(j / 200)}.${10 + (j % 200)}`;
    const h: HostDef = {
      idx: i + 1,
      id,
      name: slugBase,
      site,
      shape,
      ip,
      state: "enrolled",
      lastSeenMs: now - ((i * 7) % 40) * 1000,
      agentVersion: AGENT_NEW,
      appliedVersion: DESIRED_VERSION,
      cpu: 0,
      mem: 0,
      diskPct: 0,
      uptime: 86400 * (3 + (i % 40)) + i * 37,
      comps: [],
      ifaces: [{ name: "eno1", in_use_by: "mgmt" }],
      timeSynced: true,
      offsetMs: 0.4 + (i % 7) * 0.3,
      reconcile: { result: "ok", error: null },
      cpuB: shape === "probe" ? 6 + ((i * 13) % 14) : 14 + ((i * 11) % 14),
      cpuA: shape === "probe" ? 8 + ((i * 7) % 12) : 22 + ((i * 5) % 16),
      memB: 28 + ((i * 17) % 30),
      d0: 22 + ((i * 29) % 40),
      d1: 0,
      netS: shape === "collector" || shape === "combo" ? 4 : shape === "probe" ? 1 : 0.5,
      wrB: shape === "collector" || shape === "combo" ? 400 : 20,
      endMs: now,
    };
    h.d1 = h.d0 + 0.4 + (i % 5) * 0.3; // slow drift over 30 days
    hosts.push(h);
  }

  // ---- components per host ---------------------------------------------------------------------------------
  const collectorOf = new Map<string, string>(); // site -> collector slug
  for (const h of hosts) {
    if ((h.shape === "collector" || h.shape === "combo") && !collectorOf.has(h.site.site)) collectorOf.set(h.site.site, `col-${h.site.site}`);
  }
  const probeCountBySite: Record<string, number> = {};
  for (const h of hosts) if (h.shape === "probe") probeCountBySite[h.site.site] = (probeCountBySite[h.site.site] ?? 0) + 1;

  const mkComp = (h: HostDef, type: CompDef["type"], slug: string, config: Record<string, unknown>, metrics: Record<string, number>, keys: string[], facts: Record<string, string> = {}): CompDef => {
    const c: CompDef = {
      id: compId(nextComp++),
      type,
      slug,
      config,
      health: "ok",
      detail: "",
      metrics,
      process: { cpu_pct: 1 + (h.idx % 5), rss_mb: 60 + ((h.idx * 13) % 400), restarts: 0, uptime_s: h.uptime },
      facts,
      keys,
    };
    h.comps.push(c);
    return c;
  };
  const tlsListen = (h: HostDef): Record<string, string> => ({ listen: `${h.ip}:8443`, tls_fingerprint_sha256: fingerprint(h.id) });

  const usedSlugs = new Set<string>();
  const uniqueSlug = (base: string, i: number): string => {
    const s = usedSlugs.has(base) ? `${base}-${pad(i, 3)}` : base;
    usedSlugs.add(s);
    return s;
  };
  for (const h of hosts) {
    const i = h.idx;
    if (h.shape === "collector" || h.shape === "combo") {
      const slug = uniqueSlug(`col-${h.site.site}`, i);
      const total = probeCountBySite[h.site.site] ?? 0;
      mkComp(h, "collector", slug, { listen: `${h.ip}:8443`, retention: { metrics_days: 30, records_days: 7 } }, {
        ingest_records_per_s: 180 + (i % 9) * 20, ingest_rejected_per_min: 0, ingest_duplicates_per_min: 1, probes_total: total, probes_reporting: total,
        vm_up: 1, vm_backlog_points: 0, vm_storage_gb: 12 + (i % 6), records_db_gb: 1.2 + (i % 4) * 0.3, storage_free_gb: 300, days_to_full: 120, open_incidents: 0,
      }, ["ingest_records_per_s", "ingest_rejected_per_min", "vm_backlog_points", "vm_storage_gb", "records_db_gb", "probes_reporting"], tlsListen(h));
    }
    if (h.shape === "dashboard" || h.shape === "combo") {
      const slug = uniqueSlug(`dash-${h.site.site}`, i);
      mkComp(h, "dashboard", slug, { url: `https://${h.ip}` }, { sessions_active: 2 + (i % 5), requests_per_min: 40 + (i % 8) * 6, collectors_total: 1, collectors_reachable: 1, login_failures_1h: 0 }, ["sessions_active", "requests_per_min", "collectors_reachable"], { url: `https://${h.ip}`, tls_fingerprint_sha256: fingerprint(h.id + "d") });
    }
    if (h.shape === "runner") {
      mkComp(h, "runner", `runner-${h.site.site}`, { collector: collectorOf.get(h.site.site) ?? "" }, { drills_active: 0 }, ["drills_active"]);
    }
    if (h.shape === "probe") {
      const nPorts = 4 + ((i * 7) % 13); // 4..16
      const ports = [] as Array<Record<string, unknown>>;
      for (let p = 0; p < nPorts; p++) {
        const iface = `enp${pad(p + 1, 2)}s0`;
        h.ifaces.push({ name: iface, in_use_by: `probe:probe-${pad(i, 3)}` });
        ports.push(p % 4 === 3 ? { id: `p${p + 1}`, iface, role: "target", address: `192.168.${100 + (p % 50)}.${10 + (i % 200)}/24`, gateway: `192.168.${100 + (p % 50)}.1`, serve: { http: true, icmp: true } } : { id: `p${p + 1}`, iface, role: "client", vlan: 100 + (p % 8) });
      }
      mkComp(h, "probe", `probe-${pad(i, 3)}`, { label: `Row ${String.fromCharCode(65 + (i % 8))}${1 + (i % 12)}`, collector: collectorOf.get(h.site.site) ?? "", mgmt_iface: "eno1", ports }, {
        measurements_per_min: nPorts * 12 + (i % 5), fail_per_min: i % 11 === 0 ? 1 : 0, error_per_min: 0, spool_depth: 0, spool_bytes: 0, push_lag_s: 1 + (i % 4), clock_offset_ms: 1 + (i % 6),
      }, ["measurements_per_min", "fail_per_min", "spool_depth", "push_lag_s", "clock_offset_ms"]);
    }
  }

  // ---- scenarios: pick hosts by role and position (stable at every scale >= 24) ---------------------------------
  const firstOf = (pred: (h: HostDef) => boolean, skip = 0): HostDef => {
    const m = hosts.filter(pred);
    const h = m[Math.min(skip, m.length - 1)];
    if (!h) throw new Error("scale too small for the demo scenarios");
    return h;
  };
  const probes = hosts.filter((h) => h.shape === "probe");
  const diskHost = firstOf((h) => h.shape === "collector" && h.site.site === "hall-a");
  const crashHost = probes[0] as HostDef;
  const staleHost = probes[1] as HostDef;
  const offlineHost = probes[2] as HostDef;
  const driftA = probes[3] as HostDef;
  const driftB = probes[4] as HostDef;
  const driftC = firstOf((h) => h.shape === "dashboard" && h.site.site === "hall-c");
  const clockHost = probes[5] as HostDef;
  const memHost = probes[6] as HostDef;
  const cpuHost = firstOf((h) => h.shape === "combo");
  const reconcileHost = probes[7] as HostDef;
  if (!(crashHost && staleHost && offlineHost && driftA && driftB && clockHost && memHost && reconcileHost)) throw new Error("scale too small for the demo scenarios");

  // a disk filling toward full: 55 % 30 days ago -> 96.5 % now
  diskHost.d0 = 55;
  diskHost.d1 = 96.5;
  const dcol = diskHost.comps.find((c) => c.type === "collector") as CompDef;
  dcol.metrics.days_to_full = 1.4;
  dcol.metrics.storage_free_gb = 18;
  dcol.health = "degraded";
  dcol.detail = "storage runway below 2 days";
  scen.disk_filling = diskHost.name;

  // a crash-looping component
  const cp = crashHost.comps[0] as CompDef;
  cp.health = "fail";
  cp.detail = "exited with status 1 (restart 7 of the last 15 minutes: 5)";
  cp.process.restarts = 7;
  cp.process.uptime_s = 41;
  cp.metrics.measurements_per_min = 0;
  cp.metrics.push_lag_s = 180;
  scen.crash_loop = crashHost.name;

  staleHost.state = "stale";
  staleHost.lastSeenMs = now - 5 * 60_000;
  staleHost.endMs = staleHost.lastSeenMs;
  scen.stale = staleHost.name;

  offlineHost.state = "offline";
  offlineHost.lastSeenMs = now - 3 * 3600_000;
  offlineHost.endMs = offlineHost.lastSeenMs;
  scen.offline = offlineHost.name;

  // version drift: desired is ahead of applied for a while (and one host still runs the previous agent)
  driftA.appliedVersion = DESIRED_VERSION - 1;
  driftB.appliedVersion = DESIRED_VERSION - 1;
  driftB.agentVersion = AGENT_OLD;
  driftC.appliedVersion = DESIRED_VERSION - 2;
  driftC.agentVersion = AGENT_OLD;
  scen.version_drift = [driftA, driftB, driftC].map((h) => h.name).join(",");

  clockHost.timeSynced = false;
  clockHost.offsetMs = 1840;
  scen.clock = clockHost.name;

  memHost.mem = 91;
  memHost.memB = 90;
  scen.mem_low = memHost.name;

  cpuHost.cpuB = 88;
  cpuHost.cpuA = 8;
  scen.cpu_high = cpuHost.name;

  reconcileHost.reconcile = { result: "rolled_back", error: "probe-007: port enp03s0 vanished during apply; rolled back" };
  scen.reconcile_failed = reconcileHost.name;

  // latest values per host (what the agent's last report carried)
  for (const h of hosts) {
    const wave = Math.max(0, 1 - Math.abs(new Date(h.lastSeenMs).getUTCHours() - 14) / 10);
    h.cpu = Math.min(99, h.cpuB + h.cpuA * wave + (h.idx % 4));
    h.mem = h.mem || Math.min(97, h.memB + 5 * wave);
    h.diskPct = h.idx === diskHost.idx ? 96.5 : h.d1;
  }

  // ---- entities ---------------------------------------------------------------------------------------------
  const statements: string[] = [];
  const stamp = `${sq(nowIso)}, ${sq(nowIso)}`;

  statements.push(
    `INSERT OR IGNORE INTO settings (org_id, org_name, created_at, updated_at) VALUES ('default', 'Demo Org', ${stamp})`,
    `INSERT OR IGNORE INTO admins (org_id, email, role, disabled, last_seen, created_at, updated_at) VALUES ('default', 'demo-owner@example.com', 'owner', 0, ${sq(nowIso)}, ${stamp})`,
  );
  // releases (rows only: the demo database never holds the artifact bytes)
  const rels = [
    { v: AGENT_OLD, created: iso(now - 20 * 86400_000) },
    { v: AGENT_NEW, created: iso(now - 4 * 86400_000) },
  ];
  rels.forEach((r, k) => {
    statements.push(
      `INSERT INTO releases (version, org_id, manifest_r2_key, signature, min_agent_version, verified_at, source, notes_url, rel_id, manifest_created, created_at, updated_at) VALUES (${sq(r.v)}, 'default', ${sq(`releases/${r.v}/${relId(k + 1)}/manifest.json`)}, ${sq("A".repeat(86) + "==")}, '0.1.0', ${sq(r.created)}, 'upload', NULL, ${sq(relId(k + 1))}, ${sq(r.created)}, ${sq(r.created)}, ${sq(r.created)})`,
    );
    ["agent", "probe", "collector", "dashboard", "runner"].forEach((comp, c) => {
      const name = `exp-${comp}-${r.v}-${comp === "agent" ? "noarch" : "amd64"}.tar.gz`;
      statements.push(
        `INSERT INTO artifacts (artifact_id, org_id, version, name, component, arch, sha256, size, r2_key, created_at, updated_at) VALUES (${sq(artId(k * 10 + c + 1))}, 'default', ${sq(r.v)}, ${sq(name)}, ${sq(comp)}, ${sq(comp === "agent" ? "noarch" : "amd64")}, ${sq(sha(name))}, ${1_000_000 + c * 250_000}, ${sq(`artifacts/${artId(k * 10 + c + 1)}`)}, ${sq(r.created)}, ${sq(r.created)})`,
      );
    });
  });
  SITES.forEach((s, k) => {
    const canary = s.site === "hall-c";
    const canaryHost = canary ? (hosts.find((h) => h.site.site === "hall-c" && h.shape === "probe") as HostDef) : null;
    statements.push(
      `INSERT INTO sites (site, org_id, name, timezone, edge_label, release_version, target_version, canary_host_id, canary_state, canary_started_at, created_at, updated_at) VALUES (${sq(s.site)}, 'default', ${sq(s.name)}, ${sq(s.tz)}, ${sq(s.edge)}, ${sq(k === 0 ? AGENT_NEW : AGENT_OLD)}, ${canary ? sq(AGENT_NEW) : "NULL"}, ${canaryHost ? sq(canaryHost.id) : "NULL"}, ${canary ? "'canary'" : "'none'"}, ${canary ? sq(iso(now - 25 * 60_000)) : "NULL"}, ${sq(iso(now - 30 * 86400_000))}, ${sq(nowIso)})`,
    );
  });

  const rowChunks = (head: string, rows: string[], tail = ""): string[] => {
    const out: string[] = [];
    let cur: string[] = [];
    let len = head.length + tail.length;
    for (const r of rows) {
      if (cur.length && len + r.length + 2 > MAX_STMT) {
        out.push(`${head}${cur.join(", ")}${tail}`);
        cur = [];
        len = head.length + tail.length;
      }
      cur.push(r);
      len += r.length + 2;
    }
    if (cur.length) out.push(`${head}${cur.join(", ")}${tail}`);
    return out;
  };

  const factsOf = (h: HostDef): Record<string, unknown> => ({
    hostname: h.name,
    machine_id: sha(h.id).slice(0, 32),
    os: { id: "ubuntu", version: "24.04" },
    kernel: "6.8.0-45-generic",
    arch: "amd64",
    cpus: h.shape === "probe" ? 4 : 8,
    mem_mb: h.shape === "probe" ? 8000 : 32000,
    disk_free_mb: Math.round(400000 * (1 - h.diskPct / 100)),
    python: "3.12.3",
    time: { synced: h.timeSynced, source: "systemd-timesyncd", offset_ms: h.offsetMs },
    interfaces: h.ifaces.map((f, k) => ({
      name: f.name,
      mac: `18:66:da:${pad(h.idx % 100, 2)}:${pad(Math.floor(h.idx / 100) % 100, 2)}:${pad(k, 2)}`,
      state: "up",
      speed_mbps: k === 0 ? 1000 : 1000,
      driver: k === 0 ? "tg3" : "ixgbe",
      addrs: k === 0 ? [`${h.ip}/24`] : [],
      default_route: k === 0,
      in_use_by: f.in_use_by,
    })),
  });

  const latestOf = (h: HostDef): Record<string, unknown> => {
    const rx = 150 * h.netS * (1 + (h.idx % 5)) * 1.0;
    return {
      cpu_pct: h.state === "enrolled" ? Math.round(h.cpu * 10) / 10 : null,
      mem_pct: Math.round(h.mem * 10) / 10,
      disk_pct_max: Math.round(h.diskPct * 10) / 10,
      load1: Math.round(h.cpu / 25 * 100) / 100,
      uptime_s: h.uptime,
      temp_c_max: 44 + (h.idx % 9),
      net: { rx_pps: rx, tx_pps: rx * 0.6, rx_bps: rx * 800, tx_bps: rx * 480, iface: "eno1" },
    };
  };

  const hostRows = hosts.map((h) =>
    `(${sq(h.id)}, 'default', ${sq(h.name)}, ${sq(h.site.site)}, ${sq(h.state)}, 'amd64', ${jq(factsOf(h))}, '[]', ${sq(iso(h.lastSeenMs))}, ${sq(iso(now - 31 * 86400_000))}, ${sq(h.agentVersion)}, ${DESIRED_VERSION}, ${h.appliedVersion}, ${sq(sha("desired" + h.id + h.appliedVersion))}, 60, ${jq(latestOf(h))}, ${sq(iso(now - 31 * 86400_000))}, ${sq(iso(h.lastSeenMs))})`,
  );
  statements.push(...rowChunks("INSERT INTO hosts (host_id, org_id, name, site, state, arch, facts_json, actions_json, last_seen, enrolled_at, agent_version, desired_version, applied_version, desired_hash, status_interval_s, latest_json, created_at, updated_at) VALUES ", hostRows));

  const compRows: string[] = [];
  let compCount = 0;
  for (const h of hosts) {
    for (const c of h.comps) {
      compCount++;
      const stale = h.state !== "enrolled";
      const facts = { health: c.health, state: c.health === "fail" ? "restarting" : "running", detail: c.detail, version: h.agentVersion, since: iso(now - h.uptime * 1000), facts: c.facts, metrics: stale ? {} : c.metrics, process: c.process };
      compRows.push(`(${sq(c.id)}, 'default', ${sq(h.id)}, ${sq(c.type)}, ${sq(c.slug)}, ${jq(c.config)}, 1, ${jq(facts)}, ${sq(iso(now - 31 * 86400_000))}, ${sq(iso(h.lastSeenMs))})`);
    }
  }
  statements.push(...rowChunks("INSERT INTO components (component_id, org_id, host_id, type, slug, config_json, enabled, facts_json, created_at, updated_at) VALUES ", compRows));

  // last status report per host (compact but contract-shaped, exp.status/1)
  const statusRows = hosts.map((h) => {
    const rep = {
      schema: "exp.status/1",
      agent: { version: h.agentVersion, desired_version: DESIRED_VERSION, applied_version: h.appliedVersion, uptime_s: h.uptime, last_poll: iso(h.lastSeenMs) },
      facts: factsOf(h),
      metrics: {
        interval_s: 60,
        uptime_s: h.uptime,
        cpu: { pct: Math.round(h.cpu * 10) / 10, iowait_pct: 0.4, steal_pct: 0, load1: Math.round(h.cpu / 25 * 100) / 100, load5: 0.7, load15: 0.6 },
        mem: { total_mb: 32000, used_mb: Math.round((32000 * h.mem) / 100), available_mb: Math.round((32000 * (100 - h.mem)) / 100), pct: Math.round(h.mem * 10) / 10, swap_used_mb: 0 },
        disk: [{ mount: "/", total_gb: 437, used_gb: Math.round((437 * h.diskPct) / 100), pct: Math.round(h.diskPct * 10) / 10 }],
        disk_io: { read_kbps: 3, write_kbps: h.wrB },
        net: [{ iface: "eno1", role: "mgmt", link: "up", speed_mbps: 1000, rx_pps: 150, tx_pps: 90, rx_bps: 120000, tx_bps: 72000, rx_errors: 0, tx_errors: 0, rx_drops: 0, tx_drops: 0 }],
      },
      components: h.comps.map((c) => ({ type: c.type, id: c.slug, state: c.health === "fail" ? "restarting" : "running", health: c.health, version: h.agentVersion, process: c.process, metrics: c.metrics, facts: c.facts })),
      reconcile: { at: iso(h.lastSeenMs - 3600_000), result: h.reconcile.result, error: h.reconcile.error, duration_ms: 420 },
      events: [],
    };
    return `(${sq(h.id)}, 'default', ${sq(iso(h.lastSeenMs))}, ${jq(rep)}, ${sq(iso(h.lastSeenMs))}, ${sq(iso(h.lastSeenMs))})`;
  });
  statements.push(...rowChunks("INSERT INTO status_latest (host_id, org_id, received_at, report_json, created_at, updated_at) VALUES ", statusRows));

  // ---- issues -------------------------------------------------------------------------------------------------
  interface IssueDef { kind: string; sev: "warn" | "crit"; host: HostDef; comp?: CompDef; ageMin: number; value: number | null; detail: string; resolvedAgoMin?: number }
  const issues: IssueDef[] = [
    { kind: "disk_high", sev: "crit", host: diskHost, ageMin: 190, value: 96.5, detail: "/ is 96.5 % full" },
    { kind: "storage_runway", sev: "crit", host: diskHost, comp: dcol, ageMin: 190, value: 1.4, detail: "about 1.4 days until the collector volume is full" },
    { kind: "crash_loop", sev: "crit", host: crashHost, comp: crashHost.comps[0] as CompDef, ageMin: 14, value: 5, detail: "5 restarts in 15 minutes" },
    { kind: "component_unhealthy", sev: "crit", host: crashHost, comp: crashHost.comps[0] as CompDef, ageMin: 14, value: null, detail: "health fail: exited with status 1" },
    { kind: "host_stale", sev: "warn", host: staleHost, ageMin: 2, value: 300, detail: "no report for 5 minutes" },
    { kind: "host_offline", sev: "crit", host: offlineHost, ageMin: 170, value: 10800, detail: "no report for 3 hours" },
    { kind: "version_drift", sev: "warn", host: driftA, ageMin: 45, value: 1, detail: "applied 11, desired 12" },
    { kind: "version_drift", sev: "warn", host: driftB, ageMin: 90, value: 1, detail: "applied 11, desired 12" },
    { kind: "version_drift", sev: "warn", host: driftC, ageMin: 240, value: 2, detail: "applied 10, desired 12" },
    { kind: "clock", sev: "warn", host: clockHost, ageMin: 35, value: 1840, detail: "time not synchronised, offset 1840 ms" },
    { kind: "mem_low", sev: "warn", host: memHost, ageMin: 55, value: 9, detail: "9 % memory available for over 10 minutes" },
    { kind: "cpu_high", sev: "warn", host: cpuHost, ageMin: 75, value: 91, detail: "CPU 91 % averaged over 15 minutes" },
    { kind: "reconcile_failed", sev: "warn", host: reconcileHost, ageMin: 60, value: null, detail: "last reconcile rolled back" },
    // history: resolved issues
    { kind: "cpu_high", sev: "warn", host: probes[8] as HostDef, ageMin: 1500, value: 93, detail: "CPU 93 % averaged over 15 minutes", resolvedAgoMin: 1380 },
    { kind: "host_stale", sev: "warn", host: probes[9] as HostDef, ageMin: 2900, value: 240, detail: "no report for 4 minutes", resolvedAgoMin: 2890 },
  ];
  const issueRows = issues.map((x, k) => {
    const opened = iso(now - x.ageMin * 60_000);
    const resolved = x.resolvedAgoMin !== undefined ? sq(iso(now - x.resolvedAgoMin * 60_000)) : "NULL";
    return `(${sq(issueId(k + 1))}, 'default', ${sq(x.kind)}, ${sq(x.sev)}, ${sq(x.host.id)}, ${x.comp ? sq(x.comp.id) : "NULL"}, ${sq(x.host.site.site)}, ${sq(opened)}, ${resolved}, 0, ${num(x.value)}, ${sq(x.detail)}, ${x.sev === "crit" ? 1 : 0}, ${sq(opened)}, ${sq(nowIso)})`;
  });
  statements.push(...rowChunks("INSERT INTO issues (issue_id, org_id, kind, severity, host_id, component_id, site, opened_at, resolved_at, clean_reports, last_value, detail, notified, created_at, updated_at) VALUES ", issueRows));

  // ---- roll-ups: generated inside SQLite ---------------------------------------------------------------------------
  const hourEnd = Math.floor(now / 1000 / STEP_1H) * STEP_1H; // completed hours end here (exclusive)
  const hourStart = hourEnd - HOUR_BUCKETS * STEP_1H;
  const fiveEnd = Math.floor(now / 1000 / STEP_5M) * STEP_5M; // current partial bucket included
  const fiveStart = fiveEnd - FIVE_BUCKETS * STEP_5M;

  // time series expression block shared by every roll-up: t (bucket start), idx (host or component index)
  const wave = (t: string): string => `MAX(0.0, 1.0 - ABS(((${t} % 86400) / 3600.0) - 14.0) / 10.0) * (CASE WHEN ((${t} / 86400) + 3) % 7 >= 5 THEN 0.6 ELSE 1.0 END)`;
  const noise = (idx: string, t: string, salt: number): string => `((((${idx}) * 7919 + (${t} / 300) * 104729 + ${salt}) % 1000) / 1000.0)`;

  const hostProfiles = hosts.map((h) => `(${sq(h.id)}, ${h.idx}, ${num(h.cpuB)}, ${num(h.cpuA)}, ${num(h.memB)}, ${num(h.d0)}, ${num(h.d1)}, ${num(h.netS)}, ${num(h.wrB)}, ${Math.floor(h.endMs / 1000)})`);
  const hostRollup = (table: string, from: number, count: number, step: number, n: number): string[] => {
    const out: string[] = [];
    const per = Math.max(1, Math.floor(MAX_STMT / 3 / 80)); // profiles per statement keeps each under the size cap
    for (let a = 0; a < hostProfiles.length; a += per) {
      const prof = hostProfiles.slice(a, a + per).join(", ");
      const tExpr = `(${from} + k * ${step})`;
      out.push(
        `WITH RECURSIVE prof(hid, idx, cpu_b, cpu_a, mem_b, d0, d1, net_s, wr_b, endb) AS (VALUES ${prof}), tk(k) AS (SELECT 0 UNION ALL SELECT k + 1 FROM tk WHERE k < ${count - 1}), b AS (SELECT prof.*, ${tExpr} AS t, k FROM prof JOIN tk ON ${tExpr} <= prof.endb), c AS (SELECT b.*, ${wave("t")} AS ld, ${noise("idx", "t", 1)} AS nz, ${noise("idx", "t", 2)} AS nz2 FROM b), v AS (SELECT c.*, MIN(99.0, cpu_b + cpu_a * ld + 4.0 * nz) AS cpu, MIN(98.0, mem_b + 5.0 * ld + 2.0 * nz2) AS mem, MIN(99.5, d0 + (d1 - d0) * ((t - ${hourStart}) / ${HOUR_BUCKETS * STEP_1H}.0)) AS disk, net_s * (200.0 + 3000.0 * ld + 100.0 * nz) AS pps, wr_b * (0.4 + 1.6 * ld + 0.3 * nz2) AS wr FROM c) ` +
          `INSERT INTO ${table} (host_id, bucket, org_id, samples, cpu_n, cpu_sum, cpu_max, mem_n, mem_pct_sum, mem_pct_max, disk_n, disk_pct_sum, disk_pct_max, load_n, load1_sum, load1_max, net_n, rx_pps_sum, tx_pps_sum, rx_bps_sum, tx_bps_sum, errors_sum, drops_sum, pkts_sum, dio_n, disk_write_kbps_sum, disk_write_kbps_max, created_at, updated_at) ` +
          `SELECT hid, t, 'default', ${n}, ${n}, cpu * ${n}, MIN(100.0, cpu + 4.0 + 12.0 * nz2), ${n}, mem * ${n}, MIN(100.0, mem + 2.0), ${n}, disk * ${n}, disk, ${n}, cpu / 25.0 * ${n}, cpu / 25.0 * 1.5, ${n}, pps * ${n}, pps * 0.6 * ${n}, pps * 800.0 * ${n}, pps * 480.0 * ${n}, 0, 0, pps * 1.6 * 60.0 * ${n}, ${n}, wr * ${n}, wr * 1.8, ${sq(nowIso)}, ${sq(nowIso)} FROM v`,
      );
    }
    return out;
  };
  statements.push(...hostRollup("fleet_host_1h", hourStart, HOUR_BUCKETS, STEP_1H, 60));
  statements.push(...hostRollup("fleet_host_5m", fiveStart, FIVE_BUCKETS + 1, STEP_5M, 5));

  // management-interface history (5-minute only, 48 h)
  {
    const per = Math.max(1, Math.floor(MAX_STMT / 3 / 80));
    for (let a = 0; a < hostProfiles.length; a += per) {
      const prof = hostProfiles.slice(a, a + per).join(", ");
      const tExpr = `(${fiveStart} + k * ${STEP_5M})`;
      statements.push(
        `WITH RECURSIVE prof(hid, idx, cpu_b, cpu_a, mem_b, d0, d1, net_s, wr_b, endb) AS (VALUES ${prof}), tk(k) AS (SELECT 0 UNION ALL SELECT k + 1 FROM tk WHERE k < ${FIVE_BUCKETS}), b AS (SELECT prof.*, ${tExpr} AS t FROM prof JOIN tk ON ${tExpr} <= prof.endb), v AS (SELECT b.*, ${wave("t")} AS ld, ${noise("idx", "t", 3)} AS nz FROM b) ` +
          `INSERT INTO fleet_iface_5m (host_id, iface, bucket, org_id, samples, rx_pps_sum, tx_pps_sum, rx_bps_sum, tx_bps_sum, errors_sum, drops_sum, pkts_sum, created_at, updated_at) ` +
          `SELECT hid, 'eno1', t, 'default', 5, net_s * (200.0 + 3000.0 * ld + 100.0 * nz) * 5, net_s * (200.0 + 3000.0 * ld) * 0.6 * 5, net_s * (200.0 + 3000.0 * ld) * 800.0 * 5, net_s * (200.0 + 3000.0 * ld) * 480.0 * 5, 0, 0, net_s * (200.0 + 3000.0 * ld) * 1.6 * 60.0 * 5, ${sq(nowIso)}, ${sq(nowIso)} FROM v`,
      );
    }
  }

  // component metrics: one row per (component, key, bucket). Base level per key.
  const compProfiles: string[] = [];
  for (const h of hosts) {
    for (const c of h.comps) {
      for (const key of c.keys) {
        // level = latest value; the series follows the diurnal load for rate-like keys, stays flat for gauges
        const level = c.metrics[key] ?? 0;
        const kind = ["measurements_per_min", "ingest_records_per_s", "sessions_active", "requests_per_min"].includes(key) ? 1 : key === "vm_storage_gb" || key === "records_db_gb" ? 2 : 0;
        compProfiles.push(`(${sq(c.id)}, ${sq(key)}, ${h.idx}, ${num(level)}, ${kind}, ${Math.floor(h.endMs / 1000)})`);
      }
    }
  }
  const compRollup = (table: string, from: number, count: number, step: number, n: number): string[] => {
    const out: string[] = [];
    const per = Math.max(1, Math.floor(MAX_STMT / 3 / 90));
    for (let a = 0; a < compProfiles.length; a += per) {
      const prof = compProfiles.slice(a, a + per).join(", ");
      const tExpr = `(${from} + k * ${step})`;
      out.push(
        `WITH RECURSIVE prof(cid, key, idx, level, kind, endb) AS (VALUES ${prof}), tk(k) AS (SELECT 0 UNION ALL SELECT k + 1 FROM tk WHERE k < ${count - 1}), b AS (SELECT prof.*, ${tExpr} AS t FROM prof JOIN tk ON ${tExpr} <= prof.endb), v AS (SELECT b.*, ${wave("t")} AS ld, ${noise("idx", "t", 4)} AS nz FROM b) ` +
          `INSERT INTO ${table} (component_id, key, bucket, org_id, n, sum, max) SELECT cid, key, t, 'default', ${n}, ` +
          `(CASE kind WHEN 1 THEN level * (0.35 + 0.65 * ld) * (0.95 + 0.1 * nz) WHEN 2 THEN level * (0.8 + 0.2 * (CAST(t - ${hourStart} AS REAL) / ${HOUR_BUCKETS * STEP_1H})) ELSE level * (0.9 + 0.2 * nz) END) * ${n}, ` +
          `(CASE kind WHEN 1 THEN level * (0.35 + 0.65 * ld) * 1.15 WHEN 2 THEN level ELSE level * 1.2 END) FROM v`,
      );
    }
    return out;
  };
  statements.push(...compRollup("fleet_component_metric_1h", hourStart, HOUR_BUCKETS, STEP_1H, 60));
  statements.push(...compRollup("fleet_component_metric_5m", fiveStart, FIVE_BUCKETS + 1, STEP_5M, 5));

  for (const s of statements) {
    if (s.includes("\n")) throw new Error("seed statement contains a newline");
    if (s.length > MAX_STMT + 4000) throw new Error(`seed statement too large: ${s.length}`);
  }

  const reset = [
    "fleet_component_metric_5m", "fleet_component_metric_1h", "fleet_iface_5m", "fleet_host_5m", "fleet_host_1h", "issue_snoozes", "issue_state", "issues",
    "status_history", "status_latest", "desired_docs", "agent_creds", "enrol_tokens", "secrets", "components", "hosts", "artifacts", "releases", "sites", "audit",
  ].map((t) => `DELETE FROM ${t}`);

  return {
    reset,
    statements,
    summary: {
      hosts: hosts.length,
      sites: SITES.length,
      components: compCount,
      probes: probes.length,
      issues_open: issues.filter((x) => x.resolvedAgoMin === undefined).length,
      scenarios: scen,
      host_ids: hosts.map((h) => h.id),
    },
  };
}
