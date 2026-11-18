// 05-manager.md section 15 item 3: compiler golden tests (pure function over loaded rows).
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { compile, effectiveVersion, pickArtifact } from "../../src/compile/compile";
import type { DesiredBody, World } from "../../src/compile/types";
import { secretKey } from "../../src/compile/types";
import { canonicalJson } from "../../src/util/canonical";
import { C_COL, C_DASH, C_PROBE, FP_COL, FP_DASH, H_COL, H_DASH, H_PROBE, HOOK, SSO, TOK_PAIR, TOK_PROBE, baseWorld, clone, fid, sha } from "./world";
import { validateAgainst } from "./schemas";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = join(here, "golden");

type Doc = DesiredBody & { version: number; generated_at: string };
const finalize = (b: DesiredBody): Doc => ({ ...b, version: 1, generated_at: "2026-11-18T20:00:00.000Z" });

function build(w: World, hostId: string): Doc {
  const r = compile(w, hostId);
  expect(r.doc, `held: ${r.warnings.join("; ")}`).not.toBeNull();
  return finalize(r.doc!);
}

function golden(name: string, doc: unknown): void {
  const file = join(GOLDEN, name);
  const text = JSON.stringify(doc, null, 2) + "\n";
  if (process.env.UPDATE_GOLDEN === "1" || !existsSync(file)) {
    mkdirSync(GOLDEN, { recursive: true });
    writeFileSync(file, text);
  }
  expect(JSON.parse(readFileSync(file, "utf8"))).toEqual(JSON.parse(text));
}

const comp = (d: Doc, type: string) => d.components.find((c) => c.type === type)!;
const creds = (d: Doc, type: string, name: string): string => (comp(d, type).creds as Record<string, string>)[name]!;
const cfg = (d: Doc, type: string) => comp(d, type).config as Record<string, any>;

describe("golden documents", () => {
  it.each([
    ["collector", H_COL],
    ["dashboard", H_DASH],
    ["probe", H_PROBE],
  ])("%s host: matches the golden file and validates against desired.schema.json", (name, hostId) => {
    const doc = build(baseWorld(), hostId);
    expect(validateAgainst("desired.schema.json", doc)).toEqual([]);
    golden(`${name}-host.desired.json`, doc);
  });

  it("an all-in-one host (collector + dashboard + probe) validates and references the right artifacts", () => {
    const w = baseWorld();
    for (const c of w.components) c.host_id = H_COL;
    const doc = build(w, H_COL);
    expect(validateAgainst("desired.schema.json", doc)).toEqual([]);
    expect(doc.components.map((c) => c.type)).toEqual(["collector", "dashboard", "probe"]);
    golden("all-in-one-host.desired.json", doc);
  });
});

describe("validator sanity", () => {
  it("the schema validator really rejects bad documents", () => {
    const d = build(baseWorld(), H_PROBE) as unknown as Record<string, any>;
    expect(validateAgainst("desired.schema.json", { ...d, host_id: "nope" }).length).toBeGreaterThan(0);
    const bad = JSON.parse(JSON.stringify(d));
    bad.components[0].config.collector = { url: "http://x", tls_fingerprint_sha256: "zz", fallback: [] };
    expect(validateAgainst("desired.schema.json", bad).length).toBeGreaterThan(0);
    const bad2 = JSON.parse(JSON.stringify(d));
    bad2.components[0].creds["../x"] = "y";
    expect(validateAgainst("desired.schema.json", bad2).length).toBeGreaterThan(0);
  });
});

describe("wiring", () => {
  it("probe -> collector: URL from the reported listen, pin from the reported fingerprint", () => {
    const d = build(baseWorld(), H_PROBE);
    expect(cfg(d, "probe").collector).toEqual({ url: "https://10.32.98.25:8443", tls_fingerprint_sha256: FP_COL, fallback: [] });
    expect(cfg(d, "probe").site).toBe("hall-b");
    expect(cfg(d, "probe").mgmt_iface).toBe("eno1");
  });

  it("probe collector is null until the collector reported BOTH listen and fingerprint", () => {
    for (const facts of [{}, { listen: "10.32.98.25:8443" }, { tls_fingerprint_sha256: FP_COL }]) {
      const w = baseWorld();
      w.components.find((c) => c.component_id === C_COL)!.facts = facts;
      expect(cfg(build(w, H_PROBE), "probe").collector).toBeNull();
    }
  });

  it("collector: probes, dashboards, token hashes (verifiers only) and webhooks", () => {
    const d = build(baseWorld(), H_COL);
    const c = cfg(d, "collector");
    expect(c.probes).toEqual([{ probe_id: "probe-a1", site: "hall-b", label: "Hall B east" }]);
    expect(c.dashboards).toEqual(["dash-main"]);
    expect(c.listen).toBe("10.32.98.25:8443");
    expect(c.rules.edge_label).toBe("EC");
    expect(c.alerts.board_url).toBe("https://10.32.98.30"); // the dashboard's url, derived from its mgmt address
    expect(c.alerts.timezone).toBe("America/Chicago");
    expect(JSON.parse(creds(d, "collector", "ingest_tokens.json"))).toEqual({ "probe-a1": sha(TOK_PROBE) });
    expect(JSON.parse(creds(d, "collector", "dashboard_tokens.json"))).toEqual({ "dash-main": sha(TOK_PAIR) });
    expect(JSON.parse(creds(d, "collector", "webhooks.json"))).toEqual([{ id: "wh_1", format: "slack", url: HOOK }]);
    // collectors never receive plaintext tokens of others
    const all = JSON.stringify(comp(d, "collector").creds);
    expect(all).not.toContain(TOK_PROBE);
    expect(all).not.toContain(TOK_PAIR);
  });

  it("dashboard: collectors with URL + pin + its own expd_ token, users, NOC tokens, sso_secret", () => {
    const d = build(baseWorld(), H_DASH);
    const c = cfg(d, "dashboard");
    expect(c.collectors).toEqual([{ collector_id: "col-hallb", site: "hall-b", url: "https://10.32.98.25:8443", tls_fingerprint_sha256: FP_COL }]);
    expect(c.url).toBe("https://10.32.98.30");
    expect(c.auth.sso).toEqual({ manager_url: "https://exp.example.com", issuer: "exp-manager:default" });
    expect(c.timezone).toBe("America/Chicago");
    expect(JSON.parse(creds(d, "dashboard", "collector_tokens.json"))).toEqual({ "col-hallb": TOK_PAIR });
    expect(creds(d, "dashboard", "sso_secret")).toBe(SSO);
    expect(JSON.parse(creds(d, "dashboard", "local_users.json"))).toEqual([{ username: "admin", role: "admin", hash: expect.stringMatching(/^pbkdf2_sha256\$/) }]);
    expect(JSON.parse(creds(d, "dashboard", "noc_tokens.json"))[0]).toMatchObject({ label: "wall display", role: "viewer", sha256: sha("expn_x") });
  });

  it("a dashboard leaves out collectors that have not reported listen + pin yet", () => {
    const w = baseWorld();
    w.components.find((c) => c.component_id === C_COL)!.facts = {};
    const d = build(w, H_DASH);
    expect(cfg(d, "dashboard").collectors).toEqual([]);
    expect(JSON.parse(creds(d, "dashboard", "collector_tokens.json"))).toEqual({});
    expect(validateAgainst("desired.schema.json", d)).toEqual([]);
  });

  it("explicit dashboard.collectors / probe.collector_id override the site default", () => {
    const w = baseWorld();
    w.sites["hall-a"] = { ...w.sites["hall-b"]!, site: "hall-a", name: "Hall A" };
    const H2 = fid("h_", 9);
    w.hosts[H2] = { ...w.hosts[H_COL]!, host_id: H2, site: "hall-a", name: "col2" };
    const C2 = fid("cmp_", 9);
    w.components.push({ component_id: C2, host_id: H2, type: "collector", slug: "col-halla", config: {}, enabled: true, facts: { listen: "10.9.9.9:8443", tls_fingerprint_sha256: FP_DASH }, created_at: "2026-11-18T10:00:09.000Z" });
    w.secrets[secretKey(`${C_DASH}:${C2}`, "dashboard_token")] = { plaintext: "expd_" + "E".repeat(43), hash: sha("e"), previous_hash: null };
    w.components.find((c) => c.component_id === C_DASH)!.config.collectors = ["col-hallb", "col-halla"];
    w.components.find((c) => c.component_id === C_PROBE)!.config.collector_id = "col-halla";
    expect(cfg(build(w, H_DASH), "dashboard").collectors.map((c: any) => c.collector_id)).toEqual(["col-hallb", "col-halla"]);
    expect(cfg(build(w, H_PROBE), "probe").collector.url).toBe("https://10.9.9.9:8443");
    expect(cfg(build(w, H_COL), "collector").probes).toEqual([]);
    expect(cfg(build(w, H2), "collector").probes.map((p: any) => p.probe_id)).toEqual(["probe-a1"]);
  });

  it("path peers default to a reflector target port in the site; the collector reflector only when the site allows it", () => {
    const w = baseWorld();
    const probe = w.components.find((c) => c.component_id === C_PROBE)!;
    probe.config.tests = { path: { interval_s: 60, peers: [] } };
    (probe.config.ports as unknown[]).push({ id: "s01", iface: "enp130s0f1", role: "target", address: "10.1.0.250/24", gateway: "10.1.0.1", serve: { http: true, reflector: true, iperf3: true } });
    const peers = cfg(build(w, H_PROBE), "probe").tests.path.peers;
    expect(peers).toEqual([{ peer: "s01", address: "10.1.0.250", port: 8862, proto: ["udp", "tcp"], duration_s: 10, rate_kbps: 256 }]);

    const w2 = baseWorld();
    const p2 = w2.components.find((c) => c.component_id === C_PROBE)!;
    p2.config.tests = { path: { interval_s: 60 } };
    expect(cfg(build(w2, H_PROBE), "probe").tests.path.peers).toEqual([]); // no reflector target, site cannot reach mgmt
    w2.sites["hall-b"]!.event_net_reaches_mgmt = true;
    expect(cfg(build(w2, H_PROBE), "probe").tests.path.peers[0]).toMatchObject({ peer: "col-hallb", address: "10.32.98.25", port: 8862 });
    // admin-chosen peers are never overwritten
    p2.config.tests = { path: { interval_s: 60, peers: [{ peer: "x", address: "10.0.0.1", port: 8862, proto: ["udp"], duration_s: 5, rate_kbps: 64 }] } };
    expect(cfg(build(w2, H_PROBE), "probe").tests.path.peers[0].peer).toBe("x");
  });

  it("the management interface is never handed to a probe as a test port", () => {
    const w = baseWorld();
    (w.components.find((c) => c.component_id === C_PROBE)!.config.ports as unknown[]).push({ id: "x01", iface: "eno1", role: "client" });
    const r = compile(w, H_PROBE);
    expect(cfg(finalize(r.doc!), "probe").ports.map((p: any) => p.iface)).toEqual(["enp10s0f0"]);
    expect(r.warnings.join()).toMatch(/management interface eno1/);
  });

  it("unknown config keys are not echoed into the compiled config", () => {
    const w = baseWorld();
    const p = w.components.find((c) => c.component_id === C_PROBE)!;
    p.config.evil = "<script>";
    p.config.admin_notes = "x";
    expect(JSON.stringify(build(w, H_PROBE))).not.toContain("<script>");
  });
});

describe("releases and canary", () => {
  it("artifact choice by component + host arch with a noarch fallback", () => {
    const arts = baseWorld().artifacts;
    expect(pickArtifact(arts, "0.1.0", "collector", "arm64")!.arch).toBe("arm64");
    expect(pickArtifact(arts, "0.1.0", "collector", "amd64")!.arch).toBe("amd64");
    expect(pickArtifact(arts, "0.1.0", "probe", "arm64")!.arch).toBe("noarch");
    expect(pickArtifact(arts, "0.1.0", "collector", null)).toBeNull();
    expect(pickArtifact(arts, "9.9.9", "probe", "amd64")).toBeNull();
    const w = baseWorld();
    w.hosts[H_COL]!.arch = "arm64";
    expect(comp(build(w, H_COL), "collector").artifact.name).toBe("exp-collector-0.1.0-arm64.tar.gz");
  });

  it("the canary host gets the target version first; everyone else stays on the promoted version", () => {
    const w = baseWorld();
    Object.assign(w.sites["hall-b"]!, { target_version: "0.2.0", canary_host_id: H_PROBE, canary_state: "canary" });
    expect(effectiveVersion(w.sites["hall-b"]!, H_PROBE)).toBe("0.2.0");
    const canary = build(w, H_PROBE);
    expect(canary.agent!.version).toBe("0.2.0");
    expect(canary.release!.manifest_url).toBe("/api/agent/v1/releases/0.2.0/manifest");
    expect(comp(canary, "probe").version).toBe("0.2.0");
    expect(comp(canary, "probe").artifact.name).toBe("exp-probe-0.2.0-noarch.tar.gz");
    expect(validateAgainst("desired.schema.json", canary)).toEqual([]);
    for (const h of [H_COL, H_DASH]) {
      const d = build(w, h);
      expect(d.agent!.version).toBe("0.1.0");
      expect(d.components.every((c) => c.version === "0.1.0")).toBe(true);
    }
    // promotion: release_version moves, canary state cleared
    Object.assign(w.sites["hall-b"]!, { release_version: "0.2.0", target_version: null, canary_state: "promoted" });
    for (const h of [H_COL, H_DASH, H_PROBE]) expect(build(w, h).agent!.version).toBe("0.2.0");
    golden("canary-probe.desired.json", canary);
  });

  it("holds (no document) when a needed artifact is missing, rather than telling the agent to remove components", () => {
    const w = baseWorld();
    w.artifacts = w.artifacts.filter((a) => a.component !== "probe");
    const r = compile(w, H_PROBE);
    expect(r.doc).toBeNull();
    expect(r.warnings.join()).toMatch(/no probe artifact/);
    w.artifacts = [];
    expect(compile(w, H_COL).doc).toBeNull();
  });

  it("a site without a release: bare document for empty hosts, hold for hosts with components", () => {
    const w = baseWorld();
    w.sites["hall-b"]!.release_version = null;
    expect(compile(w, H_PROBE).doc).toBeNull();
    w.components = [];
    const bare = build(w, H_PROBE);
    expect(bare.components).toEqual([]);
    expect(bare.agent).toBeUndefined();
    expect(validateAgainst("desired.schema.json", bare)).toEqual([]);
  });
});

describe("host states and actions", () => {
  it("pending and removed hosts compile to nothing", () => {
    const w = baseWorld();
    w.hosts[H_PROBE]!.state = "pending";
    expect(compile(w, H_PROBE).doc).toBeNull();
    w.hosts[H_PROBE]!.state = "removed";
    expect(compile(w, H_PROBE).doc).toBeNull();
    expect(compile(w, "h_" + "0".repeat(26)).doc).toBeNull();
  });

  it("stale and offline hosts still get their document", () => {
    for (const s of ["stale", "offline"] as const) {
      const w = baseWorld();
      w.hosts[H_PROBE]!.state = s;
      expect(compile(w, H_PROBE).doc).not.toBeNull();
    }
  });

  it("decommissioning: no components, decommission true, still validates", () => {
    const w = baseWorld();
    w.hosts[H_PROBE]!.state = "decommissioning";
    w.hosts[H_PROBE]!.actions = [{ id: fid("act_", 1), type: "rotate_agent_secret" }];
    const d = build(w, H_PROBE);
    expect(d.decommission).toBe(true);
    expect(d.components).toEqual([]);
    expect(d.actions).toEqual([]);
    expect(validateAgainst("desired.schema.json", d)).toEqual([]);
    golden("decommission.desired.json", d);
  });

  it("actions are carried verbatim", () => {
    const w = baseWorld();
    w.hosts[H_PROBE]!.actions = [
      { id: fid("act_", 1), type: "rotate_agent_secret" },
      { id: fid("act_", 2), type: "restart_component", component_id: C_PROBE },
    ];
    const d = build(w, H_PROBE);
    expect(d.actions).toHaveLength(2);
    expect(validateAgainst("desired.schema.json", d)).toEqual([]);
  });
});

describe("version churn", () => {
  const hash = (w: World, h: string) => sha(canonicalJson(compile(w, h).doc));

  it("recompiling an unchanged world gives an identical canonical hash", () => {
    expect(hash(baseWorld(), H_PROBE)).toBe(hash(baseWorld(), H_PROBE));
    expect(hash(baseWorld(), H_COL)).toBe(hash(baseWorld(), H_COL));
  });

  it("changes that do not affect the host leave the hash alone", () => {
    const base = baseWorld();
    const h0 = { probe: hash(base, H_PROBE), col: hash(base, H_COL), dash: hash(base, H_DASH) };
    const w = baseWorld();
    // health facts, other hosts' names, unrelated site metadata, row order
    w.hosts[H_COL]!.name = "renamed";
    w.components.reverse();
    w.dashboard_users.push({ dashboard_slug: "some-other-dashboard", username: "x", role: "viewer", hash: "pbkdf2_sha256$1$a$b" });
    w.noc_tokens.push({ noc_id: fid("noc_", 2), dashboard_slug: "other", label: "x", hash: "h", expires_at: null, revoked_at: null });
    w.noc_tokens.push({ noc_id: fid("noc_", 3), dashboard_slug: "dash-main", label: "old", hash: "h", expires_at: null, revoked_at: "2026-11-01T00:00:00.000Z" });
    expect(hash(w, H_PROBE)).toBe(h0.probe);
    expect(hash(w, H_COL)).toBe(h0.col);
    expect(hash(w, H_DASH)).toBe(h0.dash);
    // config key order does not matter either
    const p = w.components.find((c) => c.component_id === C_PROBE)!;
    p.config = Object.fromEntries(Object.entries(p.config).reverse());
    expect(hash(w, H_PROBE)).toBe(h0.probe);
  });

  it("real changes do change it, and only for the hosts they affect", () => {
    const base = baseWorld();
    const h0 = { probe: hash(base, H_PROBE), col: hash(base, H_COL), dash: hash(base, H_DASH) };
    const w = baseWorld();
    w.components.find((c) => c.component_id === C_PROBE)!.config.labels = { zone: "floor-1" };
    expect(hash(w, H_PROBE)).not.toBe(h0.probe);
    expect(hash(w, H_COL)).toBe(h0.col); // the collector only lists the probe's id/site/label
    expect(hash(w, H_DASH)).toBe(h0.dash);
    const w2 = baseWorld();
    w2.components.find((c) => c.component_id === C_COL)!.facts.tls_fingerprint_sha256 = FP_DASH; // pin change fans out
    expect(hash(w2, H_PROBE)).not.toBe(h0.probe);
    expect(hash(w2, H_DASH)).not.toBe(h0.dash);
    expect(hash(w2, H_COL)).toBe(h0.col);
    const w3 = baseWorld();
    w3.noc_tokens[0]!.revoked_at = "2026-11-18T19:00:00.000Z";
    expect(hash(w3, H_DASH)).not.toBe(h0.dash);
  });

  it("expired NOC tokens drop out of the dashboard credentials", () => {
    const w = baseWorld();
    w.noc_tokens[0]!.expires_at = "2026-11-18T19:59:59.000Z";
    expect(JSON.parse(creds(build(w, H_DASH), "dashboard", "noc_tokens.json"))).toEqual([]);
  });

  it("rotation overlap: collectors list [current, previous]; the plaintext holders get the new value", () => {
    const w = baseWorld();
    const newTok = "expi_" + "N".repeat(43);
    w.secrets[secretKey(C_PROBE, "ingest_token")] = { plaintext: newTok, hash: sha(newTok), previous_hash: sha(TOK_PROBE) };
    expect(JSON.parse(creds(build(w, H_COL), "collector", "ingest_tokens.json"))).toEqual({ "probe-a1": [sha(newTok), sha(TOK_PROBE)] });
    expect(creds(build(w, H_PROBE), "probe", "ingest_token")).toBe(newTok);
    expect(validateAgainst("desired.schema.json", build(w, H_COL))).toEqual([]);
  });

  it("is deterministic and side-effect free (input world is not mutated)", () => {
    const w = baseWorld();
    const snap = JSON.stringify(w);
    compile(w, H_COL);
    compile(w, H_DASH);
    compile(w, H_PROBE);
    expect(JSON.stringify(w)).toBe(snap);
    expect(canonicalJson(compile(clone(w), H_PROBE).doc)).toBe(canonicalJson(compile(w, H_PROBE).doc));
  });
});

describe("runner", () => {
  it("is compiled once its collector has reported; uses its own ingest token", () => {
    const w = baseWorld();
    const C_RUN = fid("cmp_", 7);
    w.components.push({ component_id: C_RUN, host_id: H_PROBE, type: "runner", slug: "run-hallb", config: { drills_enabled: false, pullers: [{ source: "ec", interval_s: 60 }] }, enabled: true, facts: {}, created_at: "2026-11-18T10:00:07.000Z" });
    w.secrets[secretKey(C_RUN, "ingest_token")] = { plaintext: "expi_" + "R".repeat(43), hash: sha("r"), previous_hash: null };
    const d = build(w, H_PROBE);
    expect(d.components.map((c) => c.type)).toEqual(["probe", "runner"]);
    expect(validateAgainst("desired.schema.json", d)).toEqual([]);
    expect(JSON.parse(creds(build(w, H_COL), "collector", "ingest_tokens.json"))).toHaveProperty("run-hallb");
  });
});
