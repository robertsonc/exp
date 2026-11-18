// Deterministic World fixtures for the compiler tests (no I/O, fixed ids).
import { createHash } from "node:crypto";
import type { WArtifact, WComponent, WHost, WSecret, WSite, World } from "../../src/compile/types";
import { secretKey } from "../../src/compile/types";

export const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

const CROCK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** fixed, valid ULID-shaped id: prefix + 26 Crockford chars derived from n */
export const fid = (prefix: string, n: number): string => {
  let s = "";
  let v = n * 7919 + 13;
  for (let i = 0; i < 26; i++) {
    s += CROCK[(v + i * 5) % 32];
    v = Math.floor(v / 3) + i + n;
  }
  return prefix + s;
};

export const FP_COL = "DC:2B:CE:95:F2:A0:0C:B9:5B:3A:CF:F5:00:CB:0C:DE:E7:BD:CA:AC:63:CC:83:95:F6:30:EA:F1:27:34:6D:C6";
export const FP_DASH = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
export const PBKDF2 = "pbkdf2_sha256$600000$Tr4XuAwCFH7YD/2V/36QoA==$bJc8Pe3nYnc4c1g1Hx7qwAcWynGWZnTS42MUPGXZZoE=";

export const H_COL = fid("h_", 1);
export const H_DASH = fid("h_", 2);
export const H_PROBE = fid("h_", 3);
export const C_COL = fid("cmp_", 1);
export const C_DASH = fid("cmp_", 2);
export const C_PROBE = fid("cmp_", 3);

export const TOK_PROBE = "expi_" + "P".repeat(43);
export const TOK_PAIR = "expd_" + "D".repeat(43);
export const SSO = "c3NvLXNlY3JldC1mb3ItZ29sZGVuLXRlc3RzLTAxMjM0NTY=";
export const HOOK = "https://hooks.example.invalid/services/FIXTURE";

export function artifactsFor(version: string, seed = 100): WArtifact[] {
  const out: WArtifact[] = [];
  let n = seed;
  const add = (component: string, arch: WArtifact["arch"]) => {
    const name = `exp-${component}-${version}-${arch}.tar.gz`;
    out.push({ artifact_id: fid("art_", n++), version, name, component, arch, sha256: sha(name), size: 1000 + n });
  };
  add("agent", "noarch");
  add("probe", "noarch");
  add("dashboard", "noarch");
  add("runner", "noarch");
  add("collector", "amd64");
  add("collector", "arm64");
  return out;
}

const host = (host_id: string, name: string, ip: string, over: Partial<WHost> = {}): WHost => ({
  host_id,
  name,
  site: "hall-b",
  state: "enrolled",
  arch: "amd64",
  facts: {
    arch: "amd64",
    interfaces: [
      { name: "eno1", state: "up", addrs: [`${ip}/23`], default_route: true, in_use_by: "mgmt" },
      { name: "enp10s0f0", state: "up", addrs: [], default_route: false, in_use_by: "none" },
    ],
  },
  actions: [],
  ...over,
});

export function baseWorld(): World {
  const site: WSite = {
    site: "hall-b",
    name: "Hall B",
    timezone: "America/Chicago",
    edge_label: "EC",
    release_version: "0.1.0",
    target_version: null,
    canary_host_id: null,
    canary_state: "none",
    event_net_reaches_mgmt: false,
    retention: {},
    alerts: { voice: "sysadmin", enabled: true },
  };
  const comp = (component_id: string, host_id: string, type: WComponent["type"], slug: string, config: Record<string, unknown>, facts: WComponent["facts"] = {}, n = 0): WComponent => ({
    component_id,
    host_id,
    type,
    slug,
    config,
    enabled: true,
    facts,
    created_at: `2026-11-18T10:00:0${n}.000Z`,
  });
  const secrets: Record<string, WSecret> = {
    [secretKey(C_PROBE, "ingest_token")]: { plaintext: TOK_PROBE, hash: sha(TOK_PROBE), previous_hash: null },
    [secretKey(`${C_DASH}:${C_COL}`, "dashboard_token")]: { plaintext: TOK_PAIR, hash: sha(TOK_PAIR), previous_hash: null },
    [secretKey(C_DASH, "sso_secret")]: { plaintext: SSO, hash: null, previous_hash: null },
    [secretKey("wh_1", "webhook_url")]: { plaintext: HOOK, hash: null, previous_hash: null },
  };
  return {
    org: { id: "default", name: "HPE Event NOC" },
    settings: { agent_poll_interval_s: 30, agent_status_interval_s: 60 },
    manager_url: "https://exp.example.com",
    sites: { "hall-b": site },
    hosts: {
      [H_COL]: host(H_COL, "col-host", "10.32.98.25"),
      [H_DASH]: host(H_DASH, "dash-host", "10.32.98.30"),
      [H_PROBE]: host(H_PROBE, "probe-host", "10.32.98.41"),
    },
    components: [
      comp(C_COL, H_COL, "collector", "col-hallb", { rules: { lines: ["network", "dhcp", "dns", "internet", "apps", "wifi", "path"] }, reflector: { enabled: true, port: 8862 }, iperf3: { enabled: true, port: 5201 } }, { listen: "10.32.98.25:8443", tls_fingerprint_sha256: FP_COL }, 0),
      comp(C_DASH, H_DASH, "dashboard", "dash-main", { title: "HPE EXP - Hall B" }, { tls_fingerprint_sha256: FP_DASH }, 1),
      comp(
        C_PROBE,
        H_PROBE,
        "probe",
        "probe-a1",
        {
          label: "Hall B east",
          ports: [
            { id: "c01", iface: "enp10s0f0", role: "client", vlan: null, dhcp: { hostname: "exp-hallb-c01", vendor_class: "exp-probe", client_id: "mac" } },
          ],
          heartbeat: { interval_s: 10, gateway: true, dhcp: true, dns: true },
          tests: { dhcp: { interval_s: 300, offer_collect_s: 3.0 } },
        },
        {},
        2,
      ),
    ],
    secrets,
    dashboard_users: [{ dashboard_slug: "dash-main", username: "admin", role: "admin", hash: PBKDF2 }],
    noc_tokens: [{ noc_id: fid("noc_", 1), dashboard_slug: "dash-main", label: "wall display", hash: sha("expn_x"), expires_at: null, revoked_at: null }],
    webhooks: [{ webhook_id: "wh_1", site: "hall-b", format: "slack" }],
    artifacts: [...artifactsFor("0.1.0", 100), ...artifactsFor("0.2.0", 200)],
    now: "2026-11-18T20:00:00.000Z",
  };
}

export const clone = <T>(o: T): T => JSON.parse(JSON.stringify(o)) as T;
