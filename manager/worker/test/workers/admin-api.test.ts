// Admin endpoints: role enforcement, validation, audit, write-only secrets, SSO handoff, ports, enrol flow.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Harness, harness } from "../admin-harness";
import { FACTS, PBKDF2, WEBHOOK_URL, call, enrolHost, env, getDesired, json, resetDb, seedSiteWithRelease, statusReport, postStatus, FINGERPRINT } from "../helpers";
import { b64ToBytes } from "../../src/util/encoding";
import { setClock } from "../../src/util/time";

let h: Harness;
beforeEach(async () => {
  await resetDb();
  h = await harness();
});
afterEach(() => {
  h.restore();
  setClock(null);
});

const auditCount = async (): Promise<number> => ((await env.DB.prepare("SELECT COUNT(*) AS n FROM audit").first<{ n: number }>())?.n ?? 0);
const lastAudit = async (): Promise<{ action: string; actor: string; resource: string; details_json: string }> =>
  (await env.DB.prepare("SELECT action, actor, resource, details_json FROM audit ORDER BY ts DESC, evt_id DESC LIMIT 1").first())!;

describe("role enforcement (05-manager.md section 4)", () => {
  const mutations: Array<[string, string, unknown]> = [
    ["POST", "/sites", { site: "x", name: "X", timezone: "UTC" }],
    ["PATCH", "/sites/x", { name: "Y" }],
    ["DELETE", "/sites/x", undefined],
    ["POST", "/hosts", { name: "h", site: "x" }],
    ["PATCH", "/hosts/h_01ARZ3NDEKTSV4RRFFQ69G5FAV", { name: "n" }],
    ["DELETE", "/hosts/h_01ARZ3NDEKTSV4RRFFQ69G5FAV", undefined],
    ["POST", "/hosts/h_01ARZ3NDEKTSV4RRFFQ69G5FAV/enrol-token", {}],
    ["POST", "/hosts/h_01ARZ3NDEKTSV4RRFFQ69G5FAV/decommission", {}],
    ["POST", "/hosts/h_01ARZ3NDEKTSV4RRFFQ69G5FAV/rotate-agent", {}],
    ["POST", "/hosts/h_01ARZ3NDEKTSV4RRFFQ69G5FAV/components", { type: "probe", id: "p", config: {} }],
    ["PATCH", "/components/cmp_01ARZ3NDEKTSV4RRFFQ69G5FAV", { enabled: false }],
    ["DELETE", "/components/cmp_01ARZ3NDEKTSV4RRFFQ69G5FAV", undefined],
    ["POST", "/components/cmp_01ARZ3NDEKTSV4RRFFQ69G5FAV/restart", {}],
    ["PUT", "/components/cmp_01ARZ3NDEKTSV4RRFFQ69G5FAV/ports", { ports: [] }],
    ["POST", "/components/cmp_01ARZ3NDEKTSV4RRFFQ69G5FAV/rotate", {}],
    ["POST", "/releases/import", { version: "0.1.0", source: "github" }],
    ["PATCH", "/sites/x/release", { version: "0.1.0" }],
    ["POST", "/dashboards/d/users", { username: "u", role: "viewer", hash: PBKDF2 }],
    ["POST", "/dashboards/d/noc-tokens", { label: "l" }],
    ["PUT", "/dashboards/d/tls", { mode: "self_signed" }],
    ["PUT", "/sites/x/alerts", { config: {}, webhooks: [] }],
    ["POST", "/sites/x/alerts/test", {}],
    ["POST", "/issues/iss_01ARZ3NDEKTSV4RRFFQ69G5FAV/snooze", { for: "1h" }],
    ["PUT", "/settings/fleet-thresholds", {}],
    ["PUT", "/settings/platform-webhook", { format: "json" }],
    ["PUT", "/integrations/ec", { config: {} }],
    ["PATCH", "/settings", { org_name: "x" }],
  ];

  it("viewer and operator are refused (403) on every mutation, before any validation or lookup", async () => {
    const before = await auditCount();
    for (const role of ["viewer", "operator"] as const) {
      for (const [m, p, b] of mutations) {
        const r = await h.json(role, m, p, b);
        expect(r.status, `${role} ${m} ${p}`).toBe(403);
        expect((r.body as { error: { code: string } }).error.code).toBe("insufficient_role");
      }
    }
    expect(await auditCount()).toBe(before);
  });

  it("admins are refused on owner-only endpoints; the owner passes the role gate", async () => {
    for (const [m, p, b] of [["PUT", "/integrations/ec", { config: {} }], ["PATCH", "/settings", { org_name: "Z" }]] as Array<[string, string, unknown]>) {
      expect((await h.json("admin", m, p, b)).status).toBe(403);
    }
    expect((await h.json("owner", "PATCH", "/settings", { org_name: "Z" })).status).toBe(200);
    expect((await h.json("owner", "PUT", "/integrations/ec", { config: { url: "https://orch.example.com" } })).status).toBe(200);
  });

  it("viewers can read, and cannot read the audit log or dashboard user lists", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    for (const p of ["/me", "/sites", "/sites/hall-b", "/hosts", "/releases", "/overview", "/fleet/summary", "/fleet/sites", "/fleet/hosts", "/issues", "/settings", "/settings/fleet-thresholds", "/settings/platform-webhook", "/sites/hall-b/alerts", "/integrations/ec"]) {
      expect((await h.json("viewer", "GET", p)).status, p).toBe(200);
    }
    expect((await h.json("viewer", "GET", "/audit")).status).toBe(403);
    expect((await h.json("operator", "GET", "/audit")).status).toBe(403);
    expect((await h.json("admin", "GET", "/audit")).status).toBe(200);
    expect((await h.json("viewer", "GET", "/dashboards/x/users")).status).toBe(403);
  });
});

describe("sites, hosts, enrolment", () => {
  it("site CRUD writes exactly one audit event per mutation", async () => {
    let n = await auditCount();
    const c = await h.json("admin", "POST", "/sites", { site: "hall-b", name: "Hall B", timezone: "America/Chicago", retention: { metrics_days: 30, records_days: 7 } });
    expect(c.status).toBe(201);
    expect(c.body).toMatchObject({ site: "hall-b", name: "Hall B", timezone: "America/Chicago", release_version: null, retention: { metrics_days: 30, records_days: 7 } });
    expect(await auditCount()).toBe(++n);
    expect((await lastAudit()).action).toBe("site.create");
    expect((await h.json("admin", "POST", "/sites", { site: "hall-b", name: "dup", timezone: "UTC" })).status).toBe(409);
    expect(await auditCount()).toBe(n);
    const p = await h.json("admin", "PATCH", "/sites/hall-b", { name: "Hall B2", edge_label: "SD" });
    expect(p.body).toMatchObject({ name: "Hall B2", edge_label: "SD" });
    expect(await auditCount()).toBe(++n);
    expect((await h.json("admin", "PATCH", "/sites/hall-b", {})).status).toBe(400);
    expect((await h.json("admin", "PATCH", "/sites/hall-b", { nope: 1 })).status).toBe(400);
    expect((await h.json("admin", "GET", "/sites")).body).toMatchObject({ items: [{ site: "hall-b" }], next_cursor: null });
    expect((await h.json("admin", "DELETE", "/sites/hall-b")).status).toBe(204);
    expect(await auditCount()).toBe(++n);
    expect((await h.json("admin", "GET", "/sites/hall-b")).status).toBe(404);
    expect((await h.json("admin", "POST", "/sites", { site: "Bad Slug", name: "x", timezone: "UTC" })).status).toBe(400);
  });

  it("host create returns the one-liner with a single-use 1-hour token; the token works exactly once", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    const r = await h.json<{ host: { host_id: string; state: string }; enrol: { token: string; command: string; expires_at: string } }>("admin", "POST", "/hosts", { name: "srv-01", site: "hall-b" });
    expect(r.status).toBe(201);
    expect(r.res.headers.get("cache-control")).toBe("no-store");
    const { token, command, expires_at } = r.body.enrol;
    expect(token).toMatch(/^expe_[A-Za-z0-9_-]{43}$/);
    expect(command).toBe(`curl -fsSL https://manager.example.test/install.sh | sudo bash -s -- ${token}`);
    const ttl = Date.parse(expires_at) - Date.now();
    expect(ttl).toBeGreaterThan(3590_000);
    expect(ttl).toBeLessThanOrEqual(3600_000);
    expect(r.body.host.state).toBe("pending");
    // only the hash is stored
    const dump = JSON.stringify((await env.DB.prepare("SELECT * FROM enrol_tokens").all()).results);
    expect(dump).not.toContain(token);
    expect((await call("/api/agent/v1/enrol", json({ token, facts: FACTS() }))).status).toBe(201);
    expect((await call("/api/agent/v1/enrol", json({ token, facts: FACTS() }))).status).toBe(410);
    // the audit event never carries the token
    expect(JSON.stringify((await env.DB.prepare("SELECT details_json FROM audit").all()).results)).not.toContain(token);
  });

  it("enrol-token reissue revokes the older unused token; decommission sets decommission=true in desired", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    const c = await h.json<{ host: { host_id: string }; enrol: { token: string } }>("admin", "POST", "/hosts", { name: "srv-01", site: "hall-b" });
    const id = c.body.host.host_id;
    const t2 = await h.json<{ token: string; command: string; expires_at: string }>("admin", "POST", `/hosts/${id}/enrol-token`, {});
    expect(t2.status).toBe(201);
    expect(t2.body.command).toContain(t2.body.token);
    expect((await call("/api/agent/v1/enrol", json({ token: c.body.enrol.token, facts: FACTS() }))).status).toBe(401);
    const e = await call("/api/agent/v1/enrol", json({ token: t2.body.token, facts: FACTS() }));
    expect(e.status).toBe(201);
    const secret = ((await e.json()) as { agent_secret: string }).agent_secret;
    const d = await h.json<{ state: string }>("admin", "POST", `/hosts/${id}/decommission`, {});
    expect(d.status).toBe(202);
    expect(d.body.state).toBe("decommissioning");
    const doc = (await (await getDesired(secret)).json()) as { decommission: boolean; components: unknown[] };
    expect(doc.decommission).toBe(true);
    expect(doc.components).toEqual([]);
    // an enrolled host cannot be deleted before it is decommissioned and removed
    expect((await h.json("admin", "DELETE", `/hosts/${id}`)).status).toBe(409);
  });

  it("deleting a never-enrolled host removes it; patch moves it between sites", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    await h.json("admin", "POST", "/sites", { site: "hall-c", name: "Hall C", timezone: "UTC" });
    const c = await h.json<{ host: { host_id: string } }>("admin", "POST", "/hosts", { name: "srv-01", site: "hall-b" });
    const id = c.body.host.host_id;
    expect((await h.json("admin", "PATCH", `/hosts/${id}`, { site: "hall-c", name: "srv-x" })).body).toMatchObject({ site: "hall-c", name: "srv-x" });
    expect((await h.json("admin", "PATCH", `/hosts/${id}`, { site: "nope" })).status).toBe(404);
    expect((await h.json("admin", "DELETE", `/hosts/${id}`)).status).toBe(204);
    expect((await h.json("admin", "GET", `/hosts/${id}`)).status).toBe(404);
    expect((await h.json("admin", "DELETE", "/sites/hall-b")).status).toBe(204);
  });
});

describe("components, ports, restart, rotation", () => {
  async function probeHost() {
    await seedSiteWithRelease("hall-b", "0.1.0");
    const host = await enrolHost("hall-b", "probe-host", FACTS({
      interfaces: [
        { name: "eno1", mac: "18:66:da:00:00:01", state: "up", speed_mbps: 1000, driver: "tg3", addrs: ["10.32.98.25/23"], default_route: true, in_use_by: "mgmt" },
        { name: "enp10s0f0", mac: "18:66:da:00:00:02", state: "up", speed_mbps: 1000, driver: "ixgbe", addrs: [], default_route: false, in_use_by: "none" },
        { name: "enp10s0f1", mac: "18:66:da:00:00:03", state: "up", speed_mbps: 1000, driver: "ixgbe", addrs: [], default_route: false, in_use_by: "none" },
      ],
    }));
    const c = await h.json<{ component_id: string; type: string; id: string; health: string }>("admin", "POST", `/hosts/${host.host_id}/components`, { type: "probe", id: "probe-a1", config: { label: "A1" } });
    expect(c.status).toBe(201);
    return { host, cid: c.body.component_id };
  }

  it("ports PUT refuses the management (default-route) interface and unknown interfaces with a clear error", async () => {
    const { host, cid } = await probeHost();
    const client = (iface: string, id = "c01") => ({ id, iface, role: "client", vlan: null, dhcp: { hostname: "exp-c01", vendor_class: "exp-probe", client_id: "mac" } });
    const mgmt = await h.json<{ error: { code: string; message: string } }>("admin", "PUT", `/components/${cid}/ports`, { ports: [client("eno1")] });
    expect(mgmt.status).toBe(422);
    expect(mgmt.body.error.code).toBe("mgmt_interface_refused");
    expect(mgmt.body.error.message).toContain("eno1");
    const unknown = await h.json<{ error: { code: string } }>("admin", "PUT", `/components/${cid}/ports`, { ports: [client("enp99")] });
    expect(unknown.status).toBe(422);
    expect(unknown.body.error.code).toBe("unknown_interface");
    // refused means nothing changed and nothing was audited
    const cfg = await env.DB.prepare("SELECT config_json FROM components WHERE component_id = ?1").bind(cid).first<{ config_json: string }>();
    expect(JSON.parse(cfg!.config_json).ports).toBeUndefined();
    expect((await env.DB.prepare("SELECT 1 AS x FROM audit WHERE action = 'component.ports'").first())).toBeNull();
    // a mixed list is refused as a whole
    expect((await h.json("admin", "PUT", `/components/${cid}/ports`, { ports: [client("enp10s0f0"), client("eno1", "c02")] })).status).toBe(422);
    // duplicates
    expect((await h.json<{ error: { code: string } }>("admin", "PUT", `/components/${cid}/ports`, { ports: [client("enp10s0f0"), client("enp10s0f0", "c02")] })).body.error.code).toBe("duplicate_port");
    // valid
    const ok = await h.json<{ ports: unknown[]; desired_version: number }>("admin", "PUT", `/components/${cid}/ports`, { ports: [client("enp10s0f0"), { id: "t01", iface: "enp10s0f1", role: "target", address: "10.9.0.5/24", gateway: "10.9.0.1", serve: { reflector: true } }] });
    expect(ok.status).toBe(200);
    expect(ok.body.ports).toHaveLength(2);
    expect(ok.body.desired_version).toBeGreaterThan(0);
    expect((await lastAudit()).action).toBe("component.ports");
    const doc = (await (await getDesired(host.secret)).json()) as { components: Array<{ config: { ports: Array<{ iface: string }> } }> };
    expect(doc.components[0]!.config.ports.map((p) => p.iface)).toEqual(["enp10s0f0", "enp10s0f1"]);
    // the same rule applies through a plain config PATCH
    const bad = await h.json<{ error: { code: string } }>("admin", "PATCH", `/components/${cid}`, { config: { ports: [client("eno1")] } });
    expect(bad.status).toBe(422);
    expect(bad.body.error.code).toBe("mgmt_interface_refused");
    // non-probe components have no ports
    const col = await h.json<{ component_id: string }>("admin", "POST", `/hosts/${host.host_id}/components`, { type: "collector", id: "col-x", config: {} });
    expect((await h.json("admin", "PUT", `/components/${col.body.component_id}/ports`, { ports: [client("enp10s0f0")] })).status).toBe(422);
  });

  it("component patch/delete/restart; restart adds one action per component and shows up in desired", async () => {
    const { host, cid } = await probeHost();
    const p = await h.json<{ enabled: boolean; config: { label: string } }>("admin", "PATCH", `/components/${cid}`, { config: { label: "A2" }, enabled: false });
    expect(p.body).toMatchObject({ enabled: false, config: { label: "A2" } });
    expect((await h.json("admin", "PATCH", `/components/${cid}`, {})).status).toBe(400); // an empty patch is a validation error
  });

  it("restart action reaches the agent once; rotate rejects types without tokens; rotate returns the overlap window", async () => {
    const { host, cid } = await probeHost();
    const r1 = await h.json<{ host_id: string; action_id: string; desired_version: number }>("admin", "POST", `/components/${cid}/restart`, {});
    expect(r1.status).toBe(202);
    const r2 = await h.json<{ action_id: string }>("admin", "POST", `/components/${cid}/restart`, {});
    expect(r2.body.action_id).toBe(r1.body.action_id);
    const doc = (await (await getDesired(host.secret)).json()) as { actions: Array<{ id: string; type: string; component_id: string }> };
    expect(doc.actions).toEqual([{ id: r1.body.action_id, type: "restart_component", component_id: cid }]);
    const rot = await h.json<{ component_id: string; kinds: string[]; previous_valid_until: string; desired_version: number }>("admin", "POST", `/components/${cid}/rotate`, {});
    expect(rot.status).toBe(200);
    expect(rot.body.kinds).toEqual(["ingest_token"]);
    expect(Date.parse(rot.body.previous_valid_until) - Date.now()).toBeGreaterThan(590_000);
    expect(JSON.stringify(rot.body)).not.toMatch(/exp[aeidn]_/);
    const col = await h.json<{ component_id: string }>("admin", "POST", `/hosts/${host.host_id}/components`, { type: "collector", id: "col-x", config: {} });
    expect((await h.json("admin", "POST", `/components/${col.body.component_id}/rotate`, {})).status).toBe(400);
    const ra = await h.json<{ action_id: string }>("admin", "POST", `/hosts/${host.host_id}/rotate-agent`, {});
    expect(ra.status).toBe(202);
    expect(ra.body.action_id).toMatch(/^act_/);
    expect((await h.json("admin", "DELETE", `/components/${cid}`)).status).toBe(204);
    expect((await h.json("admin", "GET", `/hosts/${host.host_id}/components`)).body).toMatchObject({ items: [{ id: "col-x" }] });
  });
});

describe("dashboards: users, NOC tokens, SSO handoff", () => {
  async function dash() {
    await seedSiteWithRelease("hall-b", "0.1.0");
    const host = await enrolHost("hall-b", "dash-host", FACTS({ interfaces: [{ name: "eno1", mac: "18:66:da:00:00:09", state: "up", speed_mbps: 1000, addrs: ["10.32.98.30/23"], default_route: true, in_use_by: "mgmt" }] }));
    const c = await h.json<{ component_id: string }>("admin", "POST", `/hosts/${host.host_id}/components`, { type: "dashboard", id: "dash-main", config: {} });
    return { host, cid: c.body.component_id };
  }

  it("accepts only pbkdf2_sha256$600000$salt$hash; anything that looks like plaintext is refused", async () => {
    await dash();
    const bad = ["hunter2", "Password123!", "pbkdf2_sha256$1000$AAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAA", "pbkdf2_sha256$600000$short$x", "$2b$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz0123", "sha256:abc", "", PBKDF2 + "x y"];
    for (const hash of bad) {
      const r = await h.json<{ error: { code: string } }>("admin", "POST", "/dashboards/dash-main/users", { username: "alice", role: "viewer", hash });
      expect(r.status, hash).toBe(400);
    }
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM dashboard_users").first<{ n: number }>())!.n).toBe(0);
    const ok = await h.json<{ usr_id: string; username: string }>("admin", "POST", "/dashboards/dash-main/users", { username: "alice", role: "operator", hash: PBKDF2 });
    expect(ok.status).toBe(201);
    expect(JSON.stringify(ok.body)).not.toContain("pbkdf2");
    expect((await h.json("admin", "POST", "/dashboards/dash-main/users", { username: "alice", role: "viewer", hash: PBKDF2 })).status).toBe(409);
    const list = await h.json<{ items: Array<Record<string, unknown>> }>("admin", "GET", "/dashboards/dash-main/users");
    expect(list.body.items).toHaveLength(1);
    expect(JSON.stringify(list.body)).not.toContain("pbkdf2");
    expect((await h.json("admin", "DELETE", `/dashboards/dash-main/users/${ok.body.usr_id}`)).status).toBe(204);
    expect((await h.json("admin", "DELETE", `/dashboards/dash-main/users/${ok.body.usr_id}`)).status).toBe(404);
  });

  it("NOC tokens are shown once; lists carry no token and no hash; revoke is audited", async () => {
    await dash();
    const c = await h.json<{ noc: { noc_id: string }; token: string; url: string }>("admin", "POST", "/dashboards/dash-main/noc-tokens", { label: "wall", expires_in_h: 24 });
    expect(c.status).toBe(201);
    expect(c.body.token).toMatch(/^expn_[A-Za-z0-9_-]{43}$/);
    expect(c.body.url).toBe("https://10.32.98.30/noc");
    expect(c.body.url).not.toContain(c.body.token);
    const l = await h.json("admin", "GET", "/dashboards/dash-main/noc-tokens");
    expect(JSON.stringify(l.body)).not.toContain(c.body.token);
    expect(JSON.stringify(l.body)).not.toMatch(/"hash"/);
    expect(JSON.stringify((await env.DB.prepare("SELECT * FROM noc_tokens").all()).results)).not.toContain(c.body.token);
    expect((await h.json("admin", "DELETE", `/dashboards/dash-main/noc-tokens/${c.body.noc.noc_id}`)).status).toBe(204);
    expect((await lastAudit()).action).toBe("noc_token.revoke");
  });

  it("SSO handoff: auto-submitting POST form with an HS256 JWT (contract section 12), never a URL; viewers may use it", async () => {
    const { cid } = await dash();
    const before = await auditCount();
    const res = await h.api("viewer", "POST", "/dashboards/dash-main/sso", {});
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/html/);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const csp = res.headers.get("content-security-policy")!;
    expect(csp).toContain("form-action https://10.32.98.30");
    expect(csp).toMatch(/script-src 'sha256-[A-Za-z0-9+/=]+'/);
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).toContain("default-src 'none'");
    const html = await res.text();
    expect(html).toContain('method="post"');
    expect(html).toContain('action="https://10.32.98.30/auth/sso"');
    expect(html).not.toMatch(/\son[a-z]+=/); // no inline event handlers
    const token = /name="token" value="([^"]+)"/.exec(html)![1]!;
    expect(html.match(/<script>/g)).toHaveLength(1);
    expect(html).not.toContain(`${token}"`.replace(token, "") + "?token"); // never in a query string
    expect(html).not.toMatch(/[?&]token=/);
    // verify the JWT the way the dashboard does: HS256, key = the 32 bytes of the dashboard's sso_secret
    const [hd, pl, sig] = token.split(".") as [string, string, string];
    const sec = await env.DB.prepare("SELECT secret_id FROM secrets WHERE owner_ref = ?1 AND kind = 'sso_secret'").bind(cid).first<{ secret_id: string }>();
    const { getSecretRow, readSecret } = await import("../../src/secrets/store");
    const secret = await readSecret(env, (await getSecretRow(env, sec!.secret_id))!);
    const key = await crypto.subtle.importKey("raw", b64ToBytes(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const b64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
    expect(await crypto.subtle.verify("HMAC", key, b64u(sig), new TextEncoder().encode(`${hd}.${pl}`))).toBe(true);
    expect(JSON.parse(new TextDecoder().decode(b64u(hd)))).toEqual({ alg: "HS256", typ: "JWT" });
    const claims = JSON.parse(new TextDecoder().decode(b64u(pl))) as Record<string, unknown>;
    expect(claims).toMatchObject({ iss: "exp-manager:default", aud: "dash-main", sub: "viewer@example.com", role: "viewer" });
    expect((claims.exp as number) - (claims.iat as number)).toBe(120);
    expect(claims.jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(await auditCount()).toBe(before + 1);
    expect((await lastAudit()).action).toBe("dashboard.sso");
    // roles map: operator -> operator, admin/owner -> admin; each mint has a fresh jti
    const second = /name="token" value="([^"]+)"/.exec(await (await h.api("owner", "POST", "/dashboards/dash-main/sso", {})).text())![1]!;
    expect(JSON.parse(new TextDecoder().decode(b64u(second.split(".")[1]!)))).toMatchObject({ role: "admin" });
    expect(second).not.toBe(token);
    expect((await h.json("viewer", "POST", "/dashboards/nope/sso", {})).status).toBe(404);
  });
});

describe("alerts, webhooks and other write-only secrets", () => {
  async function site() {
    await h.json("admin", "POST", "/sites", { site: "hall-b", name: "Hall B", timezone: "America/Chicago" });
  }
  const cfg = { enabled: true, voice: "plain", hold_down_s: 30, hold_back_s: 10, reopen_s: 300, calm_s: 300 };

  it("webhook URLs: http://, private, loopback, link-local, IPv6 and credentialed URLs are refused (SR-15)", async () => {
    await site();
    const bad = ["http://hooks.slack.com/services/x", "https://10.0.0.1/hook", "https://127.0.0.1/hook", "https://localhost/hook", "https://169.254.169.254/latest", "https://192.168.1.5/x", "https://172.16.0.9/x", "https://[::1]/x", "https://2130706433/x", "https://0x7f.1/x", "https://user:pw@hooks.example.com/x", "https://intranet/x", "https://printer.local/x", "ftp://hooks.example.com/x", "not a url"];
    for (const url of bad) {
      const r = await h.json("admin", "PUT", "/sites/hall-b/alerts", { config: cfg, webhooks: [{ format: "slack", url }] });
      expect(r.status, url).toBe(400);
    }
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM webhooks").first<{ n: number }>())!.n).toBe(0);
    const pw = await h.json("admin", "PUT", "/settings/platform-webhook", { format: "slack", url: "http://hooks.slack.com/x" });
    expect(pw.status).toBe(400);
    const pw2 = await h.json("admin", "PUT", "/settings/platform-webhook", { format: "slack", url: "https://10.0.0.1/x" });
    expect(pw2.status).toBe(400);
  });

  it("webhook URLs are write-only: the API returns {set, updated_at}, the audit log never has them, replace and remove work", async () => {
    await site();
    const put = await h.json<{ config: Record<string, unknown>; webhooks: Array<{ id: string; format: string; url: { set: boolean; updated_at: string } }> }>("admin", "PUT", "/sites/hall-b/alerts", { config: cfg, webhooks: [{ format: "slack", url: WEBHOOK_URL }] });
    expect(put.status).toBe(200);
    expect(put.body.webhooks).toHaveLength(1);
    expect(put.body.webhooks[0]!.url.set).toBe(true);
    expect(put.body.webhooks[0]!.url.updated_at).toMatch(/Z$/);
    const id = put.body.webhooks[0]!.id;
    const get = await h.json("admin", "GET", "/sites/hall-b/alerts");
    expect(JSON.stringify(get.body)).not.toContain("hooks.slack.com");
    expect(JSON.stringify(get.body)).not.toContain("XXXXSECRETXXXX");
    expect(JSON.stringify((await env.DB.prepare("SELECT * FROM audit").all()).results)).not.toContain("hooks.slack");
    expect(JSON.stringify((await env.DB.prepare("SELECT * FROM secrets").all()).results)).not.toContain("hooks.slack");
    // omitting the url keeps the stored value, changing the format is allowed
    const keep = await h.json<{ webhooks: Array<{ url: { set: boolean } }> }>("admin", "PUT", "/sites/hall-b/alerts", { config: cfg, webhooks: [{ id, format: "teams" }] });
    expect(keep.body.webhooks[0]!.url.set).toBe(true);
    // test send decrypts the stored URL and posts to it; the result never echoes the URL
    h.handlers.push((url) => (url.startsWith("https://hooks.slack.com/") ? new Response("ok", { status: 200 }) : undefined));
    const t = await h.json<{ results: Array<{ webhook_id: string; ok: boolean; http_status: number }> }>("admin", "POST", "/sites/hall-b/alerts/test", {});
    expect(t.body.results).toEqual([{ webhook_id: id, ok: true, http_status: 200, error: null }]);
    expect(h.calls.some((c) => c.url === WEBHOOK_URL && (c.init as RequestInit).redirect === "manual")).toBe(true);
    // the compiled collector credentials (not the API) are what carries the URL to the host
    const del = await h.json<{ webhooks: unknown[] }>("admin", "PUT", "/sites/hall-b/alerts", { config: cfg, webhooks: [] });
    expect(del.body.webhooks).toEqual([]);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM secrets WHERE kind = 'webhook_url'").first<{ n: number }>())!.n).toBe(0);
  });

  it("a webhook that answers with a redirect is a failed delivery (redirects are not followed)", async () => {
    await site();
    await h.json("admin", "PUT", "/sites/hall-b/alerts", { config: cfg, webhooks: [{ format: "json", url: WEBHOOK_URL }] });
    h.handlers.push(() => new Response(null, { status: 302, headers: { location: "https://169.254.169.254/" } }));
    const t = await h.json<{ results: Array<{ ok: boolean; error: string }> }>("admin", "POST", "/sites/hall-b/alerts/test", {});
    expect(t.body.results[0]).toMatchObject({ ok: false, error: "redirect not followed" });
    expect(h.calls.filter((c) => c.url.includes("169.254")).length).toBe(0);
  });

  it("integrations: credentials are write-only and secret-looking config keys are refused", async () => {
    const put = await h.json<{ credentials: { set: boolean; updated_at: string }; config: Record<string, unknown> }>("owner", "PUT", "/integrations/ec", { config: { url: "https://orch.example.com" }, credentials: { api_key: "super-secret-api-key-value" }, allowlist: [{ nePk: "1.NE", interfaces: ["wan0"] }] });
    expect(put.status).toBe(200);
    expect(put.body.credentials.set).toBe(true);
    expect(JSON.stringify((await h.json("viewer", "GET", "/integrations/ec")).body)).not.toContain("super-secret");
    expect(JSON.stringify((await env.DB.prepare("SELECT * FROM secrets").all()).results)).not.toContain("super-secret");
    expect(JSON.stringify((await env.DB.prepare("SELECT * FROM audit").all()).results)).not.toContain("super-secret");
    expect((await h.json("owner", "PUT", "/integrations/ec", { config: { api_key: "x" } })).status).toBe(400);
    expect((await h.json("owner", "PUT", "/integrations/ec", { config: { url: "http://orch.example.com" } })).status).toBe(400);
    expect((await h.json("owner", "PUT", "/integrations/other", { config: {} })).status).toBe(404);
    // omitting credentials keeps them
    const keep = await h.json<{ credentials: { set: boolean } }>("owner", "PUT", "/integrations/ec", { config: { url: "https://orch2.example.com" } });
    expect(keep.body.credentials.set).toBe(true);
  });

  it("settings: owner patches org / admins; the configured owner cannot be demoted; audit has one event", async () => {
    await h.json("owner", "GET", "/me"); // first sign-in of the owner creates the owner row (its own audit event)
    const n = await auditCount();
    const r = await h.json<{ org_name: string; admins: Array<{ email: string; role: string }>; default_retention: unknown }>("owner", "PATCH", "/settings", { org_name: "HPE Event NOC", default_retention: { metrics_days: 14, records_days: 3 }, admins: [{ email: "Ops@Example.com", role: "operator" }] });
    expect(r.status).toBe(200);
    expect(r.body.org_name).toBe("HPE Event NOC");
    expect(r.body.admins.find((a) => a.email === "ops@example.com")?.role).toBe("operator");
    expect(await auditCount()).toBe(n + 1);
    expect((await h.json("owner", "PATCH", "/settings", { admins: [{ email: "owner@example.com", role: "viewer" }] })).status).toBe(409);
    expect((await h.json("owner", "PATCH", "/settings", { admins: [{ email: "not-an-email", role: "viewer" }] })).status).toBe(400);
    expect((await h.json("owner", "PATCH", "/settings", {})).status).toBe(400);
  });
});

describe("no secret value is ever readable through a GET (SR-14)", () => {
  it("scans every GET response of a fully populated manager for exp[aeidn]_ tokens, webhook URLs, hashes and keys", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    const col = await enrolHost("hall-b", "col-host");
    const dashH = await enrolHost("hall-b", "dash-host", FACTS({ interfaces: [{ name: "eno1", mac: "18:66:da:00:00:09", state: "up", speed_mbps: 1000, addrs: ["10.32.98.30/23"], default_route: true, in_use_by: "mgmt" }] }));
    const probe = await enrolHost("hall-b", "probe-host");
    const mk = async (host: string, type: string, id: string, config: Record<string, unknown> = {}) =>
      (await h.json<{ component_id: string }>("admin", "POST", `/hosts/${host}/components`, { type, id, config })).body.component_id;
    const colC = await mk(col.host_id, "collector", "col-hallb");
    const dashC = await mk(dashH.host_id, "dashboard", "dash-main");
    const probeC = await mk(probe.host_id, "probe", "probe-a1", { label: "A1" });
    await postStatus(col.secret, statusReport({ components: [{ type: "collector", id: "col-hallb", state: "running", health: "ok", facts: { listen: "10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT }, metrics: { ingest_records_per_s: 5 } }] }));
    await h.json("admin", "PUT", "/sites/hall-b/alerts", { config: { enabled: true, voice: "plain", hold_down_s: 30, hold_back_s: 10, reopen_s: 300, calm_s: 300 }, webhooks: [{ format: "slack", url: WEBHOOK_URL }] });
    await h.json("admin", "PUT", "/settings/platform-webhook", { format: "slack", url: "https://hooks.slack.com/services/T9/B9/PLATFORMSECRET" });
    await h.json("owner", "PUT", "/integrations/mist", { config: { url: "https://api.mist.example.com" }, credentials: { token: "mist-token-value-1234567890" } });
    const u = await h.json<{ usr_id: string }>("admin", "POST", "/dashboards/dash-main/users", { username: "bob", role: "viewer", hash: PBKDF2 });
    const noc = await h.json<{ token: string }>("admin", "POST", "/dashboards/dash-main/noc-tokens", { label: "wall" });
    await h.json("admin", "POST", `/components/${probeC}/rotate`, {});
    await h.json("admin", "POST", `/hosts/${col.host_id}/rotate-agent`, {});
    await h.json("admin", "POST", `/components/${colC}/restart`, {});
    const paths = [
      "/me", "/sites", "/sites/hall-b", "/sites/hall-b/alerts", "/hosts", `/hosts/${col.host_id}`, `/hosts/${col.host_id}/status`, `/hosts/${col.host_id}/components`,
      `/hosts/${probe.host_id}/components`, `/hosts/${dashH.host_id}/components`, "/releases", `/dashboards/dash-main/users`, `/dashboards/dash-main/noc-tokens`,
      "/integrations/ec", "/integrations/mist", "/overview", `/hosts/${col.host_id}/status`, "/fleet/summary", "/fleet/sites", "/fleet/hosts", `/fleet/hosts/${col.host_id}/metrics?range=24h`,
      `/fleet/components/${colC}/metrics?range=7d`, "/fleet/top?metric=cpu", "/issues", "/issues?state=resolved", "/settings", "/settings/fleet-thresholds", "/settings/platform-webhook", "/audit?limit=1000",
    ];
    void dashC;
    const bad = /exp[aeidn]_[A-Za-z0-9_-]{8,}|hooks\.slack\.com|PLATFORMSECRET|XXXXSECRETXXXX|pbkdf2_sha256|mist-token|BEGIN (RSA |EC )?PRIVATE KEY|sso_secret"\s*:\s*"/;
    let scanned = 0;
    for (const p of paths) {
      for (const role of ["viewer", "admin", "owner"] as const) {
        const r = await h.api(role, "GET", p);
        const text = await r.text();
        expect(text, `${role} GET ${p}`).not.toMatch(bad);
        if (r.status === 200) scanned++;
      }
    }
    expect(scanned).toBeGreaterThan(60);
    expect(u.status).toBe(201);
    expect(noc.body.token).toMatch(/^expn_/);
    // and the mutation responses that are NOT creating a secret never carry one either
    for (const [m, p, b] of [["PATCH", `/components/${probeC}`, { config: { label: "A1b" } }], ["PATCH", "/sites/hall-b", { name: "Hall B" }]] as Array<[string, string, unknown]>) {
      expect(await (await h.api("admin", m, p, b)).text()).not.toMatch(bad);
    }
  });
});

describe("one audit event per mutation (05-manager.md section 15 item 7)", () => {
  it("every admin mutation adds exactly one event with the expected action and no secret value", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    await h.json("owner", "GET", "/me"); // creates the owner row (its own event) before counting
    const host = await enrolHost("hall-b", "probe-host", FACTS({
      interfaces: [
        { name: "eno1", mac: "18:66:da:00:00:01", state: "up", speed_mbps: 1000, addrs: ["10.32.98.25/23"], default_route: true, in_use_by: "mgmt" },
        { name: "enp10s0f0", mac: "18:66:da:00:00:02", state: "up", speed_mbps: 1000, addrs: [], default_route: false, in_use_by: "none" },
      ],
    }));
    const steps: Array<{ role: "admin" | "owner"; m: string; p: string | (() => string); b?: unknown; action: string; status?: number }> = [];
    let cid = "";
    let dcid = "";
    let usr = "";
    let noc = "";
    const dashHost = await enrolHost("hall-b", "dash-host", FACTS({ interfaces: [{ name: "eno1", mac: "18:66:da:00:00:09", state: "up", speed_mbps: 1000, addrs: ["10.32.98.30/23"], default_route: true, in_use_by: "mgmt" }] }));
    const cfg = { enabled: true, voice: "plain", hold_down_s: 30, hold_back_s: 10, reopen_s: 300, calm_s: 300 };
    steps.push(
      { role: "admin", m: "POST", p: "/sites", b: { site: "hall-c", name: "C", timezone: "UTC" }, action: "site.create" },
      { role: "admin", m: "PATCH", p: "/sites/hall-c", b: { name: "C2" }, action: "site.update" },
      { role: "admin", m: "POST", p: "/hosts", b: { name: "h-new", site: "hall-c" }, action: "host.create" },
      { role: "admin", m: "POST", p: `/hosts/${host.host_id}/components`, b: { type: "probe", id: "probe-a1", config: {} }, action: "component.create" },
      { role: "admin", m: "POST", p: `/hosts/${dashHost.host_id}/components`, b: { type: "dashboard", id: "dash-main", config: {} }, action: "component.create" },
      { role: "admin", m: "PATCH", p: () => `/components/${cid}`, b: { config: { label: "x" } }, action: "component.update" },
      { role: "admin", m: "PUT", p: () => `/components/${cid}/ports`, b: { ports: [{ id: "c01", iface: "enp10s0f0", role: "client" }] }, action: "component.ports" },
      { role: "admin", m: "POST", p: () => `/components/${cid}/restart`, b: {}, action: "component.restart" },
      { role: "admin", m: "POST", p: () => `/components/${cid}/rotate`, b: {}, action: "component.rotate" },
      { role: "admin", m: "POST", p: `/hosts/${host.host_id}/rotate-agent`, b: {}, action: "host.rotate_agent" },
      { role: "admin", m: "PATCH", p: `/hosts/${host.host_id}`, b: { name: "renamed" }, action: "host.update" },
      { role: "admin", m: "POST", p: `/hosts/${host.host_id}/enrol-token`, b: {}, action: "host.enrol_token" },
      { role: "admin", m: "POST", p: () => `/dashboards/dash-main/users`, b: { username: "u1", role: "viewer", hash: PBKDF2 }, action: "dashboard_user.create" },
      { role: "admin", m: "DELETE", p: () => `/dashboards/dash-main/users/${usr}`, action: "dashboard_user.delete", status: 204 },
      { role: "admin", m: "POST", p: `/dashboards/dash-main/noc-tokens`, b: { label: "l" }, action: "noc_token.create" },
      { role: "admin", m: "DELETE", p: () => `/dashboards/dash-main/noc-tokens/${noc}`, action: "noc_token.revoke", status: 204 },
      { role: "viewer" as never, m: "POST", p: `/dashboards/dash-main/sso`, b: {}, action: "dashboard.sso" },
      { role: "admin", m: "PUT", p: `/sites/hall-b/alerts`, b: { config: cfg, webhooks: [{ format: "slack", url: WEBHOOK_URL }] }, action: "site.alerts" },
      { role: "admin", m: "POST", p: `/sites/hall-b/alerts/test`, b: {}, action: "site.alerts_test" },
      { role: "admin", m: "PUT", p: `/settings/fleet-thresholds`, b: { cpu_high: { pct: 80 } }, action: "settings.fleet_thresholds" },
      { role: "admin", m: "PUT", p: `/settings/platform-webhook`, b: { format: "json", url: "https://hooks.example.com/p" }, action: "settings.platform_webhook" },
      { role: "admin", m: "POST", p: `/settings/platform-webhook/test`, b: {}, action: "settings.platform_webhook_test" },
      { role: "owner", m: "PUT", p: `/integrations/ec`, b: { config: { url: "https://orch.example.com" }, credentials: { token: "tok-1234567890" } }, action: "integration.update" },
      { role: "owner", m: "POST", p: `/integrations/ec/test`, b: {}, action: "integration.test" },
      { role: "owner", m: "PATCH", p: `/settings`, b: { org_name: "N" }, action: "settings.update" },
      { role: "admin", m: "PATCH", p: `/sites/hall-b/release`, b: { version: "0.1.0" }, action: "site.release" },
      { role: "admin", m: "DELETE", p: () => `/components/${dcid}`, action: "component.delete", status: 204 },
      { role: "admin", m: "DELETE", p: `/sites/hall-c`, action: "site.delete", status: 409 }, // refused: still has a host -> no event
    );
    h.handlers.push(() => new Response("ok", { status: 200 }));
    let n = await auditCount();
    for (const s of steps) {
      const path = typeof s.p === "function" ? s.p() : s.p;
      const r = await h.json<Record<string, any>>(s.role, s.m, path, s.b);
      if (s.status === 409) {
        expect(r.status, `${s.m} ${path}`).toBe(409);
        expect(await auditCount(), `${s.action} refused: no event`).toBe(n);
        continue;
      }
      expect(r.status, `${s.m} ${path}: ${JSON.stringify(r.body).slice(0, 200)}`).toBe(s.status ?? (s.m === "POST" && !path.endsWith("/restart") && !path.endsWith("/rotate") && !path.endsWith("/rotate-agent") && !path.endsWith("/test") && !path.endsWith("/sso") ? 201 : s.m === "POST" ? (path.endsWith("restart") || path.endsWith("rotate-agent") ? 202 : 200) : 200));
      expect(await auditCount(), `${s.action}: exactly one event`).toBe(n + 1);
      n++;
      const last = await lastAudit();
      expect(last.action).toBe(s.action);
      expect(last.details_json + last.resource).not.toMatch(/exp[aeidn]_[A-Za-z0-9_-]{8,}|hooks\.|tok-1234567890|pbkdf2_sha256/);
      if (s.action === "component.create" && path.includes(host.host_id)) cid = r.body.component_id;
      if (s.action === "component.create" && path.includes(dashHost.host_id)) dcid = r.body.component_id;
      if (s.action === "dashboard_user.create") usr = r.body.usr_id;
      if (s.action === "noc_token.create") noc = r.body.noc.noc_id;
    }
  });

  it("an agent-confirmed decommission makes the host deletable, with one audit event each", async () => {
    await seedSiteWithRelease("hall-b", "0.1.0");
    const host = await enrolHost("hall-b", "srv");
    await h.json("admin", "POST", `/hosts/${host.host_id}/decommission`, {});
    const r = await call("/api/agent/v1/decommissioned", { method: "POST", headers: { authorization: `Bearer ${host.secret}`, "content-type": "application/json" }, body: "{}" });
    expect(r.status).toBe(204);
    const n = await auditCount();
    expect((await h.json("admin", "DELETE", `/hosts/${host.host_id}`)).status).toBe(204);
    expect(await auditCount()).toBe(n + 1);
    expect((await lastAudit()).action).toBe("host.delete");
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM agent_creds WHERE host_id = ?1").bind(host.host_id).first<{ n: number }>())!.n).toBe(0);
  });
});
