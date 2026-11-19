// 05-manager.md section 15 item 4 (and SR-6): agent authentication and authorization, 304 hot path.
import { beforeEach, describe, expect, it } from "vitest";
import { addComponent, decommissionHost, requestAgentRotation } from "../../src/admin/service";
import { newToken } from "../../src/secrets/tokens";
import { sha256Hex } from "../../src/util/encoding";
import {
  ADMIN_ACTOR, FACTS, FINGERPRINT, auditActions, bearer, call, createSite, enrolHost, env, freshIp, getDesired, json, postStatus,
  resetDb, seedRelease, seedSiteWithRelease, statusReport, type SeededRelease,
} from "../helpers";

let rel: SeededRelease;
beforeEach(async () => {
  await resetDb();
  rel = await seedSiteWithRelease("hall-b", "0.1.0");
});

const PORTS_CFG = { ports: [{ id: "c01", iface: "enp10s0f0", role: "client", vlan: null, dhcp: { hostname: "exp-c01", vendor_class: "exp-probe", client_id: "mac" } }] };

describe("GET desired", () => {
  it("401 without / with wrong / with malformed secret", async () => {
    const h = await enrolHost("hall-b");
    expect((await call("/api/agent/v1/desired")).status).toBe(401);
    expect((await getDesired(newToken("expa"))).status).toBe(401);
    expect((await getDesired("expa_short")).status).toBe(401);
    expect((await call("/api/agent/v1/desired", { headers: { authorization: `Basic ${h.secret}` } })).status).toBe(401);
    expect((await getDesired(h.secret)).status).toBe(200);
  });

  it("returns the document with ETag \"<host_id>:<version>\" and 304 on If-None-Match", async () => {
    const h = await enrolHost("hall-b");
    const r = await getDesired(h.secret);
    expect(r.status).toBe(200);
    const doc = (await r.json()) as Record<string, any>;
    expect(r.headers.get("etag")).toBe(`"${h.host_id}:${doc.version}"`);
    expect(doc.schema).toBe("exp.desired/1");
    expect(doc.host_id).toBe(h.host_id);
    expect(doc.agent.version).toBe("0.1.0");
    expect(doc.agent.artifact).toBe(rel.artifacts["agent/noarch"]!.artifact_id);
    const r304 = await getDesired(h.secret, { "If-None-Match": r.headers.get("etag")! });
    expect(r304.status).toBe(304);
    expect(await r304.text()).toBe("");
    expect(r304.headers.get("etag")).toBe(r.headers.get("etag"));
    // a stale ETag still gets the document
    expect((await getDesired(h.secret, { "If-None-Match": `"${h.host_id}:999"` })).status).toBe(200);
  });

  it("the 304 hot path is exactly ONE database read and no write", async () => {
    const h = await enrolHost("hall-b");
    const etag = (await getDesired(h.secret)).headers.get("etag")!;
    const { app } = await import("../../src/index");
    const prepared: string[] = [];
    const spy = new Proxy(env.DB, {
      get(t, p, rcv) {
        const v = Reflect.get(t, p, rcv);
        if (p === "prepare") return (sql: string) => (prepared.push(sql), t.prepare(sql));
        if (p === "batch" || p === "exec") return (...a: unknown[]) => (prepared.push(`<${String(p)}>`), (v as (...x: unknown[]) => unknown).apply(t, a));
        return typeof v === "function" ? v.bind(t) : v;
      },
    });
    const r = await app.fetch(
      new Request("https://manager.example.test/api/agent/v1/desired", { headers: { ...bearer(h.secret), "If-None-Match": etag, "CF-Connecting-IP": freshIp() } }),
      { ...env, DB: spy },
    );
    expect(r.status).toBe(304);
    expect(prepared).toHaveLength(1);
    expect(prepared[0]).toMatch(/^\s*SELECT/);
  });

  it("creds are decrypted at serve time and stored encrypted", async () => {
    const h = await enrolHost("hall-b");
    const { component_id } = await addComponent(env, ADMIN_ACTOR, h.host_id, { type: "probe", id: "probe-a1", config: PORTS_CFG });
    const doc = (await (await getDesired(h.secret)).json()) as Record<string, any>;
    const probe = doc.components.find((c: any) => c.component_id === component_id);
    expect(probe.creds.ingest_token).toMatch(/^expi_[A-Za-z0-9_-]{43}$/);
    const stored = await env.DB.prepare("SELECT doc_json FROM desired_docs WHERE host_id = ?1").bind(h.host_id).first<{ doc_json: string }>();
    expect(stored!.doc_json).not.toContain(probe.creds.ingest_token);
    expect(stored!.doc_json).toContain("enc2:");
  });
});

describe("agent secret rotation grace", () => {
  it("previous secret works inside the grace and is refused outside it; the current one always works", async () => {
    const h = await enrolHost("hall-b");
    await requestAgentRotation(env, ADMIN_ACTOR, h.host_id);
    const r = await call("/api/agent/v1/rotate", { method: "POST", headers: { ...bearer(h.secret), "content-type": "application/json" }, body: "{}" });
    expect(r.status).toBe(200);
    const b = (await r.json()) as { agent_secret: string; grace_s: number };
    expect(b.grace_s).toBe(600);
    expect(b.agent_secret).not.toBe(h.secret);
    expect((await getDesired(b.agent_secret)).status).toBe(200);
    expect((await getDesired(h.secret)).status).toBe(200); // old one: inside the grace
    await env.DB.prepare("UPDATE agent_creds SET previous_valid_until = '2020-01-01T00:00:00.000Z' WHERE host_id = ?1").bind(h.host_id).run();
    const old = await getDesired(h.secret);
    expect(old.status).toBe(401); // outside the grace
    expect(((await old.json()) as { error: { code: string } }).error.code).toBe("invalid_token");
    expect((await getDesired(b.agent_secret)).status).toBe(200);
  });

  it("rotate is refused unless the desired state carries rotate_agent_secret", async () => {
    const h = await enrolHost("hall-b");
    const r = await call("/api/agent/v1/rotate", { method: "POST", headers: bearer(h.secret), body: "{}" });
    expect(r.status).toBe(409);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe("rotation_not_requested");
    expect((await call("/api/agent/v1/rotate", { method: "POST", headers: bearer(h.secret), body: '{"x":1}' })).status).toBe(400);
  });

  it("the action is consumed: version bumps once, the new document has no rotate action, one audit event", async () => {
    const h = await enrolHost("hall-b");
    const v0 = ((await (await getDesired(h.secret)).json()) as { version: number }).version;
    await requestAgentRotation(env, ADMIN_ACTOR, h.host_id);
    const withAction = (await (await getDesired(h.secret)).json()) as { version: number; actions: Array<{ type: string }> };
    expect(withAction.version).toBe(v0 + 1);
    expect(withAction.actions.map((a) => a.type)).toEqual(["rotate_agent_secret"]);
    const rot = (await (await call("/api/agent/v1/rotate", { method: "POST", headers: bearer(h.secret), body: "{}" })).json()) as { agent_secret: string };
    const after = (await (await getDesired(rot.agent_secret)).json()) as { version: number; actions: unknown[] };
    expect(after.version).toBe(v0 + 2);
    expect(after.actions).toEqual([]);
    expect((await auditActions()).filter((a) => a === "agent.rotate")).toHaveLength(1);
    // a second rotate now has no action
    expect((await call("/api/agent/v1/rotate", { method: "POST", headers: bearer(rot.agent_secret), body: "{}" })).status).toBe(409);
  });
});

describe("auth failure throttling and per-agent rate limit", () => {
  it("repeated auth failures from one IP are throttled with 429", async () => {
    const ip = "198.51.100.200";
    const codes: number[] = [];
    for (let i = 0; i < 13; i++) codes.push((await call("/api/agent/v1/desired", { headers: bearer(newToken("expa")), ip })).status);
    expect(codes.slice(0, 10).every((c) => c === 401)).toBe(true);
    expect(codes.slice(10).every((c) => c === 429)).toBe(true);
    // a valid agent from another IP is unaffected
    const h = await enrolHost("hall-b");
    expect((await getDesired(h.secret)).status).toBe(200);
  });

  it("an agent is limited to 120 requests per minute", async () => {
    const h = await enrolHost("hall-b");
    let limited = 0;
    for (let i = 0; i < 125; i++) if ((await getDesired(h.secret)).status === 429) limited++;
    expect(limited).toBeGreaterThan(0);
  });
});

describe("artifacts (SR-6)", () => {
  it("403 unless referenced by THIS host's current desired state; streams bytes with Content-Length and sha256 ETag", async () => {
    const h = await enrolHost("hall-b");
    const other = await enrolHost("hall-b", "srv-03");
    await addComponent(env, ADMIN_ACTOR, h.host_id, { type: "probe", id: "probe-a1", config: PORTS_CFG });
    const doc = (await (await getDesired(h.secret)).json()) as { components: Array<{ artifact: { id: string; sha256: string } }>; agent: { artifact: string } };
    const probeArt = doc.components[0]!.artifact;
    const r = await call(`/api/agent/v1/artifacts/${probeArt.id}`, { headers: bearer(h.secret) });
    expect(r.status).toBe(200);
    const bytes = new Uint8Array(await r.arrayBuffer());
    expect(await sha256Hex(bytes)).toBe(probeArt.sha256);
    expect(r.headers.get("content-length")).toBe(String(bytes.length));
    expect(r.headers.get("etag")).toBe(`"${probeArt.sha256}"`);
    expect((await call(`/api/agent/v1/artifacts/${doc.agent.artifact}`, { headers: bearer(h.secret) })).status).toBe(200);
    expect((await call(`/api/agent/v1/artifacts/${probeArt.id}`, { headers: { ...bearer(h.secret), "If-None-Match": `"${probeArt.sha256}"` } })).status).toBe(304);
    // not referenced by this host's desired state (a collector artifact of the same release)
    const foreign = rel.artifacts["collector/amd64"]!.artifact_id;
    const f = await call(`/api/agent/v1/artifacts/${foreign}`, { headers: bearer(h.secret) });
    expect(f.status).toBe(403);
    expect(((await f.json()) as { error: { code: string } }).error.code).toBe("forbidden");
    // another host (no probe) cannot fetch it either, even though it is a valid artifact id
    expect((await call(`/api/agent/v1/artifacts/${probeArt.id}`, { headers: bearer(other.secret) })).status).toBe(403);
    // malformed ids and no auth
    expect((await call("/api/agent/v1/artifacts/not-an-id", { headers: bearer(h.secret) })).status).toBe(403);
    expect((await call(`/api/agent/v1/artifacts/${probeArt.id}`)).status).toBe(401);
  });

  it("a superseded release's artifacts stop being downloadable", async () => {
    const h = await enrolHost("hall-b");
    await addComponent(env, ADMIN_ACTOR, h.host_id, { type: "probe", id: "probe-a1", config: PORTS_CFG });
    const old = (await (await getDesired(h.secret)).json()) as { components: Array<{ artifact: { id: string } }> };
    const oldId = old.components[0]!.artifact.id;
    const rel2 = await seedRelease("0.2.0");
    const { setSiteRelease } = await import("../../src/admin/service");
    await setSiteRelease(env, ADMIN_ACTOR, "hall-b", { version: "0.2.0" });
    expect((await call(`/api/agent/v1/artifacts/${oldId}`, { headers: bearer(h.secret) })).status).toBe(403);
    const now = (await (await getDesired(h.secret)).json()) as { components: Array<{ artifact: { id: string } }> };
    expect(now.components[0]!.artifact.id).toBe(rel2.artifacts["probe/noarch"]!.artifact_id);
  });
});

describe("release manifest", () => {
  it("serves the exact stored bytes and the signature; 404 for unknown; 401 without auth", async () => {
    const h = await enrolHost("hall-b");
    const stored = await env.ARTIFACTS.get("releases/0.1.0/manifest.json");
    const expected = new Uint8Array(await stored!.arrayBuffer());
    const m = await call("/api/agent/v1/releases/0.1.0/manifest", { headers: bearer(h.secret) });
    expect(m.status).toBe(200);
    expect(new Uint8Array(await m.arrayBuffer())).toEqual(expected);
    const s = await call("/api/agent/v1/releases/0.1.0/manifest.sig", { headers: bearer(h.secret) });
    expect(s.status).toBe(200);
    expect(await s.text()).toMatch(/^[A-Za-z0-9+/]{86}==$/);
    expect((await call("/api/agent/v1/releases/9.9.9/manifest", { headers: bearer(h.secret) })).status).toBe(404);
    expect((await call("/api/agent/v1/releases/..%2f..%2fx/manifest", { headers: bearer(h.secret) })).status).toBe(404);
    expect((await call("/api/agent/v1/releases/0.1.0/manifest")).status).toBe(401);
  });
});

describe("POST status", () => {
  it("stores latest + history (bounded to 100), updates the host and merges component facts", async () => {
    const h = await enrolHost("hall-b");
    const { component_id } = await addComponent(env, ADMIN_ACTOR, h.host_id, { type: "collector", id: "col-hallb", config: {} });
    const report = statusReport({
      components: [
        { type: "collector", id: "col-hallb", version: "0.1.0", state: "running", health: "ok", detail: "fine", facts: { tls_fingerprint_sha256: FINGERPRINT, listen: "10.32.98.25:8443", secret_thing: "x" } },
        { type: "probe", id: "not-configured", state: "running", health: "ok" },
      ],
    });
    const r = await postStatus(h.secret, report);
    expect(r.status).toBe(204);
    const latest = await env.DB.prepare("SELECT report_json FROM status_latest WHERE host_id = ?1").bind(h.host_id).first<{ report_json: string }>();
    expect(JSON.parse(latest!.report_json).agent.version).toBe("0.1.0");
    const host = await env.DB.prepare("SELECT last_seen, agent_version, applied_version FROM hosts WHERE host_id = ?1").bind(h.host_id).first<Record<string, unknown>>();
    expect(host!.last_seen).toBeTruthy();
    expect(host!.agent_version).toBe("0.1.0");
    expect(host!.applied_version).toBe(1);
    const comp = await env.DB.prepare("SELECT facts_json FROM components WHERE component_id = ?1").bind(component_id).first<{ facts_json: string }>();
    const f = JSON.parse(comp!.facts_json);
    expect(f.health).toBe("ok");
    expect(f.facts).toEqual({ tls_fingerprint_sha256: FINGERPRINT, listen: "10.32.98.25:8443" }); // whitelisted only
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM components").first<{ n: number }>())?.n).toBe(1); // never created from a report
    for (let i = 0; i < 104; i++) expect((await postStatus(h.secret, report)).status).toBe(204 as number);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM status_history WHERE host_id = ?1").bind(h.host_id).first<{ n: number }>())?.n).toBe(100);
  }, 30000);

  it("validates: bad schema -> 400 with paths, >256 KiB -> 413, not JSON -> 400, no auth -> 401", async () => {
    const h = await enrolHost("hall-b");
    const bad = await postStatus(h.secret, statusReport({ facts: { hostname: "x", arch: "mips" } }));
    expect(bad.status).toBe(400);
    const body = (await bad.json()) as { error: { code: string; details: { errors: Array<{ path: string }> } } };
    expect(body.error.code).toBe("invalid_request");
    expect(body.error.details.errors.some((e) => e.path.includes("arch"))).toBe(true);
    expect((await postStatus(h.secret, "{nope")).status).toBe(400);
    expect((await postStatus(h.secret, statusReport({ schema: "exp.status/2" }))).status).toBe(400);
    const huge = JSON.stringify(statusReport({ events: [{ ts: "2026-11-18T20:00:00.000Z", level: "info", msg: "x".repeat(1000) }] })) + " ".repeat(300 * 1024);
    expect((await postStatus(h.secret, huge)).status).toBe(413);
    expect((await call("/api/agent/v1/status", { method: "POST", body: "{}" })).status).toBe(401);
  });

  it("a report brings a stale/offline host back to enrolled", async () => {
    const h = await enrolHost("hall-b");
    await env.DB.prepare("UPDATE hosts SET state = 'offline' WHERE host_id = ?1").bind(h.host_id).run();
    expect((await postStatus(h.secret, statusReport())).status).toBe(204);
    expect((await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(h.host_id).first<{ state: string }>())?.state).toBe("enrolled");
  });

  it("wiring facts recompile probes: the probe gets the collector URL and pin once the collector reports", async () => {
    const col = await enrolHost("hall-b", "col-host");
    const prb = await enrolHost("hall-b", "probe-host");
    await addComponent(env, ADMIN_ACTOR, col.host_id, { type: "collector", id: "col-hallb", config: {} });
    await addComponent(env, ADMIN_ACTOR, prb.host_id, { type: "probe", id: "probe-a1", config: PORTS_CFG });
    const before = (await (await getDesired(prb.secret)).json()) as { version: number; components: Array<{ config: { collector: unknown } }> };
    expect(before.components[0]!.config.collector).toBeNull(); // spools until the collector reports listen + pin
    await postStatus(col.secret, statusReport({ components: [{ type: "collector", id: "col-hallb", state: "running", health: "ok", facts: { listen: "10.32.98.25:8443" } }] }));
    const half = (await (await getDesired(prb.secret)).json()) as { version: number; components: Array<{ config: { collector: unknown } }> };
    expect(half.components[0]!.config.collector).toBeNull(); // listen alone is not enough
    expect(half.version).toBe(before.version);
    await postStatus(col.secret, statusReport({ components: [{ type: "collector", id: "col-hallb", state: "running", health: "ok", facts: { listen: "10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT } }] }));
    const after = (await (await getDesired(prb.secret)).json()) as { version: number; components: Array<{ config: { collector: Record<string, unknown> } }> };
    expect(after.version).toBe(before.version + 1);
    expect(after.components[0]!.config.collector).toEqual({ url: "https://10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT, fallback: [] });
    // an unchanged report causes no churn
    await postStatus(col.secret, statusReport({ components: [{ type: "collector", id: "col-hallb", state: "running", health: "ok", facts: { listen: "10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT } }] }));
    expect(((await (await getDesired(prb.secret)).json()) as { version: number }).version).toBe(after.version);
  });
});

describe("decommission", () => {
  it("only valid while the desired state carries decommission: true; then credentials are revoked", async () => {
    const h = await enrolHost("hall-b");
    const refused = await call("/api/agent/v1/decommissioned", { method: "POST", headers: bearer(h.secret), body: "{}" });
    expect(refused.status).toBe(409);
    expect(((await refused.json()) as { error: { code: string } }).error.code).toBe("decommission_not_requested");
    await decommissionHost(env, ADMIN_ACTOR, h.host_id);
    const doc = (await (await getDesired(h.secret)).json()) as { decommission: boolean; components: unknown[] };
    expect(doc.decommission).toBe(true);
    expect(doc.components).toEqual([]);
    expect((await call("/api/agent/v1/decommissioned", { method: "POST", headers: bearer(h.secret), body: "{}" })).status).toBe(204);
    expect((await getDesired(h.secret)).status).toBe(401);
    const row = await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(h.host_id).first<{ state: string }>();
    expect(row?.state).toBe("removed");
    const rev = await env.DB.prepare("SELECT revoked_at FROM agent_creds WHERE host_id = ?1").bind(h.host_id).first<{ revoked_at: string }>();
    expect(rev?.revoked_at).toBeTruthy();
    const acts = await auditActions();
    expect(acts.filter((a) => a === "agent.decommissioned")).toHaveLength(1);
    expect(acts.filter((a) => a === "host.decommission")).toHaveLength(1);
  });
});

describe("misc", () => {
  it("unknown agent endpoints are enveloped 404/401 and /healthz is public", async () => {
    const h = await enrolHost("hall-b");
    expect((await call("/api/agent/v1/nope", { headers: bearer(h.secret) })).status).toBe(404);
    expect((await call("/healthz")).status).toBe(200);
    void createSite;
    void json;
    void FACTS;
  });
});
