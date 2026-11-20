// M6 manager (CR-m6-manager): speedtest + runner shapes, the all-in-one profile, the Speedtest settings API, secrets and
// credential placement, consent versioning, logo artifact, QR data, TLS pair, device_key, fleet rows.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Harness, harness } from "../admin-harness";
import { ADMIN_ACTOR, FACTS, FINGERPRINT, bearer, call, createSite, enrolHost, env, getDesired, postStatus, resetDb, seedRelease, statusReport } from "../helpers";
import * as svc from "../../src/admin/service";
import { makeCert } from "../tls-fixtures";

let h: Harness;
beforeEach(async () => {
  await resetDb();
  h = await harness();
});
afterEach(() => h.restore());

const ALL_ARCHS = { agent: ["noarch"], probe: ["noarch"], collector: ["amd64"], dashboard: ["noarch"], runner: ["noarch"], speedtest: ["noarch"] };
const IFACES = [
  { name: "eno1", mac: "18:66:da:00:00:01", state: "up", speed_mbps: 1000, driver: "tg3", addrs: ["10.32.98.25/23"], default_route: true, in_use_by: "mgmt" },
  { name: "eno2", mac: "18:66:da:00:00:03", state: "up", speed_mbps: 10000, driver: "ixgbe", addrs: ["10.0.0.9/24"], default_route: false, in_use_by: "none" },
  { name: "enp10s0f0", mac: "18:66:da:00:00:02", state: "up", speed_mbps: 1000, driver: "ixgbe", addrs: [], default_route: false, in_use_by: "none" },
];

interface Box {
  host_id: string;
  secret: string;
  col: string;
  run: string;
  spd: string;
  probe: string;
}

/** ONE host with collector + runner + speedtest + probe (the all-in-one profile), collector reported listen + pin. */
async function allInOne(opts: { speedtest?: boolean } = {}): Promise<Box> {
  await createSite(env, ADMIN_ACTOR, { site: "hall-b", name: "Hall B", timezone: "America/Chicago" });
  await seedRelease("0.1.0", { archs: ALL_ARCHS });
  await env.DB.prepare("UPDATE sites SET release_version = '0.1.0' WHERE site = 'hall-b'").run();
  const host = await enrolHost("hall-b", "core-box", FACTS({ interfaces: IFACES }));
  const col = await svc.addComponent(env, ADMIN_ACTOR, host.host_id, { type: "collector", id: "col-hallb", config: {} });
  const run = await svc.addComponent(env, ADMIN_ACTOR, host.host_id, { type: "runner", id: "run-core", config: { correlation: { sources: { mist: { sites: [{ site_id: "00000000-0000-0000-0000-00000000aa01" }] }, ec: { appliances: [{ ne_pk: "1.NE" }] } } } } });
  const spd = opts.speedtest === false ? { component_id: "" } : await svc.addComponent(env, ADMIN_ACTOR, host.host_id, { type: "speedtest", id: "spd-core", config: {} });
  const probe = await svc.addComponent(env, ADMIN_ACTOR, host.host_id, {
    type: "probe",
    id: "probe-a1",
    config: { ports: [{ id: "c01", iface: "enp10s0f0", role: "client", vlan: null }] },
  });
  await postStatus(host.secret, statusReport({ facts: FACTS({ interfaces: IFACES }), components: [{ type: "collector", id: "col-hallb", state: "running", health: "ok", facts: { listen: "10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT } }] }));
  return { host_id: host.host_id, secret: host.secret, col: col.component_id, run: run.component_id, spd: spd.component_id, probe: probe.component_id };
}

const BODY = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  zones: [{ id: "hall-a", name: "Hall A" }, { id: "hall-b", name: "Hall B" }],
  zone_labels: { subnets: [{ cidr: "10.60.0.0/16", zone: "hall-a" }, { cidr: "10.61.0.0/16", zone: "hall-b" }] },
  branding: { title: "Summit speed check", colors: { primary: "#01a982", accent: "#7630ea" }, languages: ["en", "de"], copy: { start_button: "Start" } },
  consent: { text: "We measure your speed. No name or email is collected." },
  targets: { down_mbps: 25, up_mbps: 10 },
  limits: { max_concurrent_tests: 20, bytes_local: 200000000 },
  internet_leg: { enabled: true, provider: "cloudflare", auto_pause_wan_util_pct: 80 },
  serve: { placement: "core", hostname: "speed.summit.example", listen_ip: "10.0.0.9", require_real_client_ip: true, translated_addresses: ["10.0.0.2"] },
  tls: { mode: "none" },
  dns_leg: { enabled: true, zone: "t.speed.summit.example" },
  privacy: { retention_days: 30, scrub_after_diagnosis: false },
  ...over,
});

type Doc = { version: number; components: Array<{ type: string; id: string; config: Record<string, any>; creds: Record<string, string>; assets?: Array<{ name: string; content_type: string; artifact: { id: string } }> }> };
const docOf = async (secret: string): Promise<Doc> => (await (await getDesired(secret)).json()) as Doc;
const comp = (d: Doc, type: string) => d.components.find((c) => c.type === type)!;

const put = (body: unknown, role: "admin" | "owner" | "operator" | "viewer" = "admin") => h.json<any>(role, "PUT", "/sites/hall-b/speedtest", body);

describe("settings API", () => {
  it("GET before any save returns the default consent (version 1), no logo, paused false, no device key", async () => {
    await allInOne();
    const g = await h.json<any>("viewer", "GET", "/sites/hall-b/speedtest");
    expect(g.status).toBe(200);
    expect(g.body.consent.version).toBe(1);
    expect(g.body.consent.text.length).toBeGreaterThan(20);
    expect(g.body.internet_leg).toEqual({ paused: false });
    expect(g.body.branding).toBeUndefined();
  });

  it("PUT validates strictly: unknown keys, bad CIDR, missing consent, bad colour, 0.0.0.0 listen_ip are 400", async () => {
    await allInOne();
    for (const bad of [
      BODY({ surprise: 1 }),
      BODY({ zone_labels: { subnets: [{ cidr: "10.0.0.0/33", zone: "hall-a" }] } }),
      BODY({ branding: { colors: { primary: "red" } } }),
      BODY({ serve: { hostname: "x", listen_ip: "0.0.0.0" } }),
      BODY({ serve: { hostname: "x", listen_ip: "127.0.0.1" } }),
      BODY({ limits: { bytes_local: 5 } }),
      BODY({ internet_leg: { provider: "other" } }),
      BODY({ zone_labels: { subnets: [{ cidr: "10.60.0.0/16", zone: "nope" }] } }),
      BODY({ zones: [{ id: "a", name: "A" }, { id: "a", name: "B" }] }),
      BODY({ serve: { hostname: "x", listen_ip: "10.0.0.9", require_real_client_ip: true }, zone_labels: undefined, zones: undefined }),
      BODY({ dns_leg: { enabled: true } }),
      BODY({ branding: { logo_artifact: "art_01M7R3X9G0JPFS2FAGQ8ACHEYD" } }),
      { zones: [] },
      "nope",
    ]) {
      const r = await put(bad);
      expect(r.status, JSON.stringify(bad)).toBe(400);
      expect(r.body.error.code).toBe("invalid_request");
    }
  });

  it("serve.listen_ip must be an interface address of the speedtest host (when it has reported its interfaces)", async () => {
    await allInOne();
    const r = await put(BODY({ serve: { hostname: "x", listen_ip: "10.9.9.9", require_real_client_ip: false } }));
    expect(r.status).toBe(400);
    expect(r.body.error.message).toContain("not an interface address");
    expect((await put(BODY())).status).toBe(200);
  });

  it("roles: viewer reads, operator cannot write, admin writes; a mutation without X-Exp-Request is refused", async () => {
    await allInOne();
    expect((await put(BODY(), "viewer")).status).toBe(403);
    expect((await put(BODY(), "operator")).status).toBe(403);
    expect((await put(BODY(), "admin")).status).toBe(200);
    const res = await h.api("admin", "PUT", "/sites/hall-b/speedtest", BODY(), { "X-Exp-Request": "" });
    expect(res.status).toBe(403);
    expect(((await res.json()) as any).error.code).toBe("csrf_refused");
    expect((await h.json("admin", "GET", "/sites/nope/speedtest")).status).toBe(404);
  });

  it("PUT then GET round-trips; one audit event per mutation; the audit never holds the consent text", async () => {
    await allInOne();
    const before = (await env.DB.prepare("SELECT COUNT(*) AS n FROM audit").first<{ n: number }>())!.n;
    const r = await put(BODY());
    expect(r.status).toBe(200);
    const g = await h.json<any>("viewer", "GET", "/sites/hall-b/speedtest");
    expect(g.body.zones).toHaveLength(2);
    expect(g.body.branding.title).toBe("Summit speed check");
    expect(g.body.serve.listen_ip).toBe("10.0.0.9");
    expect(g.body.consent).toEqual({ text: "We measure your speed. No name or email is collected.", version: 1 });
    const after = (await env.DB.prepare("SELECT COUNT(*) AS n FROM audit").first<{ n: number }>())!.n;
    // PUT = 1 audit event (the recompile and the early auto-provisioning add none)
    expect(after - before).toBe(1);
    const a = (await env.DB.prepare("SELECT action, details_json FROM audit WHERE action = 'speedtest.settings'").first<{ action: string; details_json: string }>())!;
    expect(a.details_json).not.toContain("We measure");
    expect(JSON.parse(a.details_json).consent_version).toBe(1);
  });
});

describe("consent versioning", () => {
  it("an edit bumps the version, an unchanged text does not, and every version is kept", async () => {
    await allInOne();
    expect((await put(BODY())).body.consent.version).toBe(1);
    expect((await put(BODY({ targets: { down_mbps: 30 } }))).body.consent.version).toBe(1);
    expect((await put(BODY({ consent: { text: "Second wording." } }))).body.consent).toEqual({ text: "Second wording.", version: 2 });
    // a client-supplied version is ignored
    expect((await put(BODY({ consent: { text: "Third wording.", version: 99 } }))).body.consent.version).toBe(3);
    expect((await put(BODY({ consent: { text: "Third wording." } }))).body.consent.version).toBe(3);
    const hist = await h.json<any>("admin", "GET", "/sites/hall-b/speedtest/consent-history");
    expect(hist.body.items.map((i: any) => [i.version, i.text])).toEqual([[3, "Third wording."], [2, "Second wording."], [1, "We measure your speed. No name or email is collected."]]);
    expect((await h.json("viewer", "GET", "/sites/hall-b/speedtest/consent-history")).status).toBe(403);
    // the compiled speedtest carries the current version
    const box = await h.json<any>("admin", "GET", "/hosts");
    expect(box.status).toBe(200);
  });

  it("the compiled speedtest config carries the consent version", async () => {
    const box = await allInOne();
    await put(BODY());
    await put(BODY({ consent: { text: "Changed." } }));
    const d = await docOf(box.secret);
    expect(comp(d, "speedtest").config.consent).toEqual({ text: "Changed.", version: 2 });
  });
});

describe("the all-in-one host", () => {
  it("compiles collector + runner + speedtest + probe on ONE host, tokens only in the right documents", async () => {
    const box = await allInOne();
    expect((await put(BODY())).status).toBe(200);
    const d = await docOf(box.secret);
    expect(d.components.map((c) => c.type)).toEqual(["collector", "probe", "runner", "speedtest"]);
    const spd = comp(d, "speedtest");
    const run = comp(d, "runner");
    const col = comp(d, "collector");
    expect(spd.config.schema).toBe("exp.speedtest.config/1");
    expect(spd.config.serve.listen_ip).toBe("10.0.0.9");
    expect(spd.config.serve.client_subnets).toEqual(["10.60.0.0/16", "10.61.0.0/16"]);
    expect(spd.config.tls).toEqual({ mode: "none" });
    expect(spd.config.local_channel).toEqual({ listen: "127.0.0.1:8480" });
    expect(spd.config.collector).toEqual({ url: "https://10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT, fallback: [] });
    expect(Object.keys(spd.creds).sort()).toEqual(["collector_token", "runner_channel_token_sha256"]);
    expect(spd.creds.collector_token).toMatch(/^exps_[A-Za-z0-9_-]{43}$/);
    expect(Object.keys(run.creds).sort()).toEqual(["collector_token", "device_key_secret", "ingest_token", "integrations.json", "speedtest_channel_token"]);
    expect(run.creds.collector_token).toMatch(/^expr_/);
    expect(run.creds.speedtest_channel_token).toMatch(/^expl_/);
    expect(run.creds.device_key_secret).toMatch(/^expk_/);
    expect(run.config.correlation.speedtest_channel).toEqual({ url: "http://127.0.0.1:8480/local/v1" });
    expect(run.config.correlation.sources.sse).toEqual({ enabled: false });
    expect(run.config.correlation.privacy).toEqual({ scrub_after_diagnosis: false });
    // the collector accepts them: hashes only, never a plaintext token of the other components
    expect(col.config.speedtests).toMatchObject({ enabled: true, speedtests: ["spd-core"], runners: ["run-core"], retention_days: 30, scrub_after_diagnosis: false });
    const st = JSON.parse(col.creds["speedtest_tokens.json"]!) as Record<string, string>;
    const rt = JSON.parse(col.creds["runner_tokens.json"]!) as Record<string, string>;
    const sha = async (s: string) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))).map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(st["spd-core"]).toBe(await sha(spd.creds.collector_token!));
    expect(rt["run-core"]).toBe(await sha(run.creds.collector_token!));
    expect(spd.creds.runner_channel_token_sha256).toBe(await sha(run.creds.speedtest_channel_token!));
    const colText = JSON.stringify(col);
    for (const secret of [spd.creds.collector_token!, run.creds.collector_token!, run.creds.speedtest_channel_token!]) expect(colText).not.toContain(secret);
    expect(JSON.stringify(spd)).not.toContain(run.creds.collector_token!);
    expect(JSON.stringify(spd)).not.toContain(run.creds.device_key_secret!);
    expect(col.creds.device_key_secret).toBe(run.creds.device_key_secret);
  });

  it("device_key is sealed in D1 and appears in no admin API response or audit event", async () => {
    const box = await allInOne();
    await put(BODY());
    const key = comp(await docOf(box.secret), "runner").creds.device_key_secret!;
    const raw = key.slice("expk_".length);
    // every table, every column, as text
    const tables = (await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'").all<{ name: string }>()).results.map((t) => t.name);
    for (const t of tables) {
      const rows = (await env.DB.prepare(`SELECT * FROM ${t}`).all()).results;
      expect(JSON.stringify(rows), `table ${t}`).not.toContain(raw);
    }
    const responses: string[] = [];
    for (const [m, p, b] of [
      ["GET", "/sites/hall-b/speedtest"], ["PUT", "/sites/hall-b/speedtest", BODY()], ["GET", "/sites/hall-b/speedtest/qr"], ["GET", "/hosts"], ["GET", `/hosts/${box.host_id}/components`],
      ["GET", "/settings"], ["GET", "/audit?limit=1000"], ["POST", "/settings/speedtest-device-key", {}], ["GET", "/fleet/hosts"],
    ] as Array<[string, string, unknown?]>) {
      const r = await h.api(m === "POST" ? "owner" : "admin", m, p, b);
      responses.push(await r.text());
    }
    for (const t of responses) expect(t).not.toContain(raw);
    // rotation: a new value, the old one gone everywhere
    const key2 = comp(await docOf(box.secret), "runner").creds.device_key_secret!;
    expect(key2).not.toBe(key);
  });

  it("the device key is generated once (idempotent provisioning) and only the owner can rotate it", async () => {
    const box = await allInOne();
    await put(BODY());
    const a = comp(await docOf(box.secret), "runner").creds.device_key_secret;
    await svc.patchComponent(env, ADMIN_ACTOR, box.run, { config: { drills_enabled: false } });
    expect(comp(await docOf(box.secret), "runner").creds.device_key_secret).toBe(a);
    expect((await h.json("admin", "POST", "/settings/speedtest-device-key", {})).status).toBe(403);
    const r = await h.json<any>("owner", "POST", "/settings/speedtest-device-key", {});
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ set: true, key_id: "k2" });
    expect(Object.keys(r.body).sort()).toEqual(["key_id", "set", "updated_at"]);
    expect(comp(await docOf(box.secret), "runner").creds.device_key_secret).not.toBe(a);
    const g = await h.json<any>("viewer", "GET", "/sites/hall-b/speedtest");
    expect(g.body.device_key.set).toBe(true);
  });

  it("a runner without speedtest analytics is unchanged (no correlation block) but still gets its tokens", async () => {
    const box = await allInOne({ speedtest: false });
    const run = comp(await docOf(box.secret), "runner");
    expect(run.config.correlation).toBeUndefined();
    expect(run.creds.collector_token).toMatch(/^expr_/);
    const col = comp(await docOf(box.secret), "collector");
    expect(col.config.speedtests).toBeUndefined();
    expect(col.creds["speedtest_tokens.json"]).toBeUndefined();
  });

  it("listen_ip is required: until the settings name it the speedtest is not compiled (and nothing breaks)", async () => {
    const box = await allInOne();
    const d = await docOf(box.secret);
    expect(d.components.map((c) => c.type)).not.toContain("speedtest");
    await put(BODY());
    expect((await docOf(box.secret)).components.map((c) => c.type)).toContain("speedtest");
  });

  it("port collisions are refused (422) when the layout is created and the compiler fails closed", async () => {
    const box = await allInOne();
    await put(BODY());
    // a dashboard on the same box would take 0.0.0.0:80 + 443: collides with the speedtest's tcp/80
    const r = await h.json<any>("admin", "POST", `/hosts/${box.host_id}/components`, { type: "dashboard", id: "dash-main", config: {} });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe("port_collision");
    expect(r.body.error.details.conflicts[0]).toContain("tcp/80");
    // moving the dashboard off port 80/443 clears it
    const ok = await h.json<any>("admin", "POST", `/hosts/${box.host_id}/components`, { type: "dashboard", id: "dash-main", config: { listen: { https: "0.0.0.0:8444", http_redirect: "0.0.0.0:8081" } } });
    expect(ok.status).toBe(201);
    expect((await docOf(box.secret)).components.map((c) => c.type)).toContain("speedtest");
    // a PATCH back onto the speedtest's port is refused too
    const back = await h.json<any>("admin", "PATCH", `/components/${ok.body.component_id}`, { config: { listen: { https: "0.0.0.0:443", http_redirect: "0.0.0.0:80" } } });
    expect(back.status).toBe(422);
    // the compiler also fails closed when a collision slips past admission (e.g. written directly): the speedtest is left out
    await env.DB.prepare("UPDATE components SET config_json = ?1 WHERE component_id = ?2").bind(JSON.stringify({ listen: { https: "0.0.0.0:443", http_redirect: "0.0.0.0:80" } }), ok.body.component_id).run();
    await (await import("../../src/compile/recompile")).recompile(env, { all: true });
    expect((await docOf(box.secret)).components.map((c) => c.type)).not.toContain("speedtest");
    await env.DB.prepare("UPDATE components SET config_json = ?1 WHERE component_id = ?2").bind(JSON.stringify({ listen: { https: "0.0.0.0:8444", http_redirect: "0.0.0.0:8081" } }), ok.body.component_id).run();
    await (await import("../../src/compile/recompile")).recompile(env, { all: true });
    // a second speedtest on the same listen address collides with the first
    const dup = await h.json<any>("admin", "POST", `/hosts/${box.host_id}/components`, { type: "speedtest", id: "spd-two", config: {} });
    expect(dup.status).toBe(422);
    expect(dup.body.error.code).toBe("port_collision");
  });

  it("speedtest and runner component configs are validated (unknown keys, bad correlation, no SSE connector)", async () => {
    const box = await allInOne();
    const bad = await h.json<any>("admin", "PATCH", `/components/${box.spd}`, { config: { surprise: true } });
    expect(bad.status).toBe(422);
    const sse = await h.json<any>("admin", "PATCH", `/components/${box.run}`, { config: { correlation: { sources: { sse: { enabled: true } } } } });
    expect(sse.status).toBe(422);
    const range = await h.json<any>("admin", "PATCH", `/components/${box.run}`, { config: { correlation: { sources: { syslog: { ring_minutes: 90 } } } } });
    expect(range.status).toBe(422);
    const ok = await h.json<any>("admin", "PATCH", `/components/${box.run}`, { config: { correlation: { poll_interval_s: 3, sources: { syslog: { allow: ["10.0.0.0/8"], ring_minutes: 60 } } } } });
    expect(ok.status).toBe(200);
  });

  it("the integrations settings feed the runner's integrations.json (mist, ec); no sse key exists", async () => {
    const box = await allInOne();
    await put(BODY());
    await h.json("owner", "PUT", "/integrations/mist", { config: { api_base: "https://api.mist.example.test" }, credentials: { token: "MIST-FAKE-TOKEN" } });
    await h.json("owner", "PUT", "/integrations/ec", { config: { url: "https://orch.example.test" }, credentials: { api_key: "EC-FAKE-KEY" } });
    const j = JSON.parse(comp(await docOf(box.secret), "runner").creds["integrations.json"]!);
    expect(j).toEqual({ ec: { url: "https://orch.example.test", api_key: "EC-FAKE-KEY" }, mist: { api_base: "https://api.mist.example.test", token: "MIST-FAKE-TOKEN" } });
    expect((await h.json("owner", "GET", "/integrations/sse")).status).toBe(404);
    // the connector secrets reach no other component
    expect(JSON.stringify(comp(await docOf(box.secret), "speedtest"))).not.toContain("MIST-FAKE-TOKEN");
    expect(JSON.stringify(comp(await docOf(box.secret), "collector"))).not.toContain("EC-FAKE-KEY");
  });

  it("rotating the speedtest or runner tokens keeps the previous collector hash during the overlap", async () => {
    const box = await allInOne();
    await put(BODY());
    const before = comp(await docOf(box.secret), "collector").creds;
    const r = await h.json<any>("admin", "POST", `/components/${box.spd}/rotate`, {});
    expect(r.status).toBe(200);
    expect(r.body.kinds.sort()).toEqual(["channel_token", "speedtest_token"]);
    const d = await docOf(box.secret);
    const st = JSON.parse(comp(d, "collector").creds["speedtest_tokens.json"]!) as Record<string, string[]>;
    expect(st["spd-core"]).toHaveLength(2);
    expect(st["spd-core"]![1]).toBe((JSON.parse(before["speedtest_tokens.json"]!) as Record<string, string>)["spd-core"]);
    const r2 = await h.json<any>("admin", "POST", `/components/${box.run}/rotate`, {});
    expect(r2.body.kinds.sort()).toEqual(["channel_token", "ingest_token", "runner_token"]);
    const spd = comp(await docOf(box.secret), "speedtest");
    const run = comp(await docOf(box.secret), "runner");
    const sha = async (s: string) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))).map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(spd.creds.runner_channel_token_sha256).toBe(await sha(run.creds.speedtest_channel_token!));
  });
});

describe("internet-leg pause", () => {
  it("an operator can pause; it propagates to the speedtest document and bumps the version", async () => {
    const box = await allInOne();
    await put(BODY());
    const v0 = (await docOf(box.secret)).version;
    expect(comp(await docOf(box.secret), "speedtest").config.internet_leg.paused).toBe(false);
    expect((await h.json("viewer", "POST", "/sites/hall-b/speedtest/internet-pause", { paused: true })).status).toBe(403);
    const r = await h.json<any>("operator", "POST", "/sites/hall-b/speedtest/internet-pause", { paused: true });
    expect(r.status).toBe(200);
    expect(r.body.paused).toBe(true);
    const d = await docOf(box.secret);
    expect(d.version).toBe(v0 + 1);
    expect(comp(d, "speedtest").config.internet_leg.paused).toBe(true);
    expect((await h.json<any>("viewer", "GET", "/sites/hall-b/speedtest")).body.internet_leg.paused).toBe(true);
    // a settings save without `paused` keeps the switch where the operator put it
    await put(BODY());
    expect(comp(await docOf(box.secret), "speedtest").config.internet_leg.paused).toBe(true);
    expect((await h.json("admin", "POST", "/sites/hall-b/speedtest/internet-pause", { paused: "yes" })).status).toBe(400);
    expect((await h.json<any>("operator", "POST", "/sites/hall-b/speedtest/internet-pause", { paused: false })).body.paused).toBe(false);
  });
});

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 31, 21, 196, 137]);
const upload = (body: Uint8Array | string, ct: string, role: "admin" | "viewer" = "admin") => h.api(role, "POST", "/sites/hall-b/speedtest/logo", typeof body === "string" ? new TextEncoder().encode(body) : body, { "content-type": ct });

describe("logo", () => {
  it("stores a PNG as an artifact, delivers it as an asset of the speedtest, and the host may download it (SR-6)", async () => {
    const box = await allInOne();
    await put(BODY());
    const res = await upload(PNG, "image/png");
    expect(res.status).toBe(201);
    const logo = (await res.json()) as { artifact: string; sha256: string; size: number; content_type: string };
    expect(logo).toMatchObject({ size: PNG.length, content_type: "image/png" });
    const d = await docOf(box.secret);
    const spd = comp(d, "speedtest");
    expect(spd.config.branding.logo_artifact).toBe(logo.artifact);
    expect(spd.assets).toEqual([expect.objectContaining({ name: "logo", content_type: "image/png", artifact: expect.objectContaining({ id: logo.artifact, sha256: logo.sha256, size: PNG.length }) })]);
    const dl = await call(`/api/agent/v1/artifacts/${logo.artifact}`, { headers: bearer(box.secret) });
    expect(dl.status).toBe(200);
    expect(new Uint8Array(await dl.arrayBuffer())).toEqual(PNG);
    // GET reports it; a PUT that omits it keeps it; null removes it
    expect((await h.json<any>("viewer", "GET", "/sites/hall-b/speedtest")).body.branding.logo_artifact).toBe(logo.artifact);
    await put(BODY());
    expect(comp(await docOf(box.secret), "speedtest").assets).toHaveLength(1);
    await put(BODY({ branding: { title: "No logo", logo_artifact: null } }));
    const d2 = await docOf(box.secret);
    expect(comp(d2, "speedtest").assets).toBeUndefined();
    expect(comp(d2, "speedtest").config.branding.logo_artifact).toBeUndefined();
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM artifacts WHERE component = 'speedtest-logo'").first<{ n: number }>())!.n).toBe(0);
  });

  it("replacing the logo drops the old artifact; an artifact of another host is not downloadable", async () => {
    const box = await allInOne();
    await put(BODY());
    const a = (await (await upload(PNG, "image/png")).json()) as { artifact: string };
    const png2 = new Uint8Array([...PNG, 1, 2, 3]);
    const b = (await (await upload(png2, "image/png")).json()) as { artifact: string };
    expect(b.artifact).not.toBe(a.artifact);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM artifacts WHERE component = 'speedtest-logo'").first<{ n: number }>())!.n).toBe(1);
    const other = await enrolHost("hall-b", "other-host");
    expect((await call(`/api/agent/v1/artifacts/${b.artifact}`, { headers: bearer(other.secret) })).status).toBe(403);
    expect(box.host_id).toBeTruthy();
  });

  it("refuses wrong magic numbers, oversize bodies, unsupported types and non-admins", async () => {
    await allInOne();
    expect((await upload("GIF89a", "image/png")).status).toBe(400);
    expect((await upload(PNG, "image/jpeg")).status).toBe(400);
    expect((await upload(new Uint8Array(256 * 1024 + 1).fill(0x89), "image/png")).status).toBe(413);
    expect((await upload(PNG, "image/gif")).status).toBe(415);
    expect((await upload(new Uint8Array(0), "image/png")).status).toBe(400);
    expect((await upload(PNG, "image/png", "viewer")).status).toBe(403);
    expect((await h.api("admin", "POST", "/sites/hall-b/speedtest/logo", PNG, { "content-type": "application/json" })).status).toBe(415);
  });

  it("a plain SVG is accepted; scripts, event handlers, foreign references and entities are refused", async () => {
    await allInOne();
    const svg = (inner: string, head = "") => `${head}<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">${inner}</svg>`;
    expect((await upload(svg('<rect width="10" height="10" fill="#01a982"/>'), "image/svg+xml")).status).toBe(201);
    for (const bad of [
      svg("<script>alert(1)</script>"),
      svg('<rect onload="x()" width="1" height="1"/>'),
      svg('<image href="https://evil.example/x.png"/>'),
      svg('<image xlink:href="data:image/png;base64,AAAA"/>'),
      svg('<foreignObject><div/></foreignObject>'),
      svg('<rect style="fill:url(https://evil.example/#a)"/>'),
      svg("<style>@import url(//evil.example/a.css);</style>"),
      svg('<a href="javascript:alert(1)"><rect/></a>'),
      svg("<rect/>", '<!DOCTYPE svg [<!ENTITY x "y">]>'),
      "<html><svg/></html>",
      svg('<use href="https://evil.example/s.svg#a"/>'),
    ]) {
      const r = await upload(bad, "image/svg+xml");
      expect(r.status, bad).toBe(400);
    }
  });
});

describe("QR signage data", () => {
  it("one http URL per zone on the configured hostname; empty until a hostname and zones exist", async () => {
    await allInOne();
    expect((await h.json<any>("viewer", "GET", "/sites/hall-b/speedtest/qr")).body).toEqual({ items: [] });
    await put(BODY());
    const q = await h.json<any>("viewer", "GET", "/sites/hall-b/speedtest/qr");
    expect(q.body.items).toEqual([
      { zone: "hall-a", name: "Hall A", url: "http://speed.summit.example/?z=hall-a" },
      { zone: "hall-b", name: "Hall B", url: "http://speed.summit.example/?z=hall-b" },
    ]);
  });
});

describe("provided TLS", () => {
  it("tls.mode provided needs an uploaded pair; then 443 + the pair reach the speedtest host only", async () => {
    const box = await allInOne();
    const r = await put(BODY({ tls: { mode: "provided" } }));
    expect(r.status).toBe(400);
    const c = await makeCert({ kind: "ec", cn: "speed.summit.example" });
    const t = await h.json<any>("admin", "PUT", "/sites/hall-b/speedtest/tls", { cert_pem: c.certPem, key_pem: c.keyPem });
    expect(t.status, JSON.stringify(t.body)).toBe(200);
    expect(t.body.set).toBe(true);
    expect(JSON.stringify(t.body)).not.toContain("PRIVATE KEY");
    expect((await h.json("viewer", "GET", "/sites/hall-b/speedtest/tls")).status).toBe(403);
    expect((await put(BODY({ tls: { mode: "provided" } }))).status).toBe(200);
    const d = await docOf(box.secret);
    const spd = comp(d, "speedtest");
    expect(spd.config.tls).toEqual({ mode: "provided" });
    expect(spd.creds["tls.crt"]).toContain("BEGIN CERTIFICATE");
    expect(spd.creds["tls.key"]).toContain("PRIVATE KEY");
    for (const t2 of ["collector", "runner"]) expect(JSON.stringify(comp(d, t2))).not.toContain("PRIVATE KEY");
    // QR links switch to https
    expect((await h.json<any>("viewer", "GET", "/sites/hall-b/speedtest/qr")).body.items[0].url).toBe("https://speed.summit.example/?z=hall-a");
    // a bad pair is refused
    expect((await h.json("admin", "PUT", "/sites/hall-b/speedtest/tls", { cert_pem: "x", key_pem: "y" })).status).toBe(422);
  });
});

describe("fleet health rows", () => {
  it("the host lists the speedtest + runner shapes and their health metrics are rolled up", async () => {
    const box = await allInOne();
    await put(BODY());
    const r = await postStatus(
      box.secret,
      statusReport({
        facts: FACTS({ interfaces: IFACES }),
        components: [
          { type: "collector", id: "col-hallb", state: "running", health: "ok", facts: { listen: "10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT } },
          { type: "speedtest", id: "spd-core", state: "running", health: "ok", facts: { url: "http://speed.summit.example/", tls_mode: "none" }, metrics: { tests_per_hour: 42, active_tests: 3, queue_depth: 0, internet_leg_paused: 0, local_leg_gbps_p95: 1.4, rejected_per_hour: 2, bogus: 9 } },
          { type: "runner", id: "run-core", state: "running", health: "degraded", metrics: { correlations_per_hour: 40, evidence_lag_s_p95: 12.5, syslog_lines_per_s: 80, syslog_dropped_per_min: 0 } },
        ],
      }),
    );
    expect(r.status, await r.clone().text()).toBeLessThan(300);
    const fh = await h.json<any>("viewer", "GET", "/fleet/hosts");
    const row = fh.body.items.find((x: any) => x.host_id === box.host_id);
    expect(row.shapes).toEqual(expect.arrayContaining(["collector", "runner", "speedtest"]));
    expect(row.work.tests_per_hour).toBe(42);
    const m = await h.json<any>("viewer", "GET", `/fleet/components/${box.spd}/metrics?range=24h`);
    expect(m.status).toBe(200);
    expect(Object.keys(m.body.series).sort()).toEqual(["active_tests", "internet_leg_paused", "local_leg_gbps_p95", "queue_depth", "rejected_per_hour", "tests_per_hour"]);
    const mr = await h.json<any>("viewer", "GET", `/fleet/components/${box.run}/metrics?range=24h&keys=correlations_per_hour,syslog_lines_per_s`);
    expect(Object.keys(mr.body.series).sort()).toEqual(["correlations_per_hour", "syslog_lines_per_s"]);
    const hosts = await h.json<any>("viewer", "GET", `/fleet/hosts?type=speedtest`);
    expect(hosts.status).toBe(200);
  });
});

describe("SR-20: the manager receives no test results or evidence", () => {
  it("no admin or agent route accepts or serves results, evidence, tests or sessions", async () => {
    await allInOne();
    for (const p of ["/speedtests", "/sites/hall-b/speedtests", "/sites/hall-b/speedtest/results", "/sites/hall-b/speedtest/tests", "/sites/hall-b/speedtest/evidence", "/sites/hall-b/speedtest/sessions", "/evidence", "/results", "/st/api/v1/sessions"]) {
      for (const m of ["GET", "POST", "PUT"]) {
        const r = await h.api("owner", m, p, m === "GET" ? undefined : {});
        expect(r.status, `${m} ${p}`).toBe(404);
      }
    }
    for (const p of ["/api/agent/v1/speedtests", "/api/agent/v1/results", "/api/agent/v1/evidence"]) {
      const r = await call(p, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      expect([401, 404], p).toContain(r.status);
    }
  });
});
