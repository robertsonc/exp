// Provided dashboard TLS (CR p2): PUT/GET /dashboards/{id}/tls, validation, write-only storage, compiler output.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Harness, harness } from "../admin-harness";
import { ADMIN_ACTOR, env, fullScenario, getDesired, resetDb, seedSiteWithRelease, type Scenario } from "../helpers";
import { makeCert, pemOf, unwrapPkcs8 } from "../tls-fixtures";
import { setClock } from "../../src/util/time";

let h: Harness;
let sc: Scenario;
beforeEach(async () => {
  await resetDb();
  await seedSiteWithRelease("hall-b", "0.1.0");
  h = await harness();
  sc = await fullScenario();
});
afterEach(() => {
  h.restore();
  setClock(null);
});

type Doc = { version: number; components: Array<{ config: { tls: { mode: string } }; creds: Record<string, string> }> };
const docOf = async (secret: string): Promise<Doc> => (await (await getDesired(secret)).json()) as Doc;
const PATH = "/dashboards/dash-main/tls";
const lastAudit = async () => (await env.DB.prepare("SELECT action, resource, details_json FROM audit ORDER BY ts DESC, evt_id DESC LIMIT 1").first<{ action: string; resource: string; details_json: string }>())!;

describe("PUT/GET dashboards/{id}/tls", () => {
  it("starts self_signed, accepts a valid pair, and GET never returns the key or the PEM", async () => {
    const g0 = await h.json("admin", "GET", PATH);
    expect(g0.body).toEqual({ mode: "self_signed", set: false, updated_at: null, cert: null });
    for (const kind of ["ec", "rsa"] as const) {
      const c = await makeCert({ kind, cn: "dash.example.test", org: "Example Events" });
      const r = await h.json<Record<string, any>>("admin", "PUT", PATH, { mode: "provided", cert_pem: c.certPem, key_pem: c.keyPem });
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      expect(r.body.mode).toBe("provided");
      expect(r.body.set).toBe(true);
      expect(r.body.cert.subject).toBe("O=Example Events, CN=dash.example.test");
      expect(r.body.cert.issuer).toBe("O=Example Events, CN=dash.example.test");
      expect(r.body.cert.san).toEqual(["dash.example.test", "10.32.98.30"]);
      const fp = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", c.certDer))).map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(":");
      expect(r.body.cert.sha256).toBe(fp);
      expect(Date.parse(r.body.cert.not_after)).toBeGreaterThan(Date.now() + 300 * 86400_000);
      const g = await h.api("admin", "GET", PATH);
      const text = await g.text();
      expect(text).not.toContain("PRIVATE KEY");
      expect(text).not.toContain("BEGIN");
      expect(text).not.toContain("key_pem");
      expect(JSON.parse(text).cert.sha256).toBe(fp);
    }
  });

  it("accepts SEC1 'EC PRIVATE KEY', PKCS#1 'RSA PRIVATE KEY' and a cert chain", async () => {
    const ec = await makeCert({ kind: "ec" });
    const r1 = await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: ec.certPem, key_pem: pemOf("EC PRIVATE KEY", unwrapPkcs8(ec.keyDer)) });
    expect(r1.status, JSON.stringify(r1.body)).toBe(200);
    const rsa = await makeCert({ kind: "rsa" });
    const r2 = await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: rsa.certPem, key_pem: pemOf("RSA PRIVATE KEY", unwrapPkcs8(rsa.keyDer)) });
    expect(r2.status, JSON.stringify(r2.body)).toBe(200);
    const other = await makeCert({ cn: "intermediate.example.test" });
    const r3 = await h.json<Record<string, any>>("admin", "PUT", PATH, { mode: "provided", cert_pem: ec.certPem + other.certPem, key_pem: ec.keyPem });
    expect(r3.status).toBe(200);
    expect(r3.body.cert.subject).toContain("dash.example.test");
  });

  const rejects = async (cert: string, key: string, msg: RegExp, extra: Record<string, unknown> = {}) => {
    const before = await docOf(sc.dash.secret);
    const r = await h.json<{ error: { code: string; message: string } }>("admin", "PUT", PATH, { mode: "provided", cert_pem: cert, key_pem: key, ...extra });
    expect(r.status, JSON.stringify(r.body)).toBe(422);
    expect(r.body.error.code).toBe("invalid_config");
    expect(r.body.error.message).toMatch(msg);
    expect(r.body.error.message).not.toContain("BEGIN");
    expect((await h.json("admin", "GET", PATH)).body).toMatchObject({ mode: "self_signed", set: false });
    expect((await docOf(sc.dash.secret)).version).toBe(before.version);
  };

  it("refuses an expired certificate (422)", async () => {
    const c = await makeCert({ notBefore: new Date(Date.now() - 400 * 86400_000), notAfter: new Date(Date.now() - 86400_000) });
    await rejects(c.certPem, c.keyPem, /expired/);
  });
  it("refuses garbage PEM, a missing certificate and a missing key (422)", async () => {
    const c = await makeCert();
    await rejects("not a certificate", c.keyPem, /no PEM CERTIFICATE/);
    await rejects(pemOf("CERTIFICATE", new Uint8Array([1, 2, 3, 4, 5, 6])), c.keyPem, /X\.509|DER/);
    await rejects(c.certPem, "garbage", /exactly one PEM private key/);
    await rejects(c.certPem, "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n", /malformed|PEM/);
    await rejects(c.certPem, pemOf("PRIVATE KEY", new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00])), /private key could not be read/);
  });
  it("refuses a private key that does not match the certificate (422), same type and different type", async () => {
    const a = await makeCert({ kind: "ec" });
    const b = await makeCert({ kind: "ec" });
    await rejects(a.certPem, b.keyPem, /does not match the certificate/);
    const r = await makeCert({ kind: "rsa" });
    await rejects(a.certPem, r.keyPem, /does not match|could not be read/);
    await rejects(r.certPem, a.keyPem, /does not match|could not be read/);
  });
  it("refuses a passphrase-protected key (422)", async () => {
    const c = await makeCert();
    await rejects(c.certPem, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n", /passphrase/);
  });
  it("refuses oversize input (422 past the cap, 400 far past the schema bound)", async () => {
    const c = await makeCert();
    await rejects(c.certPem + "#".repeat(33 * 1024), c.keyPem, /exceeds 32 KiB/);
    await rejects(c.certPem, c.keyPem + "#".repeat(9 * 1024), /exceeds 8 KiB/);
    const huge = await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: c.certPem + "#".repeat(80 * 1024), key_pem: c.keyPem });
    expect(huge.status).toBe(400);
  });
  it("refuses unknown fields, a missing pair and an unknown mode (400)", async () => {
    const c = await makeCert();
    expect((await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: c.certPem })).status).toBe(400);
    expect((await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: c.certPem, key_pem: c.keyPem, extra: 1 })).status).toBe(400);
    expect((await h.json("admin", "PUT", PATH, { mode: "self_signed", cert_pem: c.certPem })).status).toBe(400);
    expect((await h.json("admin", "PUT", PATH, { mode: "acme" })).status).toBe(400);
    expect((await h.json("admin", "PUT", "/dashboards/nope/tls", { mode: "self_signed" })).status).toBe(404);
  });
  it("is admin-only and CSRF-guarded", async () => {
    const c = await makeCert();
    for (const role of ["viewer", "operator"] as const) {
      expect((await h.json(role, "PUT", PATH, { mode: "provided", cert_pem: c.certPem, key_pem: c.keyPem })).status).toBe(403);
      expect((await h.json(role, "GET", PATH)).status).toBe(403);
    }
    const r = await h.api("admin", "PUT", PATH, { mode: "self_signed" }, { "X-Exp-Request": "" });
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe("csrf_refused");
  });
});

describe("storage and audit", () => {
  it("encrypts both parts; a D1 dump holds no plaintext key or certificate; the audit has no values", async () => {
    const c = await makeCert();
    expect((await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: c.certPem, key_pem: c.keyPem })).status).toBe(200);
    const body = c.keyPem.split("\n")[1]!.slice(0, 40);
    const certBody = c.certPem.split("\n")[1]!.slice(0, 40);
    for (const table of ["secrets", "audit", "components", "desired_docs"]) {
      const rows = (await env.DB.prepare(`SELECT * FROM ${table}`).all()).results;
      const dump = JSON.stringify(rows);
      expect(dump, table).not.toContain(body);
      expect(dump, table).not.toContain(certBody);
      expect(dump, table).not.toContain("BEGIN PRIVATE KEY");
      expect(dump, table).not.toContain("PRIVATE KEY");
    }
    const row = await env.DB.prepare("SELECT kind, ciphertext, owner_ref FROM secrets WHERE kind = 'dashboard_tls'").first<{ kind: string; ciphertext: string; owner_ref: string }>();
    expect(row?.owner_ref).toBe(sc.dashId);
    const a = await lastAudit();
    expect(a.action).toBe("dashboard.tls");
    expect(a.resource).toBe("dashboard:dash-main");
    const det = JSON.parse(a.details_json) as Record<string, unknown>;
    expect(det.mode).toBe("provided");
    expect(det.secret_set).toBe(true);
    expect(JSON.stringify(det)).not.toMatch(/PRIVATE|BEGIN|key_pem|cert_pem/);
  });

  it("replacing the pair keeps one row; self_signed removes it", async () => {
    const a = await makeCert({ cn: "a.example.test" });
    const b = await makeCert({ cn: "b.example.test" });
    await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: a.certPem, key_pem: a.keyPem });
    await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: b.certPem, key_pem: b.keyPem });
    const n = async () => (await env.DB.prepare("SELECT COUNT(*) AS n FROM secrets WHERE kind = 'dashboard_tls'").first<{ n: number }>())!.n;
    expect(await n()).toBe(1);
    expect(((await h.json<{ cert: { subject: string } }>("admin", "GET", PATH)).body).cert.subject).toContain("b.example.test");
    const r = await h.json("admin", "PUT", PATH, { mode: "self_signed" });
    expect(r.body).toEqual({ mode: "self_signed", set: false, updated_at: null, cert: null });
    expect(await n()).toBe(0);
    expect((await docOf(sc.dash.secret)).components[0]!.config.tls.mode).toBe("self_signed");
  });

  it("deleting the dashboard component deletes the pair", async () => {
    const c = await makeCert();
    await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: c.certPem, key_pem: c.keyPem });
    const r = await h.json("admin", "DELETE", `/components/${sc.dashId}`);
    expect(r.status).toBe(204);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM secrets WHERE kind = 'dashboard_tls'").first<{ n: number }>())!.n).toBe(0);
  });
});

describe("compiler", () => {
  it("only the dashboard host's desired doc carries tls.crt / tls.key; mode flips back with self_signed", async () => {
    const c = await makeCert();
    const before = await docOf(sc.dash.secret);
    expect(before.components[0]!.config.tls.mode).toBe("self_signed");
    expect(before.components[0]!.creds["tls.key"]).toBeUndefined();
    const colV = (await docOf(sc.col.secret)).version;
    const probeV = (await docOf(sc.probe.secret)).version;
    await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: c.certPem, key_pem: c.keyPem });
    const d = await docOf(sc.dash.secret);
    expect(d.version).toBe(before.version + 1);
    expect(d.components[0]!.config.tls.mode).toBe("provided");
    expect(d.components[0]!.creds["tls.crt"]).toBe(c.certPem);
    expect(d.components[0]!.creds["tls.key"]).toBe(c.keyPem);
    for (const s of [sc.col.secret, sc.probe.secret]) {
      const o = await docOf(s);
      for (const comp of o.components) {
        expect(Object.keys(comp.creds)).not.toContain("tls.key");
        expect(Object.keys(comp.creds)).not.toContain("tls.crt");
      }
    }
    expect((await docOf(sc.col.secret)).version).toBe(colV);
    expect((await docOf(sc.probe.secret)).version).toBe(probeV);
    await h.json("admin", "PUT", PATH, { mode: "self_signed" });
    const back = await docOf(sc.dash.secret);
    expect(back.components[0]!.config.tls.mode).toBe("self_signed");
    expect(Object.keys(back.components[0]!.creds)).not.toContain("tls.key");
  });

  it("a config that says provided without an uploaded pair stays self_signed", async () => {
    const svc = await import("../../src/admin/service");
    await svc.updateComponentConfig(env, ADMIN_ACTOR, sc.dashId, { tls: { mode: "provided" } });
    const d = await docOf(sc.dash.secret);
    expect(d.components[0]!.config.tls.mode).toBe("self_signed");
    expect(d.components[0]!.creds["tls.key"]).toBeUndefined();
  });

  it("the provided pair survives a dashboard config rewrite (it is not part of config)", async () => {
    const svc = await import("../../src/admin/service");
    const c = await makeCert();
    await h.json("admin", "PUT", PATH, { mode: "provided", cert_pem: c.certPem, key_pem: c.keyPem });
    await svc.updateComponentConfig(env, ADMIN_ACTOR, sc.dashId, { title: "Hall B" });
    const d = await docOf(sc.dash.secret);
    expect(d.components[0]!.config.tls.mode).toBe("provided");
    expect(d.components[0]!.creds["tls.key"]).toBe(c.keyPem);
  });
});
