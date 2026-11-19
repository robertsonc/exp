// EXP_MASTER_KEY rotation with re-encryption (05-manager.md section 6, migration 0003).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runEveryFiveMinutes } from "../../src/cron";
import { openDesiredDoc } from "../../src/compile/recompile";
import { ConfigError } from "../../src/errors";
import { keyIdOf, keyRing, open, openCred, seal, sealCred, secretAad, credAad } from "../../src/secrets/crypto";
import { masterKeyStatus, rekeyBatch } from "../../src/secrets/rekey";
import { prepareRotateSecret, readPreviousSecret, readSecret, getSecretByOwner, type SecretRow } from "../../src/secrets/store";
import { newToken } from "../../src/secrets/tokens";
import type { Env } from "../../src/env";
import { sha256Hex } from "../../src/util/encoding";
import { setClock } from "../../src/util/time";
import { type Harness, harness } from "../admin-harness";
import { env, fullScenario, resetDb, seedSiteWithRelease, tableNames } from "../helpers";

const keyText = (fill: number): string => btoa(String.fromCharCode(...new Uint8Array(32).fill(fill)));
const KEY_A = env.EXP_MASTER_KEY as string;
const KEY_B = keyText(0x42);
const KEY_C = keyText(0x77);

const asB = (): Env => ({ ...env, EXP_MASTER_KEY: KEY_B, EXP_MASTER_KEY_PREVIOUS: undefined }) as Env;
const rotated = (): Env => ({ ...env, EXP_MASTER_KEY: KEY_B, EXP_MASTER_KEY_PREVIOUS: KEY_A }) as Env;

let h: Harness;
beforeEach(async () => {
  await resetDb();
  h = await harness();
  await seedSiteWithRelease("hall-b", "0.1.0");
});
afterEach(() => {
  h.restore();
  setClock(null);
});

async function secretPlaintexts(e: Env): Promise<Record<string, string>> {
  const rows = (await env.DB.prepare("SELECT * FROM secrets ORDER BY secret_id").all<SecretRow>()).results;
  const out: Record<string, string> = {};
  for (const r of rows) out[r.secret_id] = await readSecret(e, r);
  return out;
}

async function desiredPlaintexts(e: Env): Promise<Record<string, unknown>> {
  const rows = (await env.DB.prepare("SELECT host_id, doc_json FROM desired_docs ORDER BY host_id").all<{ host_id: string; doc_json: string }>()).results;
  const out: Record<string, unknown> = {};
  for (const r of rows) out[r.host_id] = await openDesiredDoc(e, r.doc_json);
  return out;
}

async function dump(): Promise<string> {
  const parts: string[] = [];
  for (const t of await tableNames()) parts.push(`-- ${t}\n${JSON.stringify((await env.DB.prepare(`SELECT * FROM ${t}`).all()).results)}`);
  return parts.join("\n");
}

const count = async (sql: string): Promise<number> => (await env.DB.prepare(sql).first<{ n: number }>())!.n;

describe("key ids", () => {
  it("key_id is the first 16 hex of sha256('exp-key-id/v1|' + key text) and carries no key material", async () => {
    const id = await keyIdOf(KEY_A);
    expect(id).toMatch(/^[0-9a-f]{16}$/);
    expect(id).toBe((await sha256Hex(`exp-key-id/v1|${KEY_A}`)).slice(0, 16));
    expect(await keyIdOf(`  ${KEY_A}\n`)).toBe(id);
    expect(await keyIdOf(KEY_B)).not.toBe(id);
  });

  it("new rows and compiled desired docs are stamped with the current key id; creds use the enc2 envelope", async () => {
    await fullScenario();
    const idA = await keyIdOf(KEY_A);
    expect(await count(`SELECT COUNT(*) AS n FROM secrets WHERE key_id IS NOT '${idA}'`)).toBe(0);
    expect(await count(`SELECT COUNT(*) AS n FROM desired_docs WHERE key_id IS NOT '${idA}'`)).toBe(0);
    const docs = (await env.DB.prepare("SELECT doc_json FROM desired_docs").all<{ doc_json: string }>()).results;
    expect(docs.some((d) => d.doc_json.includes(`enc2:${idA}:`))).toBe(true);
    expect(docs.every((d) => !d.doc_json.includes("enc1:"))).toBe(true);
  });
});

describe("rotation A -> B", () => {
  it("everything still decrypts with B current and A previous; status reports progress; cron re-encrypts in bounded batches; then B alone suffices", async () => {
    const sc = await fullScenario();
    // a rotated secret keeps a previous_* value inside its grace window: it must be re-sealed too
    const sec = (await getSecretByOwner(env, sc.probeId, "ingest_token"))!;
    const oldPlain = await readSecret(env, sec);
    await env.DB.batch([await prepareRotateSecret(env, sec, newToken("expi"), true)]);
    const before = { secrets: await secretPlaintexts(env), desired: await desiredPlaintexts(env) };
    const nSecrets = Object.keys(before.secrets).length;
    expect(nSecrets).toBeGreaterThanOrEqual(4);
    const idA = await keyIdOf(KEY_A);
    const idB = await keyIdOf(KEY_B);

    // 1. operator rotates: still readable, nothing re-sealed yet
    const rot = rotated();
    expect(await secretPlaintexts(rot)).toEqual(before.secrets);
    expect(await desiredPlaintexts(rot)).toEqual(before.desired);
    // ... and B alone cannot read yet (fails closed with the unknown-key error, no guessing)
    await expect(secretPlaintexts(asB())).rejects.toMatchObject({ code: "unknown_key_id" });
    expect((await readPreviousSecret(rot, (await getSecretByOwner(rot, sc.probeId, "ingest_token"))!, Date.now()))).toBe(oldPlain);

    // 2. read-only progress via the admin API (admin/owner only)
    h.withEnv({ EXP_MASTER_KEY: KEY_B, EXP_MASTER_KEY_PREVIOUS: KEY_A });
    expect((await h.json("viewer", "GET", "/settings/master-key")).status).toBe(403);
    expect((await h.json("operator", "GET", "/settings/master-key")).status).toBe(403);
    const s0 = await h.json<Record<string, unknown>>("admin", "GET", "/settings/master-key");
    expect(s0.status).toBe(200);
    expect(s0.body).toMatchObject({ current_key_id: idB, previous_key_id: idA, unknown_key_rows: 0, safe_to_remove_previous: false });
    const total = (s0.body.remaining_previous as number);
    expect(total).toBeGreaterThanOrEqual(nSecrets + 1 + 3); // secrets + one previous_* value + desired docs
    expect(JSON.stringify(s0.body)).not.toContain(KEY_A);
    expect(JSON.stringify(s0.body)).not.toContain(KEY_B);
    expect((await h.json("owner", "GET", "/settings/master-key")).status).toBe(200);

    // 3. bounded batches
    const r1 = await rekeyBatch(rot, 3);
    expect(r1.rewritten).toBe(3);
    expect(r1.status.remaining_previous).toBe(total - 3);
    let batches = 1;
    for (let i = 0; i < 50 && (await masterKeyStatus(rot)).remaining_previous > 0; i++, batches++) {
      const r = await rekeyBatch(rot, 3);
      expect(r.rewritten).toBeLessThanOrEqual(3);
      expect(r.rewritten + r.failed).toBeGreaterThan(0);
    }
    expect(batches).toBeGreaterThanOrEqual(3);
    const done = await masterKeyStatus(rot);
    expect(done).toMatchObject({ remaining_previous: 0, unknown_key_rows: 0, safe_to_remove_previous: true });
    expect((await rekeyBatch(rot)).rewritten).toBe(0); // idempotent, nothing left

    // 4. PREVIOUS removed: B alone decrypts everything, same plaintexts; the served desired state is unchanged
    const b = asB();
    expect(await secretPlaintexts(b)).toEqual(before.secrets);
    expect(await desiredPlaintexts(b)).toEqual(before.desired);
    const prevRow = (await getSecretByOwner(b, sc.probeId, "ingest_token"))!;
    expect(prevRow.previous_key_id).toBe(idB);
    expect(await readPreviousSecret(b, prevRow, Date.now())).toBe(oldPlain);
    expect(await count(`SELECT COUNT(*) AS n FROM secrets WHERE key_id != '${idB}'`)).toBe(0);
    expect(await count(`SELECT COUNT(*) AS n FROM desired_docs WHERE key_id != '${idB}'`)).toBe(0);
    // A alone no longer reads anything
    await expect(secretPlaintexts(env)).rejects.toBeInstanceOf(ConfigError);

    // 5. D1 holds no plaintext and no key material
    const d = await dump();
    for (const p of [...Object.values(before.secrets), oldPlain]) expect(d).not.toContain(p);
    expect(d).not.toContain(KEY_A);
    expect(d).not.toContain(KEY_B);

    // 6. audit: re-encrypt events, no key material (key ids only)
    const ev = (await env.DB.prepare("SELECT details_json FROM audit WHERE action = 'master_key.reencrypt' ORDER BY ts").all<{ details_json: string }>()).results;
    expect(ev.length).toBeGreaterThan(1);
    const joined = ev.map((e) => e.details_json).join("\n");
    expect(joined).toContain(idB);
    expect(joined).not.toContain(KEY_A);
    expect(joined).not.toContain(KEY_B);
    expect(JSON.parse(ev[ev.length - 1]!.details_json)).toMatchObject({ complete: true, remaining_previous: 0 });
  });

  it("the 5-minute cron drives the re-encryption (200 rows per run)", async () => {
    await fullScenario();
    const before = await secretPlaintexts(env);
    const rot = rotated();
    expect((await masterKeyStatus(rot)).remaining_previous).toBeGreaterThan(0);
    await runEveryFiveMinutes(rot);
    expect(await masterKeyStatus(rot)).toMatchObject({ remaining_previous: 0, safe_to_remove_previous: true });
    expect(await secretPlaintexts(asB())).toEqual(before);
  });

  it("two concurrent batches leave consistent, decryptable rows (guarded per-row updates)", async () => {
    await fullScenario();
    const before = { s: await secretPlaintexts(env), d: await desiredPlaintexts(env) };
    const rot = rotated();
    await Promise.all([rekeyBatch(rot, 4), rekeyBatch(rot, 4), rekeyBatch(rot, 4)]);
    while ((await masterKeyStatus(rot)).remaining_previous > 0) await rekeyBatch(rot, 4);
    expect(await secretPlaintexts(asB())).toEqual(before.s);
    expect(await desiredPlaintexts(asB())).toEqual(before.d);
  });

  it("a recompile after the rotation seals under the new key and does not need the old one", async () => {
    const sc = await fullScenario();
    const rot = rotated();
    const { recompile } = await import("../../src/compile/recompile");
    await rekeyBatch(rot, 1000);
    await env.DB.prepare("UPDATE desired_docs SET content_hash = 'x'").run(); // force a rewrite
    await recompile(asB(), { all: true });
    const idB = await keyIdOf(KEY_B);
    expect(await count(`SELECT COUNT(*) AS n FROM desired_docs WHERE key_id != '${idB}'`)).toBe(0);
    expect(Object.keys(await desiredPlaintexts(asB())).length).toBeGreaterThan(0);
    void sc;
  });
});

describe("fail closed", () => {
  it("a value sealed by an unknown key is never decrypted by guessing, never rewritten, and is reported", async () => {
    const sc = await fullScenario();
    const row = (await getSecretByOwner(env, sc.probeId, "ingest_token"))!;
    const ringC = await keyRing({ EXP_MASTER_KEY: KEY_C });
    const plain = await readSecret(env, row);
    const aad = secretAad(row.secret_id, row.kind, row.version);
    const s = await seal(ringC.current.key, plain, aad);
    await env.DB.prepare("UPDATE secrets SET ciphertext = ?1, nonce = ?2, key_id = ?3 WHERE secret_id = ?4").bind(s.ciphertext, s.nonce, ringC.current.id, row.secret_id).run();

    const rot = rotated();
    const bad = (await getSecretByOwner(rot, sc.probeId, "ingest_token"))!;
    await expect(readSecret(rot, bad)).rejects.toMatchObject({ code: "unknown_key_id" });
    await expect(readSecret(rot, bad)).rejects.toThrow(/neither EXP_MASTER_KEY/);
    const st = await masterKeyStatus(rot);
    expect(st.unknown_key_rows).toBe(1);
    expect(st.safe_to_remove_previous).toBe(false);
    await rekeyBatch(rot, 1000);
    const after = await env.DB.prepare("SELECT ciphertext, key_id FROM secrets WHERE secret_id = ?1").bind(row.secret_id).first<{ ciphertext: string; key_id: string }>();
    expect(after).toEqual({ ciphertext: s.ciphertext, key_id: ringC.current.id }); // untouched
    // supplying that key as previous makes it readable again
    const withC = { ...env, EXP_MASTER_KEY: KEY_B, EXP_MASTER_KEY_PREVIOUS: KEY_C } as Env;
    expect(await readSecret(withC, bad)).toBe(plain);
  });

  it("an unknown key id inside a desired-doc credential envelope fails closed", async () => {
    const ring = await keyRing(env);
    const ringC = await keyRing({ EXP_MASTER_KEY: KEY_C });
    const aad = credAad("h_1", "c_1", "ingest_token");
    const v = await sealCred(ringC, "secret-value", aad);
    await expect(openCred(ring, v, aad)).rejects.toMatchObject({ code: "unknown_key_id" });
    expect(await openCred(ringC, v, aad)).toBe("secret-value");
  });

  it("a malformed EXP_MASTER_KEY_PREVIOUS fails closed; an identical one is ignored", async () => {
    await expect(keyRing({ EXP_MASTER_KEY: KEY_A, EXP_MASTER_KEY_PREVIOUS: "%%%" })).rejects.toMatchObject({ code: "master_key_invalid" });
    expect((await keyRing({ EXP_MASTER_KEY: KEY_A, EXP_MASTER_KEY_PREVIOUS: KEY_A })).previous).toBeNull();
    expect((await keyRing({ EXP_MASTER_KEY: KEY_A, EXP_MASTER_KEY_PREVIOUS: "" })).previous).toBeNull();
  });
});

describe("legacy rows (migration 0003: key_id NULL = sealed by the key current at migration time)", () => {
  it("unstamped rows and enc1 envelopes decrypt under the current key and are stamped by the cron", async () => {
    await fullScenario();
    const before = { s: await secretPlaintexts(env), d: await desiredPlaintexts(env) };
    // simulate pre-migration data: no key ids, enc1 envelopes
    await env.DB.prepare("UPDATE secrets SET key_id = NULL, previous_key_id = NULL").run();
    const docs = (await env.DB.prepare("SELECT host_id, doc_json FROM desired_docs").all<{ host_id: string; doc_json: string }>()).results;
    for (const d of docs) {
      await env.DB.prepare("UPDATE desired_docs SET key_id = NULL, doc_json = ?1 WHERE host_id = ?2").bind(d.doc_json.replace(/enc2:[0-9a-f]{16}:/g, "enc1:"), d.host_id).run();
    }
    expect(await secretPlaintexts(env)).toEqual(before.s);
    expect(await desiredPlaintexts(env)).toEqual(before.d);
    expect((await masterKeyStatus(env)).remaining_previous).toBeGreaterThan(0);
    await rekeyBatch(env);
    expect(await masterKeyStatus(env)).toMatchObject({ remaining_previous: 0, safe_to_remove_previous: true });
    expect(await secretPlaintexts(env)).toEqual(before.s);
    expect(await desiredPlaintexts(env)).toEqual(before.d);
  });

  it("legacy rows survive a rotation done before they were stamped (current tried first, then previous only)", async () => {
    await fullScenario();
    const before = { s: await secretPlaintexts(env), d: await desiredPlaintexts(env) };
    await env.DB.prepare("UPDATE secrets SET key_id = NULL").run();
    const rot = rotated();
    expect(await secretPlaintexts(rot)).toEqual(before.s);
    await rekeyBatch(rot, 1000);
    expect(await secretPlaintexts(asB())).toEqual(before.s);
    expect(await desiredPlaintexts(asB())).toEqual(before.d);
  });
});

describe("SSO launch nonce across a rotation", () => {
  it("a nonce minted under A still verifies for its 30 s life while A is the previous key; not after PREVIOUS is removed", async () => {
    await fullScenario();
    const l = await h.json<{ url: string }>("admin", "POST", "/dashboards/dash-main/sso/launch");
    expect(l.status).toBe(200);
    const path = l.body.url.replace("/api/admin/v1", "");
    h.withEnv({ EXP_MASTER_KEY: KEY_B, EXP_MASTER_KEY_PREVIOUS: KEY_A });
    expect((await h.api("admin", "GET", path)).status).toBe(200);
    // new nonces are minted under B and verify
    const l2 = await h.json<{ url: string }>("admin", "POST", "/dashboards/dash-main/sso/launch");
    expect((await h.api("admin", "GET", l2.body.url.replace("/api/admin/v1", ""))).status).toBe(200);
    // re-encryption completes, then PREVIOUS is removed: the old nonce is dead, the new one works
    await rekeyBatch(rotated(), 1000);
    h.withEnv({ EXP_MASTER_KEY: KEY_B, EXP_MASTER_KEY_PREVIOUS: undefined });
    expect((await h.api("admin", "GET", path)).status).toBe(403);
    expect((await h.api("admin", "GET", l2.body.url.replace("/api/admin/v1", ""))).status).toBe(200);
  });
});

describe("seal/open sanity", () => {
  it("open with the wrong ring key still fails with a ConfigError", async () => {
    const ring = await keyRing(env);
    const s = await seal(ring.current.key, "x", "a");
    const other = await keyRing({ EXP_MASTER_KEY: KEY_B });
    await expect(open(other.current.key, s, "a")).rejects.toBeInstanceOf(ConfigError);
  });
});
