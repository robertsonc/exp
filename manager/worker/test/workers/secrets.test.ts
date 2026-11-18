// 05-manager.md section 15 item 6 (SR-14): no plaintext secrets at rest; encryption round trip; rotation overlap.
import { beforeEach, describe, expect, it } from "vitest";
import { rotateComponentTokens } from "../../src/admin/service";
import { ConfigError } from "../../src/errors";
import { recompile } from "../../src/compile/recompile";
import { masterKey, open, seal, secretAad } from "../../src/secrets/crypto";
import { createSecret, dropExpiredPrevious, getSecretByOwner, prepareRotateSecret, readPreviousSecret, readSecret } from "../../src/secrets/store";
import { newToken, newSsoSecret, TOKEN_RE } from "../../src/secrets/tokens";
import { sha256Hex } from "../../src/util/encoding";
import { ADMIN_ACTOR, WEBHOOK_URL, PBKDF2, env, fullScenario, getDesired, resetDb, seedSiteWithRelease, tableNames } from "../helpers";

beforeEach(async () => {
  await resetDb();
  await seedSiteWithRelease("hall-b", "0.1.0");
});

async function dump(): Promise<string> {
  const parts: string[] = [];
  for (const t of await tableNames()) {
    const rows = await env.DB.prepare(`SELECT * FROM ${t}`).all();
    parts.push(`-- ${t}\n${JSON.stringify(rows.results)}`);
  }
  return parts.join("\n");
}

describe("AES-256-GCM at rest", () => {
  it("round-trips and uses a fresh nonce per write", async () => {
    const key = await masterKey(env.EXP_MASTER_KEY);
    const a = await seal(key, "hello", "s|k|1");
    const b = await seal(key, "hello", "s|k|1");
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(await open(key, a, "s|k|1")).toBe("hello");
  });

  it("AAD = secret_id|kind|version: a row moved to another identity does not decrypt", async () => {
    const key = await masterKey(env.EXP_MASTER_KEY);
    const s = await seal(key, "hello", secretAad("sec_1", "ingest_token", 1));
    for (const aad of [secretAad("sec_2", "ingest_token", 1), secretAad("sec_1", "webhook_url", 1), secretAad("sec_1", "ingest_token", 2)]) {
      await expect(open(key, s, aad)).rejects.toBeInstanceOf(ConfigError);
    }
  });

  it("a wrong master key or a tampered ciphertext is detected", async () => {
    const id = await createSecret(env, { ownerRef: "own-1", kind: "webhook_url", plaintext: WEBHOOK_URL });
    const row = (await getSecretByOwner(env, "own-1", "webhook_url"))!;
    expect(row.secret_id).toBe(id);
    expect(await readSecret(env, row)).toBe(WEBHOOK_URL);
    const other = { ...env, EXP_MASTER_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))) };
    await expect(readSecret(other, row)).rejects.toBeInstanceOf(ConfigError);
    const tampered = { ...row, ciphertext: row.ciphertext.replace(/^./, (c) => (c === "A" ? "B" : "A")) };
    await expect(readSecret(env, tampered)).rejects.toBeInstanceOf(ConfigError);
  });

  it("a missing or malformed EXP_MASTER_KEY fails closed with a clear error", () => {
    for (const bad of [undefined, "", "   ", "%%%", btoa("too short"), btoa("x".repeat(33))]) {
      let err: unknown;
      try {
        void masterKey(bad);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as ConfigError).message).toMatch(/EXP_MASTER_KEY/);
    }
  });

  it("generates well-formed tokens", () => {
    for (const k of ["expe", "expa", "expi", "expd", "expn"] as const) {
      const t = newToken(k);
      expect(t).toMatch(TOKEN_RE[k]);
      expect(newToken(k)).not.toBe(t);
    }
    expect(atob(newSsoSecret())).toHaveLength(32);
  });
});

describe("no plaintext secrets in D1", () => {
  it("a full dump contains no exp[aeidn]_ token, no webhook URL, no plaintext cred", async () => {
    const sc = await fullScenario();
    // plaintexts that exist in the system
    const probeDoc = (await (await getDesired(sc.probe.secret)).json()) as { components: Array<{ creds: Record<string, string> }> };
    const dashDoc = (await (await getDesired(sc.dash.secret)).json()) as { components: Array<{ creds: Record<string, string> }> };
    const colDoc = (await (await getDesired(sc.col.secret)).json()) as { components: Array<{ creds: Record<string, string> }> };
    const ingest = probeDoc.components[0]!.creds.ingest_token!;
    const dashTok = Object.values(JSON.parse(dashDoc.components[0]!.creds["collector_tokens.json"]!) as Record<string, string>)[0]!;
    const sso = dashDoc.components[0]!.creds.sso_secret!;
    expect(ingest).toMatch(TOKEN_RE.expi);
    expect(dashTok).toMatch(TOKEN_RE.expd);
    expect(JSON.parse(colDoc.components[0]!.creds["webhooks.json"]!)[0].url).toBe(WEBHOOK_URL);

    const d = await dump();
    expect(d).not.toMatch(/exp[aeidn]_[A-Za-z0-9_-]{8,}/);
    expect(d).not.toContain("https://hooks");
    for (const secret of [ingest, dashTok, sso, sc.nocToken, sc.col.secret, sc.probe.secret, sc.dash.secret, WEBHOOK_URL]) {
      expect(d).not.toContain(secret);
    }
    // what IS stored is only verifiers
    expect(d).toContain(await sha256Hex(ingest));
    expect(d).toContain(await sha256Hex(sc.nocToken));
    void PBKDF2;
  });
});

describe("rotation with overlap", () => {
  it("probe ingest token: collector accepts old and new for 10 min, probe switches, then the old is dropped", async () => {
    const sc = await fullScenario();
    const hashesOf = async () => {
      const d = (await (await getDesired(sc.col.secret)).json()) as { version: number; components: Array<{ creds: Record<string, string> }> };
      return { version: d.version, map: JSON.parse(d.components[0]!.creds["ingest_tokens.json"]!) as Record<string, string | string[]> };
    };
    const probeTok = async () => ((await (await getDesired(sc.probe.secret)).json()) as { components: Array<{ creds: Record<string, string> }> }).components[0]!.creds.ingest_token!;

    const t0 = await probeTok();
    const h0 = await hashesOf();
    expect(h0.map["probe-a1"]).toBe(await sha256Hex(t0)); // plain string while there is no overlap

    await rotateComponentTokens(env, ADMIN_ACTOR, sc.probeId);
    const t1 = await probeTok();
    expect(t1).not.toBe(t0);
    expect(t1).toMatch(TOKEN_RE.expi);
    const h1 = await hashesOf();
    expect(h1.version).toBeGreaterThan(h0.version);
    expect(h1.map["probe-a1"]).toEqual([await sha256Hex(t1), await sha256Hex(t0)]); // both valid

    const row = (await getSecretByOwner(env, sc.probeId, "ingest_token"))!;
    expect(await readPreviousSecret(env, row)).toBe(t0);

    // grace elapses: cron drops previous_*; the next compile publishes only the new hash
    await env.DB.prepare("UPDATE secrets SET previous_valid_until = '2020-01-01T00:00:00.000Z' WHERE owner_ref = ?1").bind(sc.probeId).run();
    expect(await dropExpiredPrevious(env)).toBe(1);
    await recompile(env, { all: true });
    const h2 = await hashesOf();
    expect(h2.map["probe-a1"]).toBe(await sha256Hex(t1));
    expect(await readPreviousSecret(env, (await getSecretByOwner(env, sc.probeId, "ingest_token"))!)).toBeNull();
  });

  it("the old value stops counting as soon as previous_valid_until passes, even before cron runs", async () => {
    const sc = await fullScenario();
    await rotateComponentTokens(env, ADMIN_ACTOR, sc.probeId);
    await env.DB.prepare("UPDATE secrets SET previous_valid_until = '2020-01-01T00:00:00.000Z' WHERE owner_ref = ?1").bind(sc.probeId).run();
    await recompile(env, { all: true });
    const d = (await (await getDesired(sc.col.secret)).json()) as { components: Array<{ creds: Record<string, string> }> };
    const m = JSON.parse(d.components[0]!.creds["ingest_tokens.json"]!) as Record<string, unknown>;
    expect(typeof m["probe-a1"]).toBe("string");
  });

  it("dashboard tokens rotate the same way (collector sees both hashes, dashboard gets the new token)", async () => {
    const sc = await fullScenario();
    const before = (await (await getDesired(sc.dash.secret)).json()) as { components: Array<{ creds: Record<string, string> }> };
    const oldTok = JSON.parse(before.components[0]!.creds["collector_tokens.json"]!)["col-hallb"] as string;
    await rotateComponentTokens(env, ADMIN_ACTOR, sc.dashId);
    const after = (await (await getDesired(sc.dash.secret)).json()) as { components: Array<{ creds: Record<string, string> }> };
    const newTok = JSON.parse(after.components[0]!.creds["collector_tokens.json"]!)["col-hallb"] as string;
    expect(newTok).not.toBe(oldTok);
    const col = (await (await getDesired(sc.col.secret)).json()) as { components: Array<{ creds: Record<string, string> }> };
    const m = JSON.parse(col.components[0]!.creds["dashboard_tokens.json"]!) as Record<string, string[]>;
    expect(m["dash-main"]).toEqual([await sha256Hex(newTok), await sha256Hex(oldTok)]);
  });

  it("rotation bumps the version and leaves the secret row consistent (compare-and-swap on version)", async () => {
    const sc = await fullScenario();
    const row = (await getSecretByOwner(env, sc.probeId, "ingest_token"))!;
    const stmt = await prepareRotateSecret(env, row, newToken("expi"), true);
    expect((await stmt.run()).meta.changes).toBe(1);
    // a second rotation computed from the stale row changes nothing
    const stale = await prepareRotateSecret(env, row, newToken("expi"), true);
    expect((await stale.run()).meta.changes).toBe(0);
    const now = (await getSecretByOwner(env, sc.probeId, "ingest_token"))!;
    expect(now.version).toBe(row.version + 1);
    expect(now.previous_version).toBe(row.version);
  });
});
