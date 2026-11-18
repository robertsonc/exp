// Encrypted secret rows (table `secrets`). Plaintext exists only in memory.
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { newId } from "../util/ids";
import { isoAt, isoNow, nowMs } from "../util/time";
import { sha256Hex } from "../util/encoding";
import { masterKey, open, seal, secretAad } from "./crypto";

export const ROTATION_GRACE_S = 600; // previous value stays valid for 10 min (05-manager.md section 6)

export interface SecretRow {
  secret_id: string;
  owner_ref: string;
  kind: string;
  ciphertext: string;
  nonce: string;
  version: number;
  hash: string | null;
  previous_ciphertext: string | null;
  previous_nonce: string | null;
  previous_version: number | null;
  previous_hash: string | null;
  previous_valid_until: string | null;
}

export interface CreateSecretOptions {
  ownerRef: string;
  kind: string;
  plaintext: string;
  /** keep sha256(plaintext) for verifier-only consumers (ingest / dashboard / NOC tokens) */
  withHash?: boolean;
  secretId?: string;
}

/** Statement that inserts (or, with `ignoreExisting`, keeps) a secret. Returns the id too. */
export async function prepareCreateSecret(
  env: Env,
  o: CreateSecretOptions,
  ignoreExisting = false,
): Promise<{ secretId: string; stmt: D1PreparedStatement }> {
  const key = await masterKey(env.EXP_MASTER_KEY);
  const secretId = o.secretId ?? newId("sec_");
  const sealed = await seal(key, o.plaintext, secretAad(secretId, o.kind, 1));
  const now = isoNow();
  const hash = o.withHash ? await sha256Hex(o.plaintext) : null;
  const stmt = env.DB.prepare(
    `INSERT ${ignoreExisting ? "OR IGNORE " : ""}INTO secrets
       (secret_id, org_id, owner_ref, kind, ciphertext, nonce, version, hash, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?8)`,
  ).bind(secretId, DEFAULT_ORG, o.ownerRef, o.kind, sealed.ciphertext, sealed.nonce, hash, now);
  return { secretId, stmt };
}

export async function createSecret(env: Env, o: CreateSecretOptions): Promise<string> {
  const { secretId, stmt } = await prepareCreateSecret(env, o);
  await stmt.run();
  return secretId;
}

export async function getSecretRow(env: Env, secretId: string): Promise<SecretRow | null> {
  return env.DB.prepare("SELECT * FROM secrets WHERE secret_id = ?1").bind(secretId).first<SecretRow>();
}

export async function getSecretByOwner(env: Env, ownerRef: string, kind: string): Promise<SecretRow | null> {
  return env.DB.prepare("SELECT * FROM secrets WHERE owner_ref = ?1 AND kind = ?2").bind(ownerRef, kind).first<SecretRow>();
}

export async function readSecret(env: Env, row: SecretRow): Promise<string> {
  const key = await masterKey(env.EXP_MASTER_KEY);
  return open(key, { nonce: row.nonce, ciphertext: row.ciphertext }, secretAad(row.secret_id, row.kind, row.version));
}

/** Previous value if it is still inside its grace window, as plaintext (used by tests / diagnostics). */
export async function readPreviousSecret(env: Env, row: SecretRow, at: number = nowMs()): Promise<string | null> {
  if (!row.previous_ciphertext || !row.previous_nonce || row.previous_version == null) return null;
  if (!row.previous_valid_until || Date.parse(row.previous_valid_until) <= at) return null;
  const key = await masterKey(env.EXP_MASTER_KEY);
  return open(
    key,
    { nonce: row.previous_nonce, ciphertext: row.previous_ciphertext },
    secretAad(row.secret_id, row.kind, row.previous_version),
  );
}

/** Hashes that are currently valid for a verifier: the current one plus the previous within grace. */
export function activeHashes(row: Pick<SecretRow, "hash" | "previous_hash" | "previous_valid_until">, at: number = nowMs()): string[] {
  const out: string[] = [];
  if (row.hash) out.push(row.hash);
  if (row.previous_hash && row.previous_valid_until && Date.parse(row.previous_valid_until) > at) out.push(row.previous_hash);
  return out;
}

/** Statement that rotates a secret: current -> previous (valid for the grace period), version + 1. */
export async function prepareRotateSecret(
  env: Env,
  row: SecretRow,
  newPlaintext: string,
  withHash: boolean,
  graceS: number = ROTATION_GRACE_S,
): Promise<D1PreparedStatement> {
  const key = await masterKey(env.EXP_MASTER_KEY);
  const version = row.version + 1;
  const sealed = await seal(key, newPlaintext, secretAad(row.secret_id, row.kind, version));
  const hash = withHash ? await sha256Hex(newPlaintext) : null;
  return env.DB.prepare(
    `UPDATE secrets SET
       previous_ciphertext = ciphertext, previous_nonce = nonce, previous_version = version,
       previous_hash = hash, previous_valid_until = ?1,
       ciphertext = ?2, nonce = ?3, version = ?4, hash = ?5, updated_at = ?6
     WHERE secret_id = ?7 AND version = ?8`,
  ).bind(isoAt(nowMs() + graceS * 1000), sealed.ciphertext, sealed.nonce, version, hash, isoNow(), row.secret_id, row.version);
}

/** Drop previous_* values past their grace window (cron housekeeping). Returns rows changed. */
export async function dropExpiredPrevious(env: Env, at: number = nowMs()): Promise<number> {
  const r = await env.DB.prepare(
    `UPDATE secrets SET previous_ciphertext = NULL, previous_nonce = NULL, previous_version = NULL,
       previous_hash = NULL, previous_valid_until = NULL, updated_at = ?1
     WHERE previous_valid_until IS NOT NULL AND previous_valid_until <= ?1`,
  ).bind(isoAt(at)).run();
  return r.meta.changes ?? 0;
}

/** Statement that replaces a write-only secret value outright (no overlap: the old value is not kept). */
export async function prepareSetSecret(env: Env, row: SecretRow, newPlaintext: string): Promise<D1PreparedStatement> {
  const key = await masterKey(env.EXP_MASTER_KEY);
  const version = row.version + 1;
  const sealed = await seal(key, newPlaintext, secretAad(row.secret_id, row.kind, version));
  return env.DB.prepare(
    `UPDATE secrets SET ciphertext = ?1, nonce = ?2, version = ?3, previous_ciphertext = NULL, previous_nonce = NULL,
       previous_version = NULL, previous_hash = NULL, previous_valid_until = NULL, updated_at = ?4
     WHERE secret_id = ?5 AND version = ?6`,
  ).bind(sealed.ciphertext, sealed.nonce, version, isoNow(), row.secret_id, row.version);
}
