// EXP_MASTER_KEY rotation: re-encrypt everything sealed by EXP_MASTER_KEY_PREVIOUS (or unstamped legacy rows) under the
// current key, in bounded batches driven by the 5-minute cron, and report progress read-only (05-manager.md section 6).
//
// Atomic per row: every UPDATE is guarded by the key_id (and ciphertext) it read, so a concurrent rotation / recompile
// that rewrote the row wins and the batch simply skips it (it is picked up again, or is already current).
// Plaintext only ever exists in memory. Rows stamped with an unknown key id are never touched (fail closed): they are
// reported as `unknown_key_rows` so the operator can set EXP_MASTER_KEY_PREVIOUS to the right key.
import { auditStmt } from "../audit/audit";
import type { Env } from "../env";
import { credAad, credKeyId, isEncryptedCred, keyRing, openCredWithKey, openWithRing, seal, sealCred, secretAad, type KeyRing } from "./crypto";

export const REKEY_BATCH = 200;

export interface MasterKeyStatus {
  current_key_id: string;
  previous_key_id: string | null;
  /** values still sealed by the previous key (or unstamped legacy values): secrets, their previous_* values, desired docs */
  remaining_previous: number;
  /** values stamped with a key id that is neither the current nor the previous key (unreadable until that key is supplied) */
  unknown_key_rows: number;
  /** true when EXP_MASTER_KEY_PREVIOUS can be deleted without making any stored value unreadable */
  safe_to_remove_previous: boolean;
}

const n = async (env: Env, sql: string, ...args: unknown[]): Promise<number> =>
  (await env.DB.prepare(sql).bind(...args).first<{ n: number }>())?.n ?? 0;

export async function masterKeyStatus(env: Env, ring?: KeyRing): Promise<MasterKeyStatus> {
  const r = ring ?? (await keyRing(env));
  const cur = r.current.id;
  const prev = r.previous?.id ?? "";
  // "stale" = unstamped legacy or sealed by the previous key; "unknown" = stamped with any other key
  const stale = (col: string) => `(${col} IS NULL OR ${col} = ?1)`;
  const unk = (col: string) => `(${col} IS NOT NULL AND ${col} != ?1 AND ${col} != ?2)`;
  const remaining =
    (await n(env, `SELECT COUNT(*) AS n FROM secrets WHERE ${stale("key_id")}`, prev)) +
    (await n(env, `SELECT COUNT(*) AS n FROM secrets WHERE previous_ciphertext IS NOT NULL AND ${stale("previous_key_id")}`, prev)) +
    (await n(env, `SELECT COUNT(*) AS n FROM desired_docs WHERE ${stale("key_id")}`, prev));
  const unknown =
    (await n(env, `SELECT COUNT(*) AS n FROM secrets WHERE ${unk("key_id")}`, cur, prev)) +
    (await n(env, `SELECT COUNT(*) AS n FROM secrets WHERE previous_ciphertext IS NOT NULL AND ${unk("previous_key_id")}`, cur, prev)) +
    (await n(env, `SELECT COUNT(*) AS n FROM desired_docs WHERE ${unk("key_id")}`, cur, prev));
  return {
    current_key_id: cur,
    previous_key_id: r.previous?.id ?? null,
    remaining_previous: remaining,
    unknown_key_rows: unknown,
    safe_to_remove_previous: remaining === 0 && unknown === 0,
  };
}

interface Row {
  [k: string]: unknown;
}

export interface RekeyResult {
  rewritten: number;
  failed: number;
  status: MasterKeyStatus;
}

/** Re-encrypt up to `limit` rows (all three kinds share the budget). Safe to run concurrently and repeatedly. */
export async function rekeyBatch(env: Env, limit: number = REKEY_BATCH): Promise<RekeyResult> {
  const ring = await keyRing(env);
  const cur = ring.current.id;
  const prev = ring.previous?.id ?? "";
  let budget = limit;
  let rewritten = 0;
  let failed = 0;

  // 1. current values
  if (budget > 0) {
    const rows = (await env.DB.prepare(
      "SELECT secret_id, kind, version, ciphertext, nonce, key_id FROM secrets WHERE key_id IS NULL OR key_id = ?1 ORDER BY secret_id LIMIT ?2",
    ).bind(prev, budget).all<Row>()).results ?? [];
    budget -= rows.length;
    for (const r of rows) {
      try {
        const aad = secretAad(String(r.secret_id), String(r.kind), Number(r.version));
        const opened = await openWithRing(ring, { nonce: String(r.nonce), ciphertext: String(r.ciphertext) }, aad, r.key_id as string | null);
        let res;
        if (opened.keyId === cur) {
          // legacy row that already opens under the current key: only stamp it
          res = await env.DB.prepare("UPDATE secrets SET key_id = ?1 WHERE secret_id = ?2 AND ciphertext = ?3 AND key_id IS ?4").bind(cur, r.secret_id, r.ciphertext, r.key_id ?? null).run();
        } else {
          const s = await seal(ring.current.key, opened.plaintext, aad);
          res = await env.DB.prepare("UPDATE secrets SET ciphertext = ?1, nonce = ?2, key_id = ?3 WHERE secret_id = ?4 AND ciphertext = ?5 AND key_id IS ?6")
            .bind(s.ciphertext, s.nonce, cur, r.secret_id, r.ciphertext, r.key_id ?? null).run();
        }
        if ((res.meta.changes ?? 0) === 1) rewritten++;
      } catch (e) {
        failed++;
        console.warn("rekey: secret not re-encrypted", e instanceof Error ? e.name : "error");
      }
    }
  }

  // 2. previous_* values still inside their rotation grace window
  if (budget > 0) {
    const rows = (await env.DB.prepare(
      `SELECT secret_id, kind, previous_version, previous_ciphertext, previous_nonce, previous_key_id FROM secrets
       WHERE previous_ciphertext IS NOT NULL AND (previous_key_id IS NULL OR previous_key_id = ?1) ORDER BY secret_id LIMIT ?2`,
    ).bind(prev, budget).all<Row>()).results ?? [];
    budget -= rows.length;
    for (const r of rows) {
      try {
        const aad = secretAad(String(r.secret_id), String(r.kind), Number(r.previous_version));
        const opened = await openWithRing(ring, { nonce: String(r.previous_nonce), ciphertext: String(r.previous_ciphertext) }, aad, r.previous_key_id as string | null);
        let res;
        if (opened.keyId === cur) {
          res = await env.DB.prepare("UPDATE secrets SET previous_key_id = ?1 WHERE secret_id = ?2 AND previous_ciphertext = ?3 AND previous_key_id IS ?4").bind(cur, r.secret_id, r.previous_ciphertext, r.previous_key_id ?? null).run();
        } else {
          const s = await seal(ring.current.key, opened.plaintext, aad);
          res = await env.DB.prepare(
            "UPDATE secrets SET previous_ciphertext = ?1, previous_nonce = ?2, previous_key_id = ?3 WHERE secret_id = ?4 AND previous_ciphertext = ?5 AND previous_key_id IS ?6",
          ).bind(s.ciphertext, s.nonce, cur, r.secret_id, r.previous_ciphertext, r.previous_key_id ?? null).run();
        }
        if ((res.meta.changes ?? 0) === 1) rewritten++;
      } catch (e) {
        failed++;
        console.warn("rekey: previous secret value not re-encrypted", e instanceof Error ? e.name : "error");
      }
    }
  }

  // 3. credentials inside the compiled desired documents (re-sealed in place: the served plaintext, hash and version do not change)
  if (budget > 0) {
    const rows = (await env.DB.prepare("SELECT host_id, version, doc_json, key_id FROM desired_docs WHERE key_id IS NULL OR key_id = ?1 ORDER BY host_id LIMIT ?2")
      .bind(prev, budget).all<Row>()).results ?? [];
    budget -= rows.length;
    for (const r of rows) {
      try {
        const doc = JSON.parse(String(r.doc_json)) as { host_id: string; components?: Array<{ component_id: string; creds?: Record<string, string> }> };
        for (const c of doc.components ?? []) {
          for (const [name, value] of Object.entries(c.creds ?? {})) {
            if (!isEncryptedCred(value) || credKeyId(value) === cur) continue;
            const aad = credAad(doc.host_id, c.component_id, name);
            const opened = await openCredWithKey(ring, value, aad);
            c.creds![name] = await sealCred(ring, opened.plaintext, aad);
          }
        }
        const res = await env.DB.prepare("UPDATE desired_docs SET doc_json = ?1, key_id = ?2 WHERE host_id = ?3 AND version = ?4 AND key_id IS ?5")
          .bind(JSON.stringify(doc), cur, r.host_id, r.version, r.key_id ?? null).run();
        if ((res.meta.changes ?? 0) === 1) rewritten++;
      } catch (e) {
        failed++;
        console.warn("rekey: desired document not re-encrypted", e instanceof Error ? e.name : "error");
      }
    }
  }

  const status = await masterKeyStatus(env, ring);
  if (rewritten > 0) {
    await auditStmt(env.DB, {
      actor: "system",
      action: "master_key.reencrypt",
      resource: "settings:master-key",
      details: { rewritten, failed, remaining_previous: status.remaining_previous, current_key_id: status.current_key_id, previous_key_id: status.previous_key_id, complete: status.safe_to_remove_previous },
    }).run();
  }
  return { rewritten, failed, status };
}
