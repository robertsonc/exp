// Audit log (05-manager.md section 3). Exactly one event per mutation, never with secret values.
// Callers add `auditStmt(...)` to the same db.batch() as the mutation so both commit or neither does.
import { DEFAULT_ORG } from "../env";
import { newId } from "../util/ids";
import { isoNow } from "../util/time";

export interface AuditEvent {
  actor: string; // admin email, `agent:h_...`, or `system`
  action: string; // e.g. host.enrol, agent.rotate
  resource: string; // e.g. host:h_..., site:hall-b
  details?: Record<string, unknown>;
  ip?: string | null;
}

const TOKEN_RE = /exp[aeidnsrlktv]_[A-Za-z0-9_-]{8,}/g;
const URL_SECRET_RE = /https?:\/\/(hooks|[^\s"']*webhook)[^\s"']*/gi;
const SECRET_KEY_RE = /(secret|token|password|passwd|credential|api_?key|private|ciphertext|authorization|url)/i;

/** Defence in depth: drop secret-looking keys and mask token / webhook patterns before storing. */
export function scrub(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[truncated]";
  if (typeof value === "string") {
    const s = value.replace(TOKEN_RE, "[redacted]").replace(URL_SECRET_RE, "[redacted]");
    return s.length > 512 ? s.slice(0, 512) + "..." : s;
  }
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => scrub(v, depth + 1));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      // flags such as `secret_set: true` are fine; values under secret-ish keys are dropped
      if (SECRET_KEY_RE.test(k) && typeof v !== "boolean" && typeof v !== "number") {
        out[k] = "[redacted]";
      } else {
        out[k] = scrub(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}

export function auditStmt(db: D1Database, e: AuditEvent): D1PreparedStatement {
  const now = isoNow();
  return db
    .prepare(
      `INSERT INTO audit (evt_id, org_id, ts, actor, action, resource, details_json, ip, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?3, ?3)`,
    )
    .bind(newId("evt_"), DEFAULT_ORG, now, e.actor, e.action, e.resource, JSON.stringify(scrub(e.details ?? {})), e.ip ?? null);
}

export async function writeAudit(db: D1Database, e: AuditEvent): Promise<void> {
  await auditStmt(db, e).run();
}
