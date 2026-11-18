// Scheduled handlers (05-manager.md section 11). Each job is isolated: one failing job never blocks the rest.
//   */5 * * * *  expire enrol tokens, staleness/offline issues, canary promotion, drop previous_* secrets
//                past grace, prune status_history, retire consumed restart actions
//   0 * * * *    compact completed 5-minute roll-ups into 1-hour buckets, prune roll-ups and resolved issues
//   0 3 * * *    prune the audit log, report orphaned R2 objects
import { auditStmt } from "../audit/audit";
import { recompile } from "../compile/recompile";
import { parseJson } from "../compile/load";
import type { Env } from "../env";
import { compactHours, pruneRollups } from "../fleet/rollup";
import { evaluateStaleness, pruneIssues } from "../issues/engine";
import { evaluateCanaries } from "../releases/rollout";
import { dropExpiredPrevious } from "../secrets/store";
import { ulidTimeMs } from "../util/ids";
import { isoAt, nowMs } from "../util/time";

export const STATUS_HISTORY_MAX_AGE_S = 7 * 86400;
export const ACTION_TTL_S = 15 * 60;
export const AUDIT_KEEP_DAYS = 365;

async function job(name: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (e) {
    console.error(`cron job ${name} failed`, e instanceof Error ? e.name : "error");
  }
}

/** Restart / diagnostics actions are executed once per id by the agent; retire them after 15 minutes. */
export async function retireActions(env: Env, now: number): Promise<number> {
  const rows = (await env.DB.prepare("SELECT host_id, actions_json FROM hosts WHERE actions_json != '[]'").all<{ host_id: string; actions_json: string }>()).results ?? [];
  const touched: string[] = [];
  for (const h of rows) {
    const actions = parseJson<Array<{ id: string; type: string }>>(h.actions_json, []);
    const keep = actions.filter((a) => {
      if (a.type === "rotate_agent_secret") return true; // consumed by POST rotate, not by age
      const t = ulidTimeMs(a.id);
      return t === null || now - t < ACTION_TTL_S * 1000;
    });
    if (keep.length !== actions.length) {
      await env.DB.prepare("UPDATE hosts SET actions_json = ?2, updated_at = ?3 WHERE host_id = ?1").bind(h.host_id, JSON.stringify(keep), isoAt(now)).run();
      touched.push(h.host_id);
    }
  }
  if (touched.length) await recompile(env, { hostIds: touched });
  return touched.length;
}

export async function runEveryFiveMinutes(env: Env, now: number = nowMs()): Promise<void> {
  const iso = isoAt(now);
  await job("enrol_tokens", () => env.DB.prepare("DELETE FROM enrol_tokens WHERE used_at IS NULL AND expires_at < ?1").bind(iso).run());
  await job("secrets_grace", async () => {
    const dropped = await dropExpiredPrevious(env, now);
    await env.DB.prepare(
      "UPDATE agent_creds SET previous_hash = NULL, previous_valid_until = NULL WHERE previous_valid_until IS NOT NULL AND previous_valid_until <= ?1",
    ).bind(iso).run();
    // a collector's verifier list is [current, previous] only while the overlap lasts: publish the shrunk list, or the old
    // token would stay valid at the collector until some unrelated change recompiled (found by the A2.6 e2e)
    if (dropped > 0) await recompile(env, { all: true });
  });
  await job("staleness", () => evaluateStaleness(env, now));
  await job("canary", () => evaluateCanaries(env, now));
  await job("status_history", () =>
    env.DB.prepare("DELETE FROM status_history WHERE received_at < ?1").bind(isoAt(now - STATUS_HISTORY_MAX_AGE_S * 1000)).run(),
  );
  await job("actions", () => retireActions(env, now));
}

export async function runHourly(env: Env, now: number = nowMs()): Promise<void> {
  await job("compaction", () => compactHours(env, now));
  await job("prune_rollups", () => pruneRollups(env, now));
  await job("prune_issues", () => pruneIssues(env, now));
}

/** Objects older than a day that no row references: reported (never deleted automatically). */
export async function orphanedR2(env: Env, now: number): Promise<{ count: number; sample: string[] }> {
  const known = new Set<string>();
  for (const r of (await env.DB.prepare("SELECT r2_key AS k FROM artifacts UNION SELECT manifest_r2_key AS k FROM releases").all<{ k: string }>()).results ?? []) {
    known.add(r.k);
    known.add(`${r.k}.sig`); // scripts/publish-release.sh stores the detached signature next to the manifest
  }
  const orphans: string[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 50; page++) {
    const l = await env.ARTIFACTS.list({ cursor, limit: 1000 });
    for (const o of l.objects) {
      if (!known.has(o.key) && now - o.uploaded.getTime() > 86400_000) orphans.push(o.key);
    }
    if (!l.truncated) break;
    cursor = l.cursor;
  }
  return { count: orphans.length, sample: orphans.slice(0, 20) };
}

export async function runDaily(env: Env, now: number = nowMs()): Promise<void> {
  await job("audit_prune", async () => {
    const days = Number.parseInt(env.AUDIT_RETENTION_DAYS ?? "", 10);
    const keep = Number.isFinite(days) && days >= 30 ? days : AUDIT_KEEP_DAYS;
    await env.DB.prepare("DELETE FROM audit WHERE ts < ?1").bind(isoAt(now - keep * 86400_000)).run();
  });
  await job("r2_orphans", async () => {
    const o = await orphanedR2(env, now);
    if (o.count > 0) {
      console.warn("orphaned R2 objects", o.count);
      await auditStmt(env.DB, { actor: "system", action: "r2.orphans", resource: "r2:artifacts", details: { count: o.count, sample: o.sample } }).run();
    }
  });
}

export async function runScheduled(env: Env, cron: string): Promise<void> {
  switch (cron) {
    case "*/5 * * * *":
      return runEveryFiveMinutes(env);
    case "0 * * * *":
      return runHourly(env);
    case "0 3 * * *":
      return runDaily(env);
    default:
      console.warn("cron: unknown schedule", cron);
  }
}

