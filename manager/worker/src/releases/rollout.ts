// Canary rollout (05-manager.md section 9). PATCH sites/{site}/release with a canary host compiles the new
// version for that host only. This cron-driven evaluation then:
//   - PROMOTES the target to the whole site after the canary's components reported healthy for 10 minutes
//   - FAILS the canary (halts the rollout, visible as canary_state=failed + audit) when the canary host
//     rolled back / failed to reconcile, a component is in `fail` after applying, or the host went offline
// Rollback = set the previous version (admin/service.setSiteRelease).
import { auditStmt } from "../audit/audit";
import { recompile } from "../compile/recompile";
import { parseJson } from "../compile/load";
import type { Env } from "../env";
import { isoAt, nowMs } from "../util/time";

export const CANARY_HEALTHY_HOLD_S = 600;

interface SiteRow {
  site: string;
  target_version: string;
  canary_host_id: string;
  canary_started_at: string | null;
  canary_healthy_since: string | null;
}

export interface CanaryOutcome {
  site: string;
  result: "waiting" | "healthy" | "promoted" | "failed";
}

export async function evaluateCanaries(env: Env, now: number = nowMs()): Promise<CanaryOutcome[]> {
  const sites = (
    await env.DB.prepare(
      "SELECT site, target_version, canary_host_id, canary_started_at, canary_healthy_since FROM sites WHERE canary_state = 'canary' AND target_version IS NOT NULL AND canary_host_id IS NOT NULL",
    ).all<SiteRow>()
  ).results ?? [];
  const out: CanaryOutcome[] = [];
  const nowIso = isoAt(now);
  for (const s of sites) {
    const host = await env.DB.prepare("SELECT state, last_seen, desired_version, applied_version FROM hosts WHERE host_id = ?1").bind(s.canary_host_id).first<{
      state: string;
      last_seen: string | null;
      desired_version: number | null;
      applied_version: number | null;
    }>();
    const comps = (await env.DB.prepare("SELECT facts_json, enabled FROM components WHERE host_id = ?1").bind(s.canary_host_id).all<{ facts_json: string; enabled: number }>()).results ?? [];
    const latest = await env.DB.prepare("SELECT report_json, received_at FROM status_latest WHERE host_id = ?1").bind(s.canary_host_id).first<{ report_json: string; received_at: string }>();
    const started = s.canary_started_at ? Date.parse(s.canary_started_at) : 0;
    const health = comps.filter((c) => c.enabled === 1).map((c) => parseJson<{ health?: string; version?: string | null }>(c.facts_json, {}));
    const rec = parseJson<{ reconcile?: { result?: string; at?: string } | null }>(latest?.report_json, {}).reconcile;
    const reconcileBad =
      !!rec && (rec.result === "error" || rec.result === "rolled_back") && !!latest && Date.parse(latest.received_at) >= started;
    const applied = !!host && host.desired_version !== null && host.applied_version === host.desired_version;
    const anyFail = applied && health.some((h) => h.health === "fail");
    const offline = !host || host.state === "offline" || host.state === "decommissioning" || host.state === "removed";

    if (reconcileBad || anyFail || offline) {
      const reason = reconcileBad ? "the canary host rolled back or failed to reconcile" : anyFail ? "a canary component is failing" : "the canary host is offline";
      await env.DB.batch([
        env.DB.prepare("UPDATE sites SET canary_state = 'failed', canary_healthy_since = NULL, updated_at = ?2 WHERE site = ?1 AND canary_state = 'canary'").bind(s.site, nowIso),
        auditStmt(env.DB, { actor: "system", action: "site.canary_failed", resource: `site:${s.site}`, details: { version: s.target_version, reason, host_id: s.canary_host_id } }),
      ]);
      out.push({ site: s.site, result: "failed" });
      continue;
    }

    const seenAfterStart = !!host?.last_seen && Date.parse(host.last_seen) >= started;
    const healthy = !!host && host.state === "enrolled" && applied && seenAfterStart && health.every((h) => h.health === "ok");
    if (!healthy) {
      if (s.canary_healthy_since) await env.DB.prepare("UPDATE sites SET canary_healthy_since = NULL, updated_at = ?2 WHERE site = ?1").bind(s.site, nowIso).run();
      out.push({ site: s.site, result: "waiting" });
      continue;
    }
    if (!s.canary_healthy_since) {
      await env.DB.prepare("UPDATE sites SET canary_healthy_since = ?2, updated_at = ?2 WHERE site = ?1").bind(s.site, nowIso).run();
      out.push({ site: s.site, result: "healthy" });
      continue;
    }
    if (now - Date.parse(s.canary_healthy_since) >= CANARY_HEALTHY_HOLD_S * 1000) {
      const r = await env.DB.prepare(
        `UPDATE sites SET release_version = target_version, target_version = NULL, canary_state = 'promoted', canary_healthy_since = NULL, updated_at = ?2
         WHERE site = ?1 AND canary_state = 'canary' AND target_version = ?3`,
      ).bind(s.site, nowIso, s.target_version).run();
      if ((r.meta.changes ?? 0) === 1) {
        await auditStmt(env.DB, { actor: "system", action: "site.promote", resource: `site:${s.site}`, details: { version: s.target_version, auto: true } }).run();
        await recompile(env, { sites: [s.site] });
      }
      out.push({ site: s.site, result: "promoted" });
    } else out.push({ site: s.site, result: "healthy" });
  }
  return out;
}
