// Latest per-probe rows of a collector (CR-wp5-fleet-api-gaps item 2): the collector's health metrics carry a bounded
// `probes[]`; the latest rows are kept per collector component (no history) and served by
// GET /fleet/components/{id}/probes.
import type { StatusReport } from "../agent/status-schema";
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { sanitizeProbeRows } from "./query";

export async function recordProbeRows(
  env: Env,
  receivedAt: string,
  report: StatusReport,
  components: Array<{ component_id: string; type: string; slug: string }>,
): Promise<void> {
  const byKey = new Map(components.map((c) => [`${c.type}/${c.slug}`, c]));
  const stmts: D1PreparedStatement[] = [];
  for (const rc of report.components) {
    if (rc.type !== "collector") continue;
    const row = byKey.get(`${rc.type}/${rc.id}`);
    if (!row) continue;
    const rows = sanitizeProbeRows(rc.metrics?.probes);
    if (rows === null) {
      // an older collector (or one that stopped reporting the array): nothing stale is kept
      stmts.push(env.DB.prepare("DELETE FROM component_probes_latest WHERE component_id = ?1").bind(row.component_id));
      continue;
    }
    stmts.push(
      env.DB.prepare(
        `INSERT INTO component_probes_latest (component_id, org_id, reported_at, probes_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?3, ?3)
         ON CONFLICT(component_id) DO UPDATE SET reported_at = excluded.reported_at, probes_json = excluded.probes_json, updated_at = excluded.updated_at`,
      ).bind(row.component_id, DEFAULT_ORG, receivedAt, JSON.stringify(rows)),
    );
  }
  if (stmts.length) await env.DB.batch(stmts);
}
