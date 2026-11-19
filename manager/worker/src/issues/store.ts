// Issue rows -> API objects, listing with filters, snoozes.
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { ApiError, invalidRequest, notFound } from "../errors";
import { auditStmt } from "../audit/audit";
import { ISSUE_ID_RE } from "../util/ids";
import { isoNow, isoPlusSeconds } from "../util/time";
import { decodeCursor, encodeCursor } from "../util/cursor";
import { ISSUE_KINDS } from "./rules";
import { VISIBLE_OPEN_SQL } from "./visibility";

export interface IssueRow {
  issue_id: string;
  kind: string;
  severity: "warn" | "crit";
  host_id: string;
  component_id: string | null;
  component_type?: string | null;
  site: string;
  opened_at: string;
  resolved_at: string | null;
  last_value: number | null;
  detail: string;
  snoozed_until?: string | null;
  [k: string]: unknown;
}

export function issueOut(r: Record<string, unknown>): Record<string, unknown> {
  const o: Record<string, unknown> = {
    issue_id: r.issue_id,
    kind: r.kind,
    severity: r.severity,
    host_id: r.host_id,
    component_id: r.component_id ?? null,
    component_type: r.component_type ?? null,
    site: r.site,
    opened_at: r.opened_at,
    resolved_at: r.resolved_at ?? null,
    last_value: r.last_value ?? null,
    detail: r.detail ?? "",
  };
  if (r.snoozed_until !== undefined) o.snoozed_until = r.snoozed_until;
  return o;
}

export interface IssueQuery {
  severity?: string;
  site?: string;
  kind?: string;
  state?: string;
  limit?: number;
  cursor?: string;
  include_snoozed?: boolean;
}

export async function listIssues(env: Env, q: IssueQuery) {
  if (q.severity && q.severity !== "warn" && q.severity !== "crit") throw invalidRequest("severity must be warn or crit");
  if (q.kind && !(ISSUE_KINDS as readonly string[]).includes(q.kind)) throw invalidRequest("unknown issue kind");
  const state = q.state ?? "open";
  if (state !== "open" && state !== "resolved") throw invalidRequest("state must be open or resolved");
  const limit = Math.min(Math.max(q.limit ?? 100, 1), 1000);
  const cur = decodeCursor<{ id: string }>(q.cursor);
  const now = isoNow();
  const where: string[] = [];
  const args: unknown[] = [now];
  const add = (sql: string, v: unknown) => {
    args.push(v);
    where.push(sql.replace("?", `?${args.length}`));
  };
  if (state === "open") {
    where.push(q.include_snoozed ? "i.resolved_at IS NULL" : VISIBLE_OPEN_SQL);
    if (q.include_snoozed) where.push("(i.kind = 'host_offline' OR NOT EXISTS (SELECT 1 FROM issues o WHERE o.host_id = i.host_id AND o.kind = 'host_offline' AND o.resolved_at IS NULL))");
  } else where.push("i.resolved_at IS NOT NULL");
  if (q.severity) add("i.severity = ?", q.severity);
  if (q.site) add("i.site = ?", q.site);
  if (q.kind) add("i.kind = ?", q.kind);
  if (cur?.id) add("i.issue_id < ?", String(cur.id));
  args.push(limit + 1);
  const sql = `SELECT i.*, (SELECT CASE WHEN s.until_resolved = 1 THEN 'resolved' ELSE s.until END FROM issue_snoozes s
                            WHERE s.host_id = i.host_id AND s.kind = i.kind AND (s.until_resolved = 1 OR s.until > ?1)) AS snoozed_until
               FROM issues i WHERE ${where.join(" AND ")} ORDER BY i.issue_id DESC LIMIT ?${args.length}`;
  const rows = (await env.DB.prepare(sql).bind(...args).all<Record<string, unknown>>()).results ?? [];
  const page = rows.slice(0, limit);
  return {
    items: page.map((r) => (q.include_snoozed || state === "resolved" ? issueOut(r) : issueOut({ ...r, snoozed_until: undefined }))),
    next_cursor: rows.length > limit ? encodeCursor({ id: page[page.length - 1]?.issue_id }) : null,
  };
}

const SNOOZE_FOR: Record<string, number | "resolved"> = { "1h": 3600, "24h": 86400, resolved: "resolved" };

export async function snoozeIssue(env: Env, actorEmail: string, ip: string | null, issueId: string, forWhat: string) {
  if (!ISSUE_ID_RE.test(issueId)) throw notFound("no such issue");
  const spec = SNOOZE_FOR[forWhat];
  if (spec === undefined) throw invalidRequest("for must be one of 1h, 24h, resolved");
  const issue = await env.DB.prepare("SELECT issue_id, kind, host_id, resolved_at FROM issues WHERE issue_id = ?1").bind(issueId).first<{ issue_id: string; kind: string; host_id: string; resolved_at: string | null }>();
  if (!issue) throw notFound("no such issue");
  if (issue.resolved_at) throw new ApiError(409, "conflict", "issue is already resolved");
  const now = isoNow();
  const until = spec === "resolved" ? null : isoPlusSeconds(spec);
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO issue_snoozes (org_id, kind, host_id, until, until_resolved, created_by, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
       ON CONFLICT(host_id, kind) DO UPDATE SET until = excluded.until, until_resolved = excluded.until_resolved,
         created_by = excluded.created_by, updated_at = excluded.updated_at`,
    ).bind(DEFAULT_ORG, issue.kind, issue.host_id, until, spec === "resolved" ? 1 : 0, actorEmail, now),
    auditStmt(env.DB, { actor: actorEmail, action: "issue.snooze", resource: `host:${issue.host_id}`, details: { issue_id: issueId, kind: issue.kind, for: forWhat }, ip }),
  ]);
  return { issue_id: issueId, kind: issue.kind, host_id: issue.host_id, until: until ?? "resolved", created_by: actorEmail };
}

export async function unsnoozeIssue(env: Env, actorEmail: string, ip: string | null, issueId: string): Promise<void> {
  if (!ISSUE_ID_RE.test(issueId)) throw notFound("no such issue");
  const issue = await env.DB.prepare("SELECT kind, host_id FROM issues WHERE issue_id = ?1").bind(issueId).first<{ kind: string; host_id: string }>();
  if (!issue) throw notFound("no such issue");
  const has = await env.DB.prepare("SELECT 1 AS x FROM issue_snoozes WHERE host_id = ?1 AND kind = ?2").bind(issue.host_id, issue.kind).first();
  if (!has) throw notFound("issue is not snoozed");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM issue_snoozes WHERE host_id = ?1 AND kind = ?2").bind(issue.host_id, issue.kind),
    auditStmt(env.DB, { actor: actorEmail, action: "issue.unsnooze", resource: `host:${issue.host_id}`, details: { issue_id: issueId, kind: issue.kind }, ip }),
  ]);
}
