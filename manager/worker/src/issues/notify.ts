// Platform webhook (05-manager.md section 14): Slack / Teams / JSON, URL stored as a secret. It fires on
// `crit` open (including warn -> crit escalation) and on resolve of a crit issue that was announced;
// snoozed or suppressed issues never fire. Delivery failures are logged (no URL) and never break ingestion.
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { getSecretRow, readSecret } from "../secrets/store";
import { type WebhookFormat, payloadFor, postWebhook } from "../notify/webhook";
import type { IssueRow } from "./store";

export const PLATFORM_OWNER = "platform";
export const PLATFORM_KIND = "platform_webhook_url";

export interface PlatformTarget {
  url: string;
  format: WebhookFormat;
}

export async function platformTarget(env: Env): Promise<PlatformTarget | null> {
  const s = await env.DB.prepare("SELECT platform_webhook_secret_id AS id, platform_webhook_format AS fmt FROM settings WHERE org_id = ?1")
    .bind(DEFAULT_ORG)
    .first<{ id: string | null; fmt: string }>();
  if (!s?.id) return null;
  const row = await getSecretRow(env, s.id);
  if (!row) return null;
  const fmt = s.fmt === "slack" || s.fmt === "teams" ? s.fmt : "json";
  return { url: await readSecret(env, row), format: fmt };
}

export type IssueEvent = { type: "open" | "resolved"; issue: IssueRow; hostName?: string };

export function messageFor(ev: IssueEvent): string {
  const i = ev.issue;
  const head = ev.type === "open" ? `[${i.severity.toUpperCase()}]` : "[RESOLVED]";
  return `${head} ${i.kind} on ${ev.hostName ?? i.host_id} (site ${i.site}): ${i.detail}`.slice(0, 400);
}

/** Returns true when a delivery was attempted and succeeded. */
export async function notifyPlatform(env: Env, ev: IssueEvent): Promise<boolean> {
  if (ev.issue.severity !== "crit") return false;
  try {
    const t = await platformTarget(env);
    if (!t) return false;
    const host = await env.DB.prepare("SELECT name FROM hosts WHERE host_id = ?1").bind(ev.issue.host_id).first<{ name: string }>();
    const e = { ...ev, hostName: host?.name };
    const i = ev.issue;
    const res = await postWebhook(
      t.url,
      payloadFor(t.format, messageFor(e), {
        event: ev.type === "open" ? "issue.opened" : "issue.resolved",
        issue: { id: i.issue_id, kind: i.kind, severity: i.severity, host_id: i.host_id, host: host?.name ?? null, site: i.site, detail: i.detail, opened_at: i.opened_at, resolved_at: i.resolved_at },
      }),
    );
    if (!res.ok) console.warn("platform webhook delivery failed", res.http_status ?? res.error);
    return res.ok;
  } catch (e) {
    console.warn("platform webhook error", e instanceof Error ? e.name : "error");
    return false;
  }
}
