// Intent mutations added in step 2: site/host edits and deletes, restart, probe ports, user delete, alerts,
// integrations, settings, thresholds, platform webhook. Same rules as service.ts: validate, ONE batch with
// exactly one audit event, then recompile what changed. Secrets are write-only and encrypted.
import { z } from "zod";
import { auditStmt } from "../audit/audit";
import { ensureSettings, parseJson } from "../compile/load";
import { recompile } from "../compile/recompile";
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { ApiError, invalidRequest, notFound, unavailable } from "../errors";
import { ConfigError } from "../errors";
import { type WebhookFormat, payloadFor, postWebhook, validateWebhookUrl } from "../notify/webhook";
import { mergeThresholds, ThresholdsSchema } from "../issues/thresholds";
import { PLATFORM_KIND, PLATFORM_OWNER, platformTarget } from "../issues/notify";
import { WEBHOOK_KIND } from "../compile/wiring";
import { getSecretByOwner, getSecretRow, prepareCreateSecret, prepareSetSecret, readSecret } from "../secrets/store";
import { COMPONENT_ID_RE, HOST_ID_RE, SLUG_RE, newId, NOC_ID_RE, USR_ID_RE } from "../util/ids";
import { isoNow } from "../util/time";
import type { Actor } from "./service";

const IFACE_RE = /^[A-Za-z0-9_.:-]{1,15}$/;
const IPV4 = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/;
const IPV4_CIDR = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\/(3[0-2]|[12]?[0-9])$/;
const TZ_RE = /^(UTC|[A-Za-z]+(\/[A-Za-z0-9_+-]+){1,2})$/;
const HTTPS_URL = /^https:\/\/[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(\/[^\s]*)?$/;

const slugS = z.string().regex(SLUG_RE);
const base = { id: slugS, iface: z.string().regex(IFACE_RE) };
export const PortSchema = z.discriminatedUnion("role", [
  z.object({
    ...base,
    role: z.literal("client"),
    vlan: z.number().int().min(1).max(4094).nullable().optional(),
    dhcp: z
      .object({
        hostname: z.string().regex(/^[A-Za-z0-9]([A-Za-z0-9-]{0,62})$/).optional(),
        vendor_class: z.string().max(64).regex(/^[A-Za-z0-9._-]*$/).optional(),
        client_id: z.enum(["mac", "hostname"]).optional(),
      })
      .strict()
      .optional(),
  }).strict(),
  z.object({
    ...base,
    role: z.literal("target"),
    address: z.string().regex(IPV4_CIDR),
    gateway: z.string().regex(IPV4),
    serve: z
      .object({ http: z.boolean(), https: z.boolean(), icmp: z.boolean(), reflector: z.boolean(), iperf3: z.boolean() })
      .partial()
      .strict()
      .optional(),
    faults_allowed: z.boolean().optional(),
  }).strict(),
  z.object({
    ...base,
    role: z.literal("wifi"),
    ssid: z.string().min(1).max(32).regex(/^[^\x00-\x1f\x7f]*$/),
    band: z.enum(["2.4", "5", "6", "any"]).optional(),
  }).strict(),
]);
export type Port = z.infer<typeof PortSchema>;

interface FactIface {
  name?: string;
  state?: string;
  default_route?: boolean;
  in_use_by?: string;
}

/**
 * Validates probe ports against the host's reported interfaces: unknown interfaces and the management /
 * default-route interface are refused (SR-18: preflight never touches the mgmt interface).
 */
export async function validateProbePorts(env: Env, hostId: string, componentId: string | null, mgmtOverride: unknown, rawPorts: unknown): Promise<Port[]> {
  const parsed = z.array(PortSchema).min(0).max(64).safeParse(rawPorts);
  if (!parsed.success) {
    throw new ApiError(422, "invalid_ports", "ports failed validation", {
      errors: parsed.error.issues.slice(0, 10).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })),
    });
  }
  const ports = parsed.data;
  if (ports.length === 0) return ports;
  const host = await env.DB.prepare("SELECT facts_json FROM hosts WHERE host_id = ?1").bind(hostId).first<{ facts_json: string }>();
  const ifaces = parseJson<{ interfaces?: FactIface[] }>(host?.facts_json, {}).interfaces ?? [];
  if (ifaces.length === 0) throw new ApiError(422, "no_host_facts", "the host has not reported its interfaces yet; enrol it first");
  const mgmt = new Set<string>();
  for (const i of ifaces) if (i.name && (i.default_route === true || i.in_use_by === "mgmt")) mgmt.add(i.name);
  if (typeof mgmtOverride === "string" && mgmtOverride) mgmt.add(mgmtOverride);
  const known = new Set(ifaces.map((i) => i.name));
  const ids = new Set<string>();
  const used = new Set<string>();
  for (const p of ports) {
    if (mgmt.has(p.iface)) throw new ApiError(422, "mgmt_interface_refused", `interface ${p.iface} is the management interface (default route) and cannot be a test port`, { iface: p.iface });
    if (!known.has(p.iface)) throw new ApiError(422, "unknown_interface", `interface ${p.iface} does not exist on this host`, { iface: p.iface, known: [...known].slice(0, 32) });
    if (ids.has(p.id)) throw new ApiError(422, "duplicate_port", `port id ${p.id} is used twice`);
    if (used.has(p.iface)) throw new ApiError(422, "duplicate_port", `interface ${p.iface} is assigned to two ports`);
    ids.add(p.id);
    used.add(p.iface);
  }
  const others = (
    await env.DB.prepare("SELECT component_id, slug, config_json FROM components WHERE host_id = ?1 AND type = 'probe' AND component_id != ?2").bind(hostId, componentId ?? "").all<{ component_id: string; slug: string; config_json: string }>()
  ).results ?? [];
  for (const o of others) {
    const cfg = parseJson<{ ports?: Array<{ iface?: string }> }>(o.config_json, {});
    for (const op of cfg.ports ?? []) {
      if (op.iface && used.has(op.iface)) throw new ApiError(422, "interface_in_use", `interface ${op.iface} is already used by probe ${o.slug}`, { iface: op.iface });
    }
  }
  return ports;
}

export async function putProbePorts(env: Env, actor: Actor, componentId: string, rawPorts: unknown): Promise<{ component_id: string; ports: Port[]; desired_version: number | null }> {
  if (!COMPONENT_ID_RE.test(componentId)) throw notFound("no such component");
  const c = await env.DB.prepare("SELECT host_id, type, slug, config_json FROM components WHERE component_id = ?1").bind(componentId).first<{ host_id: string; type: string; slug: string; config_json: string }>();
  if (!c) throw notFound("no such component");
  if (c.type !== "probe") throw new ApiError(422, "not_a_probe", "only probe components have ports");
  const cfg = parseJson<Record<string, unknown>>(c.config_json, {});
  const ports = await validateProbePorts(env, c.host_id, componentId, cfg.mgmt_iface, rawPorts);
  const now = isoNow();
  await env.DB.batch([
    env.DB.prepare("UPDATE components SET config_json = ?2, updated_at = ?3 WHERE component_id = ?1").bind(componentId, JSON.stringify({ ...cfg, ports }), now),
    auditStmt(env.DB, { actor: actor.email, action: "component.ports", resource: `component:${componentId}`, details: { id: c.slug, ports: ports.map((p) => ({ id: p.id, iface: p.iface, role: p.role })) }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
  const h = await env.DB.prepare("SELECT desired_version FROM hosts WHERE host_id = ?1").bind(c.host_id).first<{ desired_version: number | null }>();
  return { component_id: componentId, ports, desired_version: h?.desired_version ?? null };
}

// ---- sites -------------------------------------------------------------------------------------------
export const RetentionSchema = z.object({ metrics_days: z.number().int().min(1).max(365), records_days: z.number().int().min(1).max(365) }).strict();

export async function updateSite(env: Env, actor: Actor, site: string, p: { name?: string; timezone?: string; edge_label?: string; retention?: unknown }): Promise<void> {
  const row = await env.DB.prepare("SELECT site FROM sites WHERE site = ?1").bind(site).first();
  if (!row) throw notFound("no such site");
  const sets: string[] = [];
  const args: unknown[] = [site];
  const add = (col: string, v: unknown) => {
    args.push(v);
    sets.push(`${col} = ?${args.length}`);
  };
  if (p.name !== undefined) add("name", p.name);
  if (p.timezone !== undefined) add("timezone", p.timezone);
  if (p.edge_label !== undefined) add("edge_label", p.edge_label);
  if (p.retention !== undefined) add("retention_json", JSON.stringify(p.retention));
  args.push(isoNow());
  sets.push(`updated_at = ?${args.length}`);
  await env.DB.batch([
    env.DB.prepare(`UPDATE sites SET ${sets.join(", ")} WHERE site = ?1`).bind(...args),
    auditStmt(env.DB, { actor: actor.email, action: "site.update", resource: `site:${site}`, details: { fields: Object.keys(p) }, ip: actor.ip }),
  ]);
  await recompile(env, { sites: [site] });
}

export async function deleteSite(env: Env, actor: Actor, site: string): Promise<void> {
  const row = await env.DB.prepare("SELECT site FROM sites WHERE site = ?1").bind(site).first();
  if (!row) throw notFound("no such site");
  const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM hosts WHERE site = ?1 AND state != 'removed'").bind(site).first<{ n: number }>();
  if ((n?.n ?? 0) > 0) throw new ApiError(409, "conflict", "the site still has hosts; decommission and delete them first");
  const hooks = (await env.DB.prepare("SELECT webhook_id, secret_id FROM webhooks WHERE site = ?1").bind(site).all<{ webhook_id: string; secret_id: string }>()).results ?? [];
  await env.DB.batch([
    ...hooks.map((h) => env.DB.prepare("DELETE FROM secrets WHERE secret_id = ?1").bind(h.secret_id)),
    env.DB.prepare("DELETE FROM webhooks WHERE site = ?1").bind(site),
    env.DB.prepare("DELETE FROM hosts WHERE site = ?1 AND state = 'removed'").bind(site),
    env.DB.prepare("DELETE FROM sites WHERE site = ?1").bind(site),
    auditStmt(env.DB, { actor: actor.email, action: "site.delete", resource: `site:${site}`, ip: actor.ip }),
  ]);
}

// ---- hosts -------------------------------------------------------------------------------------------
export async function updateHost(env: Env, actor: Actor, hostId: string, p: { name?: string; site?: string }): Promise<void> {
  if (!HOST_ID_RE.test(hostId)) throw notFound("no such host");
  const h = await env.DB.prepare("SELECT host_id, site, state FROM hosts WHERE host_id = ?1").bind(hostId).first<{ host_id: string; site: string; state: string }>();
  if (!h || h.state === "removed") throw notFound("no such host");
  if (p.site !== undefined) {
    const s = await env.DB.prepare("SELECT 1 AS x FROM sites WHERE site = ?1").bind(p.site).first();
    if (!s) throw notFound("no such site");
  }
  const sets: string[] = [];
  const args: unknown[] = [hostId];
  if (p.name !== undefined) (args.push(p.name), sets.push(`name = ?${args.length}`));
  if (p.site !== undefined) (args.push(p.site), sets.push(`site = ?${args.length}`));
  args.push(isoNow());
  sets.push(`updated_at = ?${args.length}`);
  await env.DB.batch([
    env.DB.prepare(`UPDATE hosts SET ${sets.join(", ")} WHERE host_id = ?1`).bind(...args),
    auditStmt(env.DB, { actor: actor.email, action: "host.update", resource: `host:${hostId}`, details: { fields: Object.keys(p), from_site: h.site, to_site: p.site ?? h.site }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
}

/** Only hosts that never enrolled or are already removed can be deleted; others must be decommissioned. */
export async function deleteHost(env: Env, actor: Actor, hostId: string): Promise<void> {
  if (!HOST_ID_RE.test(hostId)) throw notFound("no such host");
  const h = await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(hostId).first<{ state: string }>();
  if (!h) throw notFound("no such host");
  if (h.state !== "pending" && h.state !== "removed") throw new ApiError(409, "conflict", "decommission the host first (it is still enrolled)");
  const comps = (await env.DB.prepare("SELECT component_id FROM components WHERE host_id = ?1").bind(hostId).all<{ component_id: string }>()).results ?? [];
  const stmts: D1PreparedStatement[] = [];
  for (const c of comps) {
    stmts.push(env.DB.prepare("DELETE FROM secrets WHERE owner_ref = ?1 OR owner_ref LIKE ?2 OR owner_ref LIKE ?3").bind(c.component_id, `${c.component_id}:%`, `%:${c.component_id}`));
  }
  await env.DB.batch([
    ...stmts,
    env.DB.prepare("DELETE FROM components WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM enrol_tokens WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM agent_creds WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM desired_docs WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM status_latest WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM status_history WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM issue_state WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM issue_snoozes WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM issues WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM fleet_host_5m WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM fleet_host_1h WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM fleet_iface_5m WHERE host_id = ?1").bind(hostId),
    env.DB.prepare("DELETE FROM hosts WHERE host_id = ?1").bind(hostId),
    auditStmt(env.DB, { actor: actor.email, action: "host.delete", resource: `host:${hostId}`, details: { components: comps.length }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
}

/** Asks the host's agent to restart one component (executed once per action id, retired by cron). */
export async function restartComponent(env: Env, actor: Actor, componentId: string): Promise<{ host_id: string; action_id: string; desired_version: number }> {
  if (!COMPONENT_ID_RE.test(componentId)) throw notFound("no such component");
  const c = await env.DB.prepare("SELECT host_id, type, slug FROM components WHERE component_id = ?1").bind(componentId).first<{ host_id: string; type: string; slug: string }>();
  if (!c) throw notFound("no such component");
  const h = await env.DB.prepare("SELECT state, actions_json FROM hosts WHERE host_id = ?1").bind(c.host_id).first<{ state: string; actions_json: string }>();
  if (!h || h.state === "pending" || h.state === "removed" || h.state === "decommissioning") throw new ApiError(409, "conflict", "the host is not enrolled");
  const actions = parseJson<Array<{ id: string; type: string; component_id?: string }>>(h.actions_json, []);
  const existing = actions.find((a) => a.type === "restart_component" && a.component_id === componentId);
  let id = existing?.id;
  if (!id) {
    id = newId("act_");
    actions.push({ id, type: "restart_component", component_id: componentId });
    await env.DB.batch([
      env.DB.prepare("UPDATE hosts SET actions_json = ?2, updated_at = ?3 WHERE host_id = ?1").bind(c.host_id, JSON.stringify(actions), isoNow()),
      auditStmt(env.DB, { actor: actor.email, action: "component.restart", resource: `component:${componentId}`, details: { type: c.type, id: c.slug, action_id: id }, ip: actor.ip }),
    ]);
    await recompile(env, { hostIds: [c.host_id] });
  }
  const d = await env.DB.prepare("SELECT desired_version FROM hosts WHERE host_id = ?1").bind(c.host_id).first<{ desired_version: number | null }>();
  return { host_id: c.host_id, action_id: id, desired_version: d?.desired_version ?? 0 };
}

export async function deleteDashboardUser(env: Env, actor: Actor, dashboardSlug: string, usrId: string): Promise<void> {
  if (!USR_ID_RE.test(usrId)) throw notFound("no such user");
  const u = await env.DB.prepare("SELECT username FROM dashboard_users WHERE usr_id = ?1 AND dashboard_slug = ?2").bind(usrId, dashboardSlug).first<{ username: string }>();
  if (!u) throw notFound("no such user");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM dashboard_users WHERE usr_id = ?1").bind(usrId),
    auditStmt(env.DB, { actor: actor.email, action: "dashboard_user.delete", resource: `dashboard:${dashboardSlug}`, details: { usr_id: usrId, username: u.username }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
}

export const nocIdOk = (id: string): boolean => NOC_ID_RE.test(id);

// ---- site alerts -------------------------------------------------------------------------------------
export const AlertsConfigSchema = z
  .object({
    enabled: z.boolean(),
    board_url: z.string().max(512).regex(HTTPS_URL).nullable().optional(),
    timezone: z.string().max(64).regex(TZ_RE).optional(),
    voice: z.enum(["plain", "sysadmin"]),
    hold_down_s: z.number().int().min(0).max(3600),
    hold_back_s: z.number().int().min(0).max(3600),
    reopen_s: z.number().int().min(0).max(86400),
    calm_s: z.number().int().min(0).max(86400),
  })
  .strict();
export const WebhookWriteSchema = z
  .object({ id: z.string().regex(/^wh_[A-Za-z0-9_-]{1,60}$/).optional(), format: z.enum(["slack", "teams", "json"]), url: z.string().max(512).optional() })
  .strict();
export const AlertsPutSchema = z.object({ config: AlertsConfigSchema, webhooks: z.array(WebhookWriteSchema).max(20) }).strict();

export const ALERT_DEFAULTS = { enabled: true, voice: "plain", hold_down_s: 30, hold_back_s: 10, reopen_s: 300, calm_s: 300 } as const;

const secretState = (updated: string | null) => ({ set: updated !== null, updated_at: updated });

export async function getSiteAlerts(env: Env, site: string) {
  const s = await env.DB.prepare("SELECT alerts_json, timezone FROM sites WHERE site = ?1").bind(site).first<{ alerts_json: string; timezone: string }>();
  if (!s) throw notFound("no such site");
  const cfg = parseJson<Record<string, unknown>>(s.alerts_json, {});
  const hooks = (
    await env.DB.prepare(
      `SELECT w.webhook_id, w.format, sec.updated_at AS secret_updated FROM webhooks w LEFT JOIN secrets sec ON sec.secret_id = w.secret_id WHERE w.site = ?1 ORDER BY w.webhook_id`,
    ).bind(site).all<{ webhook_id: string; format: string; secret_updated: string | null }>()
  ).results ?? [];
  return {
    config: { ...ALERT_DEFAULTS, board_url: null, timezone: s.timezone, ...cfg },
    webhooks: hooks.map((h) => ({ id: h.webhook_id, format: h.format, url: secretState(h.secret_updated) })),
  };
}

export async function putSiteAlerts(env: Env, actor: Actor, site: string, body: unknown) {
  const s = await env.DB.prepare("SELECT 1 AS x FROM sites WHERE site = ?1").bind(site).first();
  if (!s) throw notFound("no such site");
  const p = AlertsPutSchema.safeParse(body);
  if (!p.success) throw invalidRequest("alerts failed validation", { errors: p.error.issues.slice(0, 10).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })) });
  const { config, webhooks } = p.data;
  const existing = (await env.DB.prepare("SELECT webhook_id, secret_id FROM webhooks WHERE site = ?1").bind(site).all<{ webhook_id: string; secret_id: string }>()).results ?? [];
  const byId = new Map(existing.map((e) => [e.webhook_id, e]));
  const seen = new Set<string>();
  const stmts: D1PreparedStatement[] = [];
  const now = isoNow();
  let created = 0;
  let replaced = 0;
  for (const w of webhooks) {
    if (w.url !== undefined) validateWebhookUrl(w.url); // SR-15: https only, no private / loopback / link-local
    if (w.id) {
      const cur = byId.get(w.id);
      if (!cur) throw notFound(`no such webhook ${w.id} on this site`);
      if (seen.has(w.id)) throw invalidRequest("duplicate webhook id");
      seen.add(w.id);
      stmts.push(env.DB.prepare("UPDATE webhooks SET format = ?2, updated_at = ?3 WHERE webhook_id = ?1").bind(w.id, w.format, now));
      if (w.url !== undefined) {
        const row = await getSecretRow(env, cur.secret_id);
        if (!row) throw new ApiError(500, "internal_error", "webhook secret missing");
        stmts.push(await prepareSetSecret(env, row, w.url));
        replaced++;
      }
    } else {
      if (w.url === undefined) throw invalidRequest("a new webhook needs a url");
      const id = newId("wh_");
      const { secretId, stmt } = await prepareCreateSecret(env, { ownerRef: id, kind: WEBHOOK_KIND, plaintext: w.url });
      stmts.push(stmt, env.DB.prepare("INSERT INTO webhooks (webhook_id, org_id, site, format, secret_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)").bind(id, DEFAULT_ORG, site, w.format, secretId, now));
      created++;
    }
  }
  let removed = 0;
  for (const e of existing) {
    if (seen.has(e.webhook_id)) continue;
    stmts.push(env.DB.prepare("DELETE FROM webhooks WHERE webhook_id = ?1").bind(e.webhook_id), env.DB.prepare("DELETE FROM secrets WHERE secret_id = ?1").bind(e.secret_id));
    removed++;
  }
  const cfg = { ...config, board_url: config.board_url ?? undefined };
  await env.DB.batch([
    env.DB.prepare("UPDATE sites SET alerts_json = ?2, updated_at = ?3 WHERE site = ?1").bind(site, JSON.stringify(cfg), now),
    ...stmts,
    auditStmt(env.DB, { actor: actor.email, action: "site.alerts", resource: `site:${site}`, details: { enabled: config.enabled, voice: config.voice, webhooks: webhooks.length, created, replaced, removed, secret_set: replaced + created > 0 }, ip: actor.ip }),
  ]);
  await recompile(env, { sites: [site] });
  return getSiteAlerts(env, site);
}

export async function testSiteAlerts(env: Env, actor: Actor, site: string) {
  const s = await env.DB.prepare("SELECT name FROM sites WHERE site = ?1").bind(site).first<{ name: string }>();
  if (!s) throw notFound("no such site");
  const hooks = (await env.DB.prepare("SELECT webhook_id, format, secret_id FROM webhooks WHERE site = ?1 ORDER BY webhook_id").bind(site).all<{ webhook_id: string; format: WebhookFormat; secret_id: string }>()).results ?? [];
  const results: Array<{ webhook_id: string; ok: boolean; http_status: number | null; error: string | null }> = [];
  for (const h of hooks) {
    try {
      const row = await getSecretRow(env, h.secret_id);
      const url = row ? await readSecret(env, row) : null;
      if (!url) {
        results.push({ webhook_id: h.webhook_id, ok: false, http_status: null, error: "webhook URL is not set" });
        continue;
      }
      const r = await postWebhook(url, payloadFor(h.format, `exp test notification for site ${s.name}: alert delivery works.`, { event: "alerts.test", site }));
      results.push({ webhook_id: h.webhook_id, ...r });
    } catch (e) {
      if (e instanceof ConfigError) throw unavailable(e.message);
      results.push({ webhook_id: h.webhook_id, ok: false, http_status: null, error: "could not read the stored URL" });
    }
  }
  await auditStmt(env.DB, { actor: actor.email, action: "site.alerts_test", resource: `site:${site}`, details: { webhooks: results.length, ok: results.filter((r) => r.ok).length }, ip: actor.ip }).run();
  return { results };
}

// ---- integrations (write-only credentials) -----------------------------------------------------------
export const INTEGRATION_KIND = "integration_credentials";
export const IntegrationPutSchema = z
  .object({
    config: z.record(z.string().max(64), z.unknown()),
    credentials: z.object({ api_key: z.string().min(1).max(512), token: z.string().min(1).max(512) }).partial().strict().optional(),
    allowlist: z.array(z.record(z.string().max(64), z.unknown())).max(500).optional(),
  })
  .strict();

const isKind = (k: string): k is "ec" | "mist" => k === "ec" || k === "mist";

export async function getIntegration(env: Env, kind: string) {
  if (!isKind(kind)) throw notFound("no such integration");
  const r = await env.DB.prepare("SELECT config_json, secret_id, allowlist_json, updated_at FROM integrations WHERE kind = ?1").bind(kind).first<{ config_json: string; secret_id: string | null; allowlist_json: string; updated_at: string }>();
  let credUpdated: string | null = null;
  if (r?.secret_id) credUpdated = (await env.DB.prepare("SELECT updated_at FROM secrets WHERE secret_id = ?1").bind(r.secret_id).first<{ updated_at: string }>())?.updated_at ?? null;
  return {
    kind,
    config: parseJson<Record<string, unknown>>(r?.config_json, {}),
    credentials: secretState(credUpdated),
    allowlist: parseJson<unknown[]>(r?.allowlist_json, []),
    updated_at: r?.updated_at ?? null,
  };
}

export async function putIntegration(env: Env, actor: Actor, kind: string, body: unknown) {
  if (!isKind(kind)) throw notFound("no such integration");
  const p = IntegrationPutSchema.safeParse(body);
  if (!p.success) throw invalidRequest("integration failed validation", { errors: p.error.issues.slice(0, 10).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })) });
  const { config, credentials, allowlist } = p.data;
  for (const k of ["url", "api_base", "base_url"]) {
    const v = config[k];
    if (v !== undefined && !(typeof v === "string" && v.length <= 512 && HTTPS_URL.test(v) && !/@/.test(v.split("/")[2] ?? ""))) throw invalidRequest(`config.${k} must be an https URL without credentials`);
  }
  // secrets never live in config: refuse secret-looking keys so they cannot be read back
  for (const k of Object.keys(config)) if (/(secret|token|password|api_?key|credential)/i.test(k)) throw invalidRequest(`config.${k} looks like a secret; send credentials in the write-only credentials object`);
  const cur = await env.DB.prepare("SELECT secret_id, allowlist_json FROM integrations WHERE kind = ?1").bind(kind).first<{ secret_id: string | null; allowlist_json: string }>();
  const now = isoNow();
  const stmts: D1PreparedStatement[] = [];
  let secretId = cur?.secret_id ?? null;
  let secretSet = false;
  if (credentials && Object.keys(credentials).length > 0) {
    const plaintext = JSON.stringify(credentials);
    if (secretId) {
      const row = await getSecretRow(env, secretId);
      if (row) stmts.push(await prepareSetSecret(env, row, plaintext));
      else {
        const c = await prepareCreateSecret(env, { ownerRef: `integration:${kind}`, kind: INTEGRATION_KIND, plaintext });
        secretId = c.secretId;
        stmts.push(c.stmt);
      }
    } else {
      const c = await prepareCreateSecret(env, { ownerRef: `integration:${kind}`, kind: INTEGRATION_KIND, plaintext });
      secretId = c.secretId;
      stmts.push(c.stmt);
    }
    secretSet = true;
  }
  stmts.push(
    env.DB.prepare(
      `INSERT INTO integrations (kind, org_id, config_json, secret_id, allowlist_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
       ON CONFLICT(kind) DO UPDATE SET config_json = excluded.config_json, secret_id = excluded.secret_id, allowlist_json = excluded.allowlist_json, updated_at = excluded.updated_at`,
    ).bind(kind, DEFAULT_ORG, JSON.stringify(config), secretId, allowlist !== undefined ? JSON.stringify(allowlist) : (cur?.allowlist_json ?? "[]"), now),
    auditStmt(env.DB, { actor: actor.email, action: "integration.update", resource: `integration:${kind}`, details: { config_keys: Object.keys(config), allowlist: allowlist?.length ?? null, secret_set: secretSet }, ip: actor.ip }),
  );
  await env.DB.batch(stmts);
  return getIntegration(env, kind);
}

export async function testIntegration(env: Env, actor: Actor, kind: string) {
  if (!isKind(kind)) throw notFound("no such integration");
  const i = await getIntegration(env, kind);
  let out: { ok: boolean; detail: string; inventory_count: number | null };
  const url = (i.config.url ?? i.config.api_base ?? i.config.base_url) as string | undefined;
  if (!url) out = { ok: false, detail: "no url configured", inventory_count: null };
  else if (!i.credentials.set) out = { ok: false, detail: "no credentials configured", inventory_count: null };
  else {
    try {
      validateWebhookUrl(url);
      const res = await fetch(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(5000), headers: { "user-agent": "exp-manager" } });
      await res.body?.cancel().catch(() => undefined);
      out = { ok: res.status < 500, detail: `reachable (http ${res.status}); API checks run with drills`, inventory_count: null };
    } catch (e) {
      out = { ok: false, detail: e instanceof ApiError ? e.message.slice(0, 200) : "not reachable from the manager", inventory_count: null };
    }
  }
  await auditStmt(env.DB, { actor: actor.email, action: "integration.test", resource: `integration:${kind}`, details: { ok: out.ok }, ip: actor.ip }).run();
  return out;
}

// ---- settings ------------------------------------------------------------------------------------------
export const SettingsPatchSchema = z
  .object({
    org_name: z.string().min(1).max(128),
    drills_enabled: z.boolean(),
    drills_two_person: z.boolean(),
    default_retention: RetentionSchema,
    release_channel: z.string().min(1).max(32).regex(/^[A-Za-z0-9._-]+$/),
    owner: z.string().max(254),
    admins: z.array(z.object({ email: z.string().max(254), role: z.enum(["owner", "admin", "operator", "viewer"]), disabled: z.boolean().optional() }).strict()).max(200),
  })
  .partial()
  .strict();

const EMAIL_RE = /^[^\s@]{1,128}@[^\s@]{1,253}$/;

export async function getSettings(env: Env) {
  await ensureSettings(env);
  const s = await env.DB.prepare("SELECT * FROM settings WHERE org_id = ?1").bind(DEFAULT_ORG).first<Record<string, unknown>>();
  const admins = (await env.DB.prepare("SELECT email, role, disabled, last_seen FROM admins ORDER BY email").all<{ email: string; role: string; disabled: number; last_seen: string | null }>()).results ?? [];
  return {
    org_name: String(s?.org_name || env.ORG_NAME || ""),
    drills_enabled: Number(s?.drills_enabled) === 1,
    drills_two_person: Number(s?.drills_two_person) === 1,
    default_retention: { metrics_days: Number(s?.default_retention_metrics_days ?? 30), records_days: Number(s?.default_retention_records_days ?? 7) },
    release_channel: String(s?.release_channel ?? "stable"),
    owner: (env.EXP_OWNER_EMAIL ?? "").toLowerCase(),
    admins: admins.map((a) => ({ email: a.email, role: a.role, disabled: a.disabled === 1, last_seen: a.last_seen })),
    updated_at: String(s?.updated_at ?? isoNow()),
  };
}

export async function patchSettings(env: Env, actor: Actor, body: unknown) {
  await ensureSettings(env);
  const p = SettingsPatchSchema.safeParse(body);
  if (!p.success || Object.keys(p.data).length === 0) throw invalidRequest("settings patch failed validation", { errors: p.success ? [] : p.error.issues.slice(0, 10).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })) });
  const d = p.data;
  const now = isoNow();
  const sets: string[] = [];
  const args: unknown[] = [DEFAULT_ORG];
  const add = (col: string, v: unknown) => (args.push(v), sets.push(`${col} = ?${args.length}`));
  if (d.org_name !== undefined) add("org_name", d.org_name);
  if (d.drills_enabled !== undefined) add("drills_enabled", d.drills_enabled ? 1 : 0);
  if (d.drills_two_person !== undefined) add("drills_two_person", d.drills_two_person ? 1 : 0);
  if (d.default_retention) (add("default_retention_metrics_days", d.default_retention.metrics_days), add("default_retention_records_days", d.default_retention.records_days));
  if (d.release_channel !== undefined) add("release_channel", d.release_channel);
  add("updated_at", now);

  const ownerEmail = (env.EXP_OWNER_EMAIL ?? "").trim().toLowerCase();
  const stmts: D1PreparedStatement[] = [env.DB.prepare(`UPDATE settings SET ${sets.join(", ")} WHERE org_id = ?1`).bind(...args)];
  const entries: Array<{ email: string; role: string; disabled: boolean }> = [];
  if (d.owner !== undefined) entries.push({ email: d.owner, role: "owner", disabled: false });
  for (const a of d.admins ?? []) entries.push({ email: a.email, role: a.role, disabled: a.disabled === true });
  for (const e of entries) {
    const email = e.email.trim().toLowerCase();
    if (!EMAIL_RE.test(email)) throw invalidRequest("invalid admin email");
    if (email === ownerEmail && (e.role !== "owner" || e.disabled)) throw new ApiError(409, "conflict", "the configured owner cannot be demoted or disabled");
    if (email === actor.email.toLowerCase() && (e.role !== "owner" || e.disabled)) throw new ApiError(409, "conflict", "you cannot demote or disable yourself");
    stmts.push(
      env.DB.prepare(
        `INSERT INTO admins (org_id, email, role, disabled, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)
         ON CONFLICT(email) DO UPDATE SET role = excluded.role, disabled = excluded.disabled, updated_at = excluded.updated_at`,
      ).bind(DEFAULT_ORG, email, e.role, e.disabled ? 1 : 0, now),
    );
  }
  stmts.push(auditStmt(env.DB, { actor: actor.email, action: "settings.update", resource: "settings", details: { fields: Object.keys(d), admins: entries.map((e) => ({ email: e.email.toLowerCase(), role: e.role, disabled: e.disabled })) }, ip: actor.ip }));
  await env.DB.batch(stmts);
  return getSettings(env);
}

// ---- fleet thresholds / platform webhook ---------------------------------------------------------------
export async function getThresholds(env: Env) {
  const r = await env.DB.prepare("SELECT fleet_thresholds_json FROM settings WHERE org_id = ?1").bind(DEFAULT_ORG).first<{ fleet_thresholds_json: string }>();
  return mergeThresholds(parseJson(r?.fleet_thresholds_json, {}));
}

export async function putThresholds(env: Env, actor: Actor, body: unknown) {
  const p = ThresholdsSchema.safeParse(body);
  if (!p.success) throw invalidRequest("thresholds failed validation", { errors: p.error.issues.slice(0, 10).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })) });
  const t = mergeThresholds(p.data, false);
  const bad =
    (t.disk_high.warn_pct > t.disk_high.crit_pct && "disk_high.warn_pct must not exceed crit_pct") ||
    (t.storage_runway.warn_days < t.storage_runway.crit_days && "storage_runway.warn_days must not be below crit_days") ||
    (t.probe_push_lag.warn_s > t.probe_push_lag.crit_s && "probe_push_lag.warn_s must not exceed crit_s");
  if (bad) throw invalidRequest(bad);
  await ensureSettings(env);
  const now = isoNow();
  await env.DB.batch([
    env.DB.prepare("UPDATE settings SET fleet_thresholds_json = ?2, updated_at = ?3 WHERE org_id = ?1").bind(DEFAULT_ORG, JSON.stringify(p.data), now),
    auditStmt(env.DB, { actor: actor.email, action: "settings.fleet_thresholds", resource: "settings", details: { groups: Object.keys(p.data) }, ip: actor.ip }),
  ]);
  return t;
}

export async function getPlatformWebhook(env: Env) {
  await ensureSettings(env);
  const s = await env.DB.prepare("SELECT platform_webhook_secret_id AS id, platform_webhook_format AS fmt FROM settings WHERE org_id = ?1").bind(DEFAULT_ORG).first<{ id: string | null; fmt: string }>();
  let updated: string | null = null;
  if (s?.id) updated = (await env.DB.prepare("SELECT updated_at FROM secrets WHERE secret_id = ?1").bind(s.id).first<{ updated_at: string }>())?.updated_at ?? null;
  return { format: (s?.fmt ?? "json") as WebhookFormat, url: secretState(updated) };
}

export async function putPlatformWebhook(env: Env, actor: Actor, body: unknown) {
  const p = z.object({ format: z.enum(["slack", "teams", "json"]), url: z.string().max(512).optional() }).strict().safeParse(body);
  if (!p.success) throw invalidRequest("platform webhook failed validation");
  await ensureSettings(env);
  if (p.data.url !== undefined) validateWebhookUrl(p.data.url);
  const cur = await env.DB.prepare("SELECT platform_webhook_secret_id AS id FROM settings WHERE org_id = ?1").bind(DEFAULT_ORG).first<{ id: string | null }>();
  const stmts: D1PreparedStatement[] = [];
  let secretId = cur?.id ?? null;
  if (p.data.url !== undefined) {
    const row = secretId ? await getSecretRow(env, secretId) : await getSecretByOwner(env, PLATFORM_OWNER, PLATFORM_KIND);
    if (row) {
      secretId = row.secret_id;
      stmts.push(await prepareSetSecret(env, row, p.data.url));
    } else {
      const c = await prepareCreateSecret(env, { ownerRef: PLATFORM_OWNER, kind: PLATFORM_KIND, plaintext: p.data.url });
      secretId = c.secretId;
      stmts.push(c.stmt);
    }
  }
  const now = isoNow();
  stmts.push(
    env.DB.prepare("UPDATE settings SET platform_webhook_secret_id = ?2, platform_webhook_format = ?3, updated_at = ?4 WHERE org_id = ?1").bind(DEFAULT_ORG, secretId, p.data.format, now),
    auditStmt(env.DB, { actor: actor.email, action: "settings.platform_webhook", resource: "settings", details: { format: p.data.format, secret_set: p.data.url !== undefined }, ip: actor.ip }),
  );
  await env.DB.batch(stmts);
  return getPlatformWebhook(env);
}

export async function testPlatformWebhook(env: Env, actor: Actor) {
  let t;
  try {
    t = await platformTarget(env);
  } catch (e) {
    if (e instanceof ConfigError) throw unavailable(e.message);
    throw e;
  }
  if (!t) throw new ApiError(409, "conflict", "no platform webhook is configured");
  const r = await postWebhook(t.url, payloadFor(t.format, "exp platform webhook test: fleet issue notifications are delivered here.", { event: "platform.test" }));
  await auditStmt(env.DB, { actor: actor.email, action: "settings.platform_webhook_test", resource: "settings", details: { ok: r.ok }, ip: actor.ip }).run();
  return r;
}
