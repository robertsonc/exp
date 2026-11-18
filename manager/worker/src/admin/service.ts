// Intent mutations (sites, hosts, components, release targets, dashboard users, NOC tokens, webhooks,
// credential rotation). Each function validates, performs ONE database batch that includes exactly one
// audit event, then recompiles the affected desired states. Step 2 exposes these as admin routes.
import { auditStmt } from "../audit/audit";
import { recompile } from "../compile/recompile";
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { ApiError, invalidRequest, notFound } from "../errors";
import { ensureSettings } from "../compile/load";
import { ROTATION_GRACE_S, prepareCreateSecret, prepareRotateSecret, getSecretByOwner } from "../secrets/store";
import { newToken, tokenHash } from "../secrets/tokens";
import { COMPONENT_ID_RE, HOST_ID_RE, SEMVER_RE, SLUG_RE, newId } from "../util/ids";
import { isoNow, isoPlusSeconds } from "../util/time";
import { validateWebhookUrl } from "../notify/webhook";
import { validateProbePorts } from "./intent";
import { DASH_TOKEN_KIND, INGEST_KIND, WEBHOOK_KIND, pairOwner } from "../compile/wiring";
import { loadWorld } from "../compile/load";
import { collectorsOfDashboard } from "../compile/wiring";

export const ENROL_TTL_S = 3600;
export interface Actor {
  email: string;
  ip?: string | null;
}

const COMPONENT_TYPES = ["probe", "collector", "dashboard", "runner"] as const;
export const PBKDF2_RE = /^pbkdf2_sha256\$600000\$[A-Za-z0-9+/=_-]{8,64}\$[A-Za-z0-9+/=_-]{16,128}$/;

const slug = (v: unknown, what: string): string => {
  if (typeof v !== "string" || !SLUG_RE.test(v)) throw invalidRequest(`${what} must be a slug [a-z0-9][a-z0-9-]{0,63}`);
  return v;
};

export async function createSite(
  env: Env,
  actor: Actor,
  s: { site: string; name: string; timezone?: string; edge_label?: string; retention?: Record<string, unknown> },
): Promise<void> {
  const site = slug(s.site, "site");
  if (!s.name || s.name.length > 128) throw invalidRequest("name is required (<= 128 chars)");
  await ensureSettings(env);
  const now = isoNow();
  const exists = await env.DB.prepare("SELECT 1 AS x FROM sites WHERE site = ?1").bind(site).first();
  if (exists) throw new ApiError(409, "conflict", "site already exists");
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO sites (site, org_id, name, timezone, edge_label, retention_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?7, ?6, ?6)`,
    ).bind(site, DEFAULT_ORG, s.name, s.timezone ?? "UTC", s.edge_label ?? "EC", now, JSON.stringify(s.retention ?? {})),
    auditStmt(env.DB, { actor: actor.email, action: "site.create", resource: `site:${site}`, details: { name: s.name }, ip: actor.ip }),
  ]);
}

/** Creates the pending host and its first enrol token (shown once; only the hash is stored). */
export async function createHost(
  env: Env,
  actor: Actor,
  h: { name: string; site: string },
): Promise<{ host_id: string; enrol_token: string; expires_at: string }> {
  if (!h.name || h.name.length > 128) throw invalidRequest("name is required (<= 128 chars)");
  const site = await env.DB.prepare("SELECT site FROM sites WHERE site = ?1").bind(slug(h.site, "site")).first();
  if (!site) throw notFound("no such site");
  const hostId = newId("h_");
  const token = newToken("expe");
  const now = isoNow();
  const expires = isoPlusSeconds(ENROL_TTL_S);
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO hosts (host_id, org_id, name, site, state, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?5)`).bind(hostId, DEFAULT_ORG, h.name, h.site, now),
    env.DB.prepare(
      `INSERT INTO enrol_tokens (token_hash, org_id, host_id, expires_at, created_by, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)`,
    ).bind(await tokenHash(token), DEFAULT_ORG, hostId, expires, actor.email, now),
    auditStmt(env.DB, { actor: actor.email, action: "host.create", resource: `host:${hostId}`, details: { name: h.name, site: h.site }, ip: actor.ip }),
  ]);
  return { host_id: hostId, enrol_token: token, expires_at: expires };
}

/** A fresh enrol token for an existing host; unused older tokens of the host are revoked. */
export async function issueEnrolToken(env: Env, actor: Actor, hostId: string): Promise<{ enrol_token: string; expires_at: string }> {
  if (!HOST_ID_RE.test(hostId)) throw notFound("no such host");
  const host = await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(hostId).first<{ state: string }>();
  if (!host || host.state === "removed") throw notFound("no such host");
  const token = newToken("expe");
  const now = isoNow();
  const expires = isoPlusSeconds(ENROL_TTL_S);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM enrol_tokens WHERE host_id = ?1 AND used_at IS NULL").bind(hostId),
    env.DB.prepare(
      `INSERT INTO enrol_tokens (token_hash, org_id, host_id, expires_at, created_by, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)`,
    ).bind(await tokenHash(token), DEFAULT_ORG, hostId, expires, actor.email, now),
    auditStmt(env.DB, { actor: actor.email, action: "host.enrol_token", resource: `host:${hostId}`, ip: actor.ip }),
  ]);
  return { enrol_token: token, expires_at: expires };
}

export async function addComponent(
  env: Env,
  actor: Actor,
  hostId: string,
  c: { type: string; id: string; config?: Record<string, unknown> },
): Promise<{ component_id: string }> {
  if (!(COMPONENT_TYPES as readonly string[]).includes(c.type)) throw invalidRequest("unsupported component type");
  const id = slug(c.id, "id");
  const host = await env.DB.prepare("SELECT site FROM hosts WHERE host_id = ?1 AND state != 'removed'").bind(hostId).first<{ site: string }>();
  if (!host) throw notFound("no such host");
  const cfgBytes = JSON.stringify(c.config ?? {}).length;
  if (cfgBytes > 65536) throw new ApiError(422, "invalid_config", "component config exceeds 64 KiB");
  if (c.type === "probe" && Array.isArray(c.config?.ports)) await validateProbePorts(env, hostId, null, c.config?.mgmt_iface, c.config.ports);
  const dup = await env.DB.prepare("SELECT 1 AS x FROM components WHERE type = ?1 AND slug = ?2").bind(c.type, id).first();
  if (dup) throw new ApiError(409, "conflict", `${c.type} ${id} already exists`);
  const cid = newId("cmp_");
  const now = isoNow();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO components (component_id, org_id, host_id, type, slug, config_json, enabled, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)`,
    ).bind(cid, DEFAULT_ORG, hostId, c.type, id, JSON.stringify(c.config ?? {}), now),
    auditStmt(env.DB, { actor: actor.email, action: "component.create", resource: `component:${cid}`, details: { host_id: hostId, type: c.type, id }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
  return { component_id: cid };
}

export async function updateComponentConfig(env: Env, actor: Actor, componentId: string, config: Record<string, unknown>): Promise<void> {
  await patchComponent(env, actor, componentId, { config });
}

export async function patchComponent(env: Env, actor: Actor, componentId: string, p: { config?: Record<string, unknown>; enabled?: boolean }): Promise<void> {
  if (!COMPONENT_ID_RE.test(componentId)) throw notFound("no such component");
  const row = await env.DB.prepare("SELECT type, slug, host_id, config_json FROM components WHERE component_id = ?1").bind(componentId).first<{ type: string; slug: string; host_id: string; config_json: string }>();
  if (!row) throw notFound("no such component");
  const sets: string[] = [];
  const args: unknown[] = [componentId];
  if (p.config !== undefined) {
    if (JSON.stringify(p.config).length > 65536) throw new ApiError(422, "invalid_config", "component config exceeds 64 KiB");
    if (row.type === "probe" && Array.isArray(p.config.ports)) await validateProbePorts(env, row.host_id, componentId, p.config.mgmt_iface, p.config.ports);
    args.push(JSON.stringify(p.config));
    sets.push(`config_json = ?${args.length}`);
  }
  if (p.enabled !== undefined) {
    args.push(p.enabled ? 1 : 0);
    sets.push(`enabled = ?${args.length}`);
  }
  if (sets.length === 0) throw invalidRequest("nothing to change");
  args.push(isoNow());
  sets.push(`updated_at = ?${args.length}`);
  await env.DB.batch([
    env.DB.prepare(`UPDATE components SET ${sets.join(", ")} WHERE component_id = ?1`).bind(...args),
    auditStmt(env.DB, { actor: actor.email, action: "component.update", resource: `component:${componentId}`, details: { type: row.type, id: row.slug, keys: Object.keys(p.config ?? {}), enabled: p.enabled ?? null }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
}

export async function deleteComponent(env: Env, actor: Actor, componentId: string): Promise<void> {
  const row = await env.DB.prepare("SELECT type, slug FROM components WHERE component_id = ?1").bind(componentId).first<{ type: string; slug: string }>();
  if (!row) throw notFound("no such component");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM components WHERE component_id = ?1").bind(componentId),
    auditStmt(env.DB, { actor: actor.email, action: "component.delete", resource: `component:${componentId}`, details: { type: row.type, id: row.slug }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
}

/** Release target: with a canary host the new version goes to that host first (target_version). */
export async function setSiteRelease(
  env: Env,
  actor: Actor,
  site: string,
  r: { version: string; canary_host_id?: string | null },
): Promise<void> {
  if (!SEMVER_RE.test(r.version)) throw invalidRequest("version must be semver");
  const rel = await env.DB.prepare("SELECT 1 AS x FROM releases WHERE version = ?1").bind(r.version).first();
  if (!rel) throw notFound("no such release (import it first)");
  const row = await env.DB.prepare("SELECT site FROM sites WHERE site = ?1").bind(site).first();
  if (!row) throw notFound("no such site");
  const now = isoNow();
  let stmt: D1PreparedStatement;
  if (r.canary_host_id) {
    const h = await env.DB.prepare("SELECT 1 AS x FROM hosts WHERE host_id = ?1 AND site = ?2").bind(r.canary_host_id, site).first();
    if (!h) throw invalidRequest("canary host must belong to the site");
    stmt = env.DB.prepare(
      `UPDATE sites SET target_version = ?2, canary_host_id = ?3, canary_state = 'canary', canary_started_at = ?4, canary_healthy_since = NULL, updated_at = ?4 WHERE site = ?1`,
    ).bind(site, r.version, r.canary_host_id, now);
  } else {
    stmt = env.DB.prepare(
      `UPDATE sites SET release_version = ?2, target_version = NULL, canary_host_id = NULL, canary_state = 'none', canary_started_at = NULL, canary_healthy_since = NULL, updated_at = ?3 WHERE site = ?1`,
    ).bind(site, r.version, now);
  }
  await env.DB.batch([
    stmt,
    auditStmt(env.DB, { actor: actor.email, action: "site.release", resource: `site:${site}`, details: { version: r.version, canary_host_id: r.canary_host_id ?? null }, ip: actor.ip }),
  ]);
  await recompile(env, { sites: [site] });
}

/** Manual canary promotion: the target becomes the site's version for everyone. */
export async function promoteCanary(env: Env, actor: Actor, site: string): Promise<void> {
  const row = await env.DB.prepare("SELECT target_version, canary_state FROM sites WHERE site = ?1").bind(site).first<{ target_version: string | null; canary_state: string }>();
  if (!row) throw notFound("no such site");
  if (row.canary_state !== "canary" || !row.target_version) throw new ApiError(409, "conflict", "no canary rollout in progress");
  const now = isoNow();
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE sites SET release_version = target_version, target_version = NULL, canary_state = 'promoted', canary_healthy_since = NULL, updated_at = ?2 WHERE site = ?1`,
    ).bind(site, now),
    auditStmt(env.DB, { actor: actor.email, action: "site.promote", resource: `site:${site}`, details: { version: row.target_version }, ip: actor.ip }),
  ]);
  await recompile(env, { sites: [site] });
}

export async function decommissionHost(env: Env, actor: Actor, hostId: string): Promise<void> {
  const h = await env.DB.prepare("SELECT state FROM hosts WHERE host_id = ?1").bind(hostId).first<{ state: string }>();
  if (!h || h.state === "removed") throw notFound("no such host");
  if (h.state === "pending") throw new ApiError(409, "conflict", "host never enrolled: delete it instead");
  await env.DB.batch([
    env.DB.prepare("UPDATE hosts SET state = 'decommissioning', updated_at = ?2 WHERE host_id = ?1").bind(hostId, isoNow()),
    auditStmt(env.DB, { actor: actor.email, action: "host.decommission", resource: `host:${hostId}`, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
}

/** Adds a rotate_agent_secret action to the host's desired state; the agent then calls POST rotate. */
export async function requestAgentRotation(env: Env, actor: Actor, hostId: string): Promise<{ action_id: string }> {
  const h = await env.DB.prepare("SELECT state, actions_json FROM hosts WHERE host_id = ?1").bind(hostId).first<{ state: string; actions_json: string }>();
  if (!h || h.state === "removed" || h.state === "pending") throw notFound("no such enrolled host");
  let actions: Array<{ id: string; type: string }> = [];
  try {
    actions = JSON.parse(h.actions_json) as typeof actions;
  } catch {
    actions = [];
  }
  const existing = actions.find((a) => a.type === "rotate_agent_secret");
  if (existing) return { action_id: existing.id };
  const id = newId("act_");
  actions.push({ id, type: "rotate_agent_secret" });
  await env.DB.batch([
    env.DB.prepare("UPDATE hosts SET actions_json = ?2, updated_at = ?3 WHERE host_id = ?1").bind(hostId, JSON.stringify(actions), isoNow()),
    auditStmt(env.DB, { actor: actor.email, action: "host.rotate_agent", resource: `host:${hostId}`, ip: actor.ip }),
  ]);
  await recompile(env, { hostIds: [hostId] });
  return { action_id: id };
}

/** Rotates a component's generated tokens (probe/runner ingest token, dashboard->collector tokens). */
export async function rotateComponentTokens(
  env: Env,
  actor: Actor,
  componentId: string,
): Promise<{ component_id: string; kinds: string[]; previous_valid_until: string; desired_version: number }> {
  if (!COMPONENT_ID_RE.test(componentId)) throw notFound("no such component");
  const row = await env.DB.prepare("SELECT type, host_id FROM components WHERE component_id = ?1").bind(componentId).first<{ type: string; host_id: string }>();
  if (!row) throw notFound("no such component");
  const stmts: D1PreparedStatement[] = [];
  let kind = "";
  if (row.type === "probe" || row.type === "runner") {
    kind = INGEST_KIND;
    const s = await getSecretByOwner(env, componentId, INGEST_KIND);
    if (s) stmts.push(await prepareRotateSecret(env, s, newToken("expi"), true));
  } else if (row.type === "dashboard") {
    kind = DASH_TOKEN_KIND;
    const world = await loadWorld(env);
    const comp = world.components.find((c) => c.component_id === componentId);
    for (const col of comp ? collectorsOfDashboard(world, comp) : []) {
      const s = await getSecretByOwner(env, pairOwner(componentId, col.component_id), DASH_TOKEN_KIND);
      if (s) stmts.push(await prepareRotateSecret(env, s, newToken("expd"), true));
    }
  } else {
    throw invalidRequest("this component type has no rotatable tokens");
  }
  if (stmts.length === 0) throw new ApiError(409, "conflict", "no tokens provisioned yet");
  await env.DB.batch([
    ...stmts,
    auditStmt(env.DB, { actor: actor.email, action: "component.rotate", resource: `component:${componentId}`, details: { tokens: stmts.length, kind }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
  const h = await env.DB.prepare("SELECT desired_version FROM hosts WHERE host_id = ?1").bind(row.host_id).first<{ desired_version: number | null }>();
  return { component_id: componentId, kinds: [kind], previous_valid_until: isoPlusSeconds(ROTATION_GRACE_S), desired_version: h?.desired_version ?? 0 };
}

/** Dashboard local user: the password hash is computed in the browser; plaintext is refused. */
export async function createDashboardUser(
  env: Env,
  actor: Actor,
  dashboardSlug: string,
  u: { username: string; role: "viewer" | "operator" | "admin"; hash: string },
): Promise<{ usr_id: string }> {
  slug(dashboardSlug, "dashboard");
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(u.username)) throw invalidRequest("invalid username");
  if (!["viewer", "operator", "admin"].includes(u.role)) throw invalidRequest("invalid role");
  if (!PBKDF2_RE.test(u.hash)) throw invalidRequest("hash must be pbkdf2_sha256$600000$<salt>$<hash>, computed client-side (plaintext passwords are never accepted)");
  const d = await env.DB.prepare("SELECT 1 AS x FROM components WHERE type = 'dashboard' AND slug = ?1").bind(dashboardSlug).first();
  if (!d) throw notFound("no such dashboard");
  const dupUser = await env.DB.prepare("SELECT 1 AS x FROM dashboard_users WHERE dashboard_slug = ?1 AND username = ?2").bind(dashboardSlug, u.username).first();
  if (dupUser) throw new ApiError(409, "conflict", "a user with that name already exists on this dashboard");
  const id = newId("usr_");
  const now = isoNow();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO dashboard_users (usr_id, org_id, dashboard_slug, username, role, hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)`,
    ).bind(id, DEFAULT_ORG, dashboardSlug, u.username, u.role, u.hash, now),
    auditStmt(env.DB, { actor: actor.email, action: "dashboard_user.create", resource: `dashboard:${dashboardSlug}`, details: { usr_id: id, username: u.username, role: u.role }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
  return { usr_id: id };
}

/** NOC token: returned once; only sha256 is stored. */
export async function createNocToken(
  env: Env,
  actor: Actor,
  dashboardSlug: string,
  t: { label: string; expires_at?: string | null },
): Promise<{ noc_id: string; token: string }> {
  slug(dashboardSlug, "dashboard");
  if (!t.label || t.label.length > 64) throw invalidRequest("label is required (<= 64 chars)");
  const d = await env.DB.prepare("SELECT 1 AS x FROM components WHERE type = 'dashboard' AND slug = ?1").bind(dashboardSlug).first();
  if (!d) throw notFound("no such dashboard");
  const token = newToken("expn");
  const id = newId("noc_");
  const now = isoNow();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO noc_tokens (noc_id, org_id, dashboard_slug, label, hash, expires_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)`,
    ).bind(id, DEFAULT_ORG, dashboardSlug, t.label, await tokenHash(token), t.expires_at ?? null, now),
    auditStmt(env.DB, { actor: actor.email, action: "noc_token.create", resource: `dashboard:${dashboardSlug}`, details: { noc_id: id, label: t.label }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
  return { noc_id: id, token };
}

export async function revokeNocToken(env: Env, actor: Actor, nocId: string): Promise<void> {
  const row = await env.DB.prepare("SELECT dashboard_slug FROM noc_tokens WHERE noc_id = ?1 AND revoked_at IS NULL").bind(nocId).first<{ dashboard_slug: string }>();
  if (!row) throw notFound("no such NOC token");
  const now = isoNow();
  await env.DB.batch([
    env.DB.prepare("UPDATE noc_tokens SET revoked_at = ?2, updated_at = ?2 WHERE noc_id = ?1").bind(nocId, now),
    auditStmt(env.DB, { actor: actor.email, action: "noc_token.revoke", resource: `dashboard:${row.dashboard_slug}`, details: { noc_id: nocId }, ip: actor.ip }),
  ]);
  await recompile(env, { all: true });
}

export { validateWebhookUrl };

export async function addWebhook(env: Env, actor: Actor, site: string, w: { format: "slack" | "teams" | "json"; url: string }): Promise<{ webhook_id: string }> {
  if (!["slack", "teams", "json"].includes(w.format)) throw invalidRequest("invalid format");
  validateWebhookUrl(w.url);
  const s = await env.DB.prepare("SELECT 1 AS x FROM sites WHERE site = ?1").bind(site).first();
  if (!s) throw notFound("no such site");
  const id = newId("wh_");
  const { secretId, stmt } = await prepareCreateSecret(env, { ownerRef: id, kind: WEBHOOK_KIND, plaintext: w.url });
  const now = isoNow();
  await env.DB.batch([
    stmt,
    env.DB.prepare(`INSERT INTO webhooks (webhook_id, org_id, site, format, secret_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)`).bind(id, DEFAULT_ORG, site, w.format, secretId, now),
    auditStmt(env.DB, { actor: actor.email, action: "webhook.create", resource: `site:${site}`, details: { webhook_id: id, format: w.format, secret_set: true }, ip: actor.ip }),
  ]);
  await recompile(env, { sites: [site] });
  return { webhook_id: id };
}
