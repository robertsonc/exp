// Admin API (01-contracts.md section 13, shared/openapi/admin.yaml). Base /api/admin/v1. Every request is
// authenticated by the Access JWT middleware (fail closed) and role-checked per endpoint; every mutation
// writes exactly one audit event (in the service layer). Drills are step 3 of WP-4 and answer 501.
import { Hono } from "hono";
import type { Context } from "hono";
import { z } from "zod";
import { accessAuth, adminOf, requireRole } from "../auth/access";
import type { AppBindings, Env } from "../env";
import { ApiError, invalidRequest, notFound } from "../errors";
import { componentMetrics, fleetHosts, fleetSites, fleetSummary, fleetTop, hostMetrics, mgmtIpOf, overview } from "../fleet/query";
import { listIssues, snoozeIssue, unsnoozeIssue } from "../issues/store";
import { importFromGithub, importFromUpload } from "../releases/verify";
import { readJson } from "../util/body";
import { sha256Hex } from "../util/encoding";
import { HOST_ID_RE, SEMVER_RE, SLUG_RE } from "../util/ids";
import { isoNow, isoPlusSeconds } from "../util/time";
import * as intent from "./intent";
import * as read from "./read";
import * as svc from "./service";
import { buildSsoPage } from "./sso";

export const adminRoutes = new Hono<AppBindings>();
adminRoutes.use("*", accessAuth);
adminRoutes.use("*", async (c, next) => {
  await learnManagerUrl(c.env, c.req.url);
  await next();
});
// admin responses carry data and are never shared-cache material
adminRoutes.use("*", async (c, next) => {
  await next();
  if (!c.res.headers.has("cache-control")) c.res.headers.set("cache-control", "no-store");
});

const MAX_BODY = 256 * 1024;
type Ctx = Context<AppBindings>;

const actorOf = (c: Ctx): svc.Actor => ({ email: adminOf(c).email, ip: c.get("ip") });
const zErrors = (e: z.ZodError) => ({ errors: e.issues.slice(0, 10).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })) });

async function bodyOf<S extends z.ZodTypeAny>(c: Ctx, schema: S): Promise<z.infer<S>> {
  const raw = await readJson(c.req.raw, MAX_BODY);
  if (raw === undefined) throw invalidRequest("a JSON body is required");
  const p = schema.safeParse(raw);
  if (!p.success) throw invalidRequest("request failed validation", zErrors(p.error));
  return p.data;
}
/** Optional body (e.g. POST /enrol-token): absent or {} is fine, anything else must be an empty object. */
async function emptyBody(c: Ctx): Promise<void> {
  const raw = await readJson(c.req.raw, 4096);
  if (raw === undefined) return;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw) || Object.keys(raw).length) throw invalidRequest("this endpoint takes no body");
}

const q = (c: Ctx, k: string): string | undefined => {
  const v = c.req.query(k);
  return v === undefined || v === "" ? undefined : v;
};
const limitQ = (c: Ctx): number => read.limitOf(q(c, "limit"));
const created = (c: Ctx, data: unknown) => c.json(data as Record<string, unknown>, 201, { "cache-control": "no-store" });

const slugS = z.string().regex(SLUG_RE);
const tzS = z.string().max(64).regex(/^(UTC|[A-Za-z]+(\/[A-Za-z0-9_+-]+){1,2})$/);
const SiteCreate = z.object({ site: slugS, name: z.string().min(1).max(128), timezone: tzS, edge_label: z.string().max(32).optional(), retention: intent.RetentionSchema.optional() }).strict();
const SitePatch = z.object({ name: z.string().min(1).max(128), timezone: tzS, edge_label: z.string().max(32), retention: intent.RetentionSchema }).partial().strict();
const SHAPES = z.enum(["probe", "collector", "dashboard", "runner"]);
const HostCreate = z.object({ name: z.string().min(1).max(128), site: slugS, shapes: z.array(SHAPES).max(4).optional() }).strict();
const HostPatch = z.object({ name: z.string().min(1).max(128), site: slugS }).partial().strict();
const ComponentCreate = z.object({ type: z.enum(["probe", "collector", "dashboard", "runner", "speedtest"]), id: slugS, config: z.record(z.string(), z.unknown()) }).strict();
const ComponentPatch = z.object({ config: z.record(z.string(), z.unknown()), enabled: z.boolean() }).partial().strict();
const SiteRelease = z.object({ version: z.string().regex(SEMVER_RE).max(64), canary_host_id: z.string().regex(HOST_ID_RE).nullable().optional() }).strict();
const ReleaseImport = z.object({ version: z.string().regex(SEMVER_RE).max(64), source: z.enum(["github", "upload"]) }).strict();
const UserCreate = z.object({ username: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/), role: z.enum(["viewer", "operator", "admin"]), hash: z.string().max(512) }).strict();
const NocCreate = z.object({ label: z.string().min(1).max(128), expires_in_h: z.number().int().min(1).max(8760).optional() }).strict();
const Snooze = z.object({ for: z.enum(["1h", "24h", "resolved"]) }).strict();

adminRoutes.get("/me", requireRole("viewer"), (c) => {
  const a = adminOf(c);
  return c.json({ email: a.email, role: a.role });
});

// ---- sites ----------------------------------------------------------------------------------------------
adminRoutes.get("/sites", requireRole("viewer"), async (c) => c.json(await read.listSites(c.env, limitQ(c), q(c, "cursor"))));
adminRoutes.post("/sites", requireRole("admin"), async (c) => {
  const b = await bodyOf(c, SiteCreate);
  await svc.createSite(c.env, actorOf(c), b);
  return created(c, await read.getSite(c.env, b.site));
});
adminRoutes.get("/sites/:site", requireRole("viewer"), async (c) => c.json(await read.getSite(c.env, c.req.param("site"))));
adminRoutes.patch("/sites/:site", requireRole("admin"), async (c) => {
  const site = c.req.param("site");
  const b = await bodyOf(c, SitePatch);
  if (Object.keys(b).length === 0) throw invalidRequest("nothing to change");
  await intent.updateSite(c.env, actorOf(c), site, b);
  return c.json(await read.getSite(c.env, site));
});
adminRoutes.delete("/sites/:site", requireRole("admin"), async (c) => {
  await intent.deleteSite(c.env, actorOf(c), c.req.param("site"));
  return c.body(null, 204);
});
adminRoutes.patch("/sites/:site/release", requireRole("admin"), async (c) => {
  const site = c.req.param("site");
  const b = await bodyOf(c, SiteRelease);
  await svc.setSiteRelease(c.env, actorOf(c), site, { version: b.version, canary_host_id: b.canary_host_id ?? null });
  return c.json(await read.getSite(c.env, site));
});
adminRoutes.get("/sites/:site/alerts", requireRole("viewer"), async (c) => c.json(await intent.getSiteAlerts(c.env, c.req.param("site"))));
adminRoutes.put("/sites/:site/alerts", requireRole("admin"), async (c) => {
  const raw = await readJson(c.req.raw, MAX_BODY);
  return c.json(await intent.putSiteAlerts(c.env, actorOf(c), c.req.param("site"), raw));
});
adminRoutes.post("/sites/:site/alerts/test", requireRole("admin"), async (c) => c.json(await intent.testSiteAlerts(c.env, actorOf(c), c.req.param("site"))));

// ---- hosts ----------------------------------------------------------------------------------------------
async function managerBase(c: Ctx): Promise<string> {
  const env = c.env;
  if (env.MANAGER_URL && env.MANAGER_URL.trim()) return env.MANAGER_URL.trim().replace(/\/+$/, "");
  const s = await env.DB.prepare("SELECT manager_url FROM settings WHERE org_id = 'default'").first<{ manager_url: string | null }>();
  return (s?.manager_url ?? new URL(c.req.url).origin).replace(/\/+$/, "");
}
const enrolCommand = (base: string, token: string): string => `curl -fsSL ${base}/install.sh | sudo bash -s -- ${token}`;

adminRoutes.get("/hosts", requireRole("viewer"), async (c) => c.json(await read.listHosts(c.env, { site: q(c, "site"), state: q(c, "state"), limit: limitQ(c), cursor: q(c, "cursor") })));
adminRoutes.post("/hosts", requireRole("admin"), async (c) => {
  const b = await bodyOf(c, HostCreate);
  const r = await svc.createHost(c.env, actorOf(c), { name: b.name, site: b.site });
  return created(c, {
    host: await read.getHost(c.env, r.host_id),
    enrol: { token: r.enrol_token, command: enrolCommand(await managerBase(c), r.enrol_token), expires_at: r.expires_at },
  });
});
adminRoutes.get("/hosts/:id", requireRole("viewer"), async (c) => c.json(await read.getHost(c.env, c.req.param("id"))));
adminRoutes.patch("/hosts/:id", requireRole("admin"), async (c) => {
  const id = c.req.param("id");
  const b = await bodyOf(c, HostPatch);
  if (Object.keys(b).length === 0) throw invalidRequest("nothing to change");
  await intent.updateHost(c.env, actorOf(c), id, b);
  return c.json(await read.getHost(c.env, id));
});
adminRoutes.delete("/hosts/:id", requireRole("admin"), async (c) => {
  await intent.deleteHost(c.env, actorOf(c), c.req.param("id"));
  return c.body(null, 204);
});
adminRoutes.post("/hosts/:id/enrol-token", requireRole("admin"), async (c) => {
  await emptyBody(c);
  const id = c.req.param("id");
  const h = await read.getHost(c.env, id);
  if (h.state !== "pending" && h.state !== "enrolled" && h.state !== "stale" && h.state !== "offline") throw new ApiError(409, "conflict", `a ${h.state} host cannot be enrolled`);
  const t = await svc.issueEnrolToken(c.env, actorOf(c), id);
  return created(c, { token: t.enrol_token, command: enrolCommand(await managerBase(c), t.enrol_token), expires_at: t.expires_at });
});
adminRoutes.post("/hosts/:id/decommission", requireRole("admin"), async (c) => {
  await emptyBody(c);
  const id = c.req.param("id");
  await svc.decommissionHost(c.env, actorOf(c), id);
  return c.json(await read.getHost(c.env, id), 202);
});
adminRoutes.post("/hosts/:id/rotate-agent", requireRole("admin"), async (c) => {
  await emptyBody(c);
  const id = c.req.param("id");
  const r = await svc.requestAgentRotation(c.env, actorOf(c), id);
  const h = await c.env.DB.prepare("SELECT desired_version FROM hosts WHERE host_id = ?1").bind(id).first<{ desired_version: number | null }>();
  return c.json({ host_id: id, action_id: r.action_id, desired_version: h?.desired_version ?? 0 }, 202);
});
adminRoutes.get("/hosts/:id/status", requireRole("viewer"), async (c) => {
  const id = c.req.param("id");
  if (!HOST_ID_RE.test(id)) throw notFound("no such host");
  const r = await c.env.DB.prepare(
    `SELECT h.host_id, h.state, h.desired_version, h.applied_version, s.received_at, s.report_json
     FROM hosts h LEFT JOIN status_latest s ON s.host_id = h.host_id WHERE h.host_id = ?1 AND h.state != 'removed'`,
  ).bind(id).first<{ host_id: string; state: string; desired_version: number | null; applied_version: number | null; received_at: string | null; report_json: string | null }>();
  if (!r) throw notFound("no such host");
  if (!r.report_json || !r.received_at) throw notFound("this host has not reported yet");
  return c.json({ host_id: r.host_id, state: r.state, received_at: r.received_at, desired_version: r.desired_version, applied_version: r.applied_version, report: JSON.parse(r.report_json) });
});
adminRoutes.get("/hosts/:id/components", requireRole("viewer"), async (c) => c.json(await read.listHostComponents(c.env, c.req.param("id"), limitQ(c), q(c, "cursor"))));
adminRoutes.post("/hosts/:id/components", requireRole("admin"), async (c) => {
  const b = await bodyOf(c, ComponentCreate);
  const hostId = c.req.param("id");
  if (!HOST_ID_RE.test(hostId)) throw notFound("no such host");
  const r = await svc.addComponent(c.env, actorOf(c), hostId, { type: b.type, id: b.id, config: b.config });
  return created(c, await read.getComponent(c.env, r.component_id));
});

// ---- components -----------------------------------------------------------------------------------------
adminRoutes.patch("/components/:cid", requireRole("admin"), async (c) => {
  const id = c.req.param("cid");
  const b = await bodyOf(c, ComponentPatch);
  await svc.patchComponent(c.env, actorOf(c), id, b);
  return c.json(await read.getComponent(c.env, id));
});
adminRoutes.delete("/components/:cid", requireRole("admin"), async (c) => {
  await svc.deleteComponent(c.env, actorOf(c), c.req.param("cid"));
  return c.body(null, 204);
});
adminRoutes.post("/components/:cid/restart", requireRole("admin"), async (c) => {
  await emptyBody(c);
  return c.json(await intent.restartComponent(c.env, actorOf(c), c.req.param("cid")), 202);
});
adminRoutes.put("/components/:cid/ports", requireRole("admin"), async (c) => {
  const raw = await readJson(c.req.raw, MAX_BODY);
  if (raw === null || typeof raw !== "object" || Array.isArray(raw) || !Array.isArray((raw as { ports?: unknown }).ports) || Object.keys(raw).length !== 1) throw invalidRequest('body must be {"ports": [...]}');
  const ports = (raw as { ports: unknown[] }).ports;
  if (ports.length < 1 || ports.length > 64) throw invalidRequest("ports must hold 1..64 entries");
  return c.json(await intent.putProbePorts(c.env, actorOf(c), c.req.param("cid"), ports));
});
adminRoutes.post("/components/:cid/rotate", requireRole("admin"), async (c) => {
  await emptyBody(c);
  return c.json(await svc.rotateComponentTokens(c.env, actorOf(c), c.req.param("cid")));
});

// ---- releases -------------------------------------------------------------------------------------------
adminRoutes.get("/releases", requireRole("viewer"), async (c) => c.json(await read.listReleases(c.env, limitQ(c), q(c, "cursor"))));
adminRoutes.post("/releases/import", requireRole("admin"), async (c) => {
  const b = await bodyOf(c, ReleaseImport);
  if (b.source !== "github") throw invalidRequest('source "upload" uses POST /releases/upload (multipart)');
  const r = await importFromGithub(c.env, actorOf(c), b.version);
  return created(c, await read.getReleaseByVersion(c.env, r.version));
});
adminRoutes.post("/releases/upload", requireRole("admin"), async (c) => {
  const r = await importFromUpload(c.env, actorOf(c), c.req.raw);
  return created(c, await read.getReleaseByVersion(c.env, r.version));
});

// ---- dashboards -----------------------------------------------------------------------------------------
adminRoutes.get("/dashboards/:did/users", requireRole("admin"), async (c) => {
  const d = await read.dashboardSlug(c.env, c.req.param("did"));
  return c.json(await read.listDashboardUsers(c.env, d.slug, limitQ(c), q(c, "cursor")));
});
adminRoutes.post("/dashboards/:did/users", requireRole("admin"), async (c) => {
  const d = await read.dashboardSlug(c.env, c.req.param("did"));
  const b = await bodyOf(c, UserCreate);
  const r = await svc.createDashboardUser(c.env, actorOf(c), d.slug, b);
  const u = (await read.listDashboardUsers(c.env, d.slug, 1000, undefined)).items.find((x) => x.usr_id === r.usr_id);
  return created(c, u ?? { usr_id: r.usr_id, username: b.username, role: b.role, created_at: isoNow() });
});
adminRoutes.delete("/dashboards/:did/users/:usr", requireRole("admin"), async (c) => {
  const d = await read.dashboardSlug(c.env, c.req.param("did"));
  await intent.deleteDashboardUser(c.env, actorOf(c), d.slug, c.req.param("usr"));
  return c.body(null, 204);
});
adminRoutes.get("/dashboards/:did/noc-tokens", requireRole("admin"), async (c) => {
  const d = await read.dashboardSlug(c.env, c.req.param("did"));
  return c.json(await read.listNocTokens(c.env, d.slug, limitQ(c), q(c, "cursor")));
});
adminRoutes.post("/dashboards/:did/noc-tokens", requireRole("admin"), async (c) => {
  const d = await read.dashboardSlug(c.env, c.req.param("did"));
  const b = await bodyOf(c, NocCreate);
  const expires = b.expires_in_h ? isoPlusSeconds(b.expires_in_h * 3600) : null;
  const r = await svc.createNocToken(c.env, actorOf(c), d.slug, { label: b.label, expires_at: expires });
  const row = await c.env.DB.prepare("SELECT noc_id, label, expires_at, revoked_at, created_at FROM noc_tokens WHERE noc_id = ?1").bind(r.noc_id).first<Record<string, unknown>>();
  const base = await dashboardBase(c.env, d.component_id);
  // the token is shown ONCE here; the NOC page takes it by POST, never in a URL
  return created(c, { noc: { ...row, role: "viewer" }, token: r.token, url: base ? `${base}/noc` : null });
});
adminRoutes.delete("/dashboards/:did/noc-tokens/:noc", requireRole("admin"), async (c) => {
  const d = await read.dashboardSlug(c.env, c.req.param("did"));
  const noc = c.req.param("noc");
  const owner = await c.env.DB.prepare("SELECT 1 AS x FROM noc_tokens WHERE noc_id = ?1 AND dashboard_slug = ?2").bind(noc, d.slug).first();
  if (!owner) throw notFound("no such NOC token");
  await svc.revokeNocToken(c.env, actorOf(c), noc);
  return c.body(null, 204);
});
adminRoutes.post("/dashboards/:did/sso", requireRole("viewer"), async (c) => {
  await emptyBody(c);
  const page = await buildSsoPage(c.env, adminOf(c), c.get("ip"), c.req.param("did"));
  return new Response(page.html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": page.csp, "referrer-policy": "no-referrer" },
  });
});

async function dashboardBase(env: Env, componentId: string): Promise<string | null> {
  const r = await env.DB.prepare("SELECT c.config_json, c.facts_json, h.facts_json AS hf FROM components c JOIN hosts h ON h.host_id = c.host_id WHERE c.component_id = ?1").bind(componentId).first<{ config_json: string; facts_json: string; hf: string }>();
  if (!r) return null;
  try {
    const url = (JSON.parse(r.config_json) as { url?: string }).url ?? (JSON.parse(r.facts_json) as { facts?: { url?: string } }).facts?.url;
    if (url) return url.replace(/\/+$/, "");
  } catch {
    /* fall through to the management address */
  }
  const ip = mgmtIpOf(r.hf);
  return ip ? `https://${ip}` : null;
}

// ---- integrations ---------------------------------------------------------------------------------------
adminRoutes.get("/integrations/:kind", requireRole("viewer"), async (c) => c.json(await intent.getIntegration(c.env, c.req.param("kind"))));
adminRoutes.put("/integrations/:kind", requireRole("owner"), async (c) => c.json(await intent.putIntegration(c.env, actorOf(c), c.req.param("kind"), await readJson(c.req.raw, MAX_BODY))));
adminRoutes.post("/integrations/:kind/test", requireRole("owner"), async (c) => {
  await emptyBody(c);
  return c.json(await intent.testIntegration(c.env, actorOf(c), c.req.param("kind")));
});

// ---- drills: WP-4 step 3 --------------------------------------------------------------------------------
adminRoutes.all("/drills", requireRole("viewer"), () => {
  throw new ApiError(501, "not_implemented", "drills are not implemented yet");
});
adminRoutes.all("/drills/*", requireRole("viewer"), () => {
  throw new ApiError(501, "not_implemented", "drills are not implemented yet");
});

// ---- status, fleet --------------------------------------------------------------------------------------
/** Fleet responses: ETag over the payload (ignoring as_of) + `Cache-Control: private, max-age=15`; honours If-None-Match. */
async function fleetJson(c: Ctx, data: unknown): Promise<Response> {
  const text = JSON.stringify(data);
  const etag = `"${(await sha256Hex(text.replace(/"as_of":"[^"]*"/g, ""))).slice(0, 32)}"`;
  const headers = { etag, "cache-control": "private, max-age=15" };
  const inm = c.req.header("If-None-Match");
  if (inm && inm.split(",").some((p) => p.trim().replace(/^W\//, "") === etag || p.trim() === "*")) return new Response(null, { status: 304, headers });
  return new Response(text, { status: 200, headers: { ...headers, "content-type": "application/json" } });
}

adminRoutes.get("/overview", requireRole("viewer"), async (c) => c.json(await overview(c.env)));
adminRoutes.get("/fleet/summary", requireRole("viewer"), async (c) => fleetJson(c, await fleetSummary(c.env)));
adminRoutes.get("/fleet/sites", requireRole("viewer"), async (c) => fleetJson(c, await fleetSites(c.env)));
adminRoutes.get("/fleet/hosts", requireRole("viewer"), async (c) =>
  fleetJson(c, await fleetHosts(c.env, { site: q(c, "site"), type: q(c, "type"), health: q(c, "health"), state: q(c, "state"), version: q(c, "version"), q: q(c, "q"), sort: q(c, "sort"), limit: limitQ(c), cursor: q(c, "cursor") })),
);
adminRoutes.get("/fleet/hosts/:id/metrics", requireRole("viewer"), async (c) => fleetJson(c, await hostMetrics(c.env, c.req.param("id"), q(c, "range") ?? "24h", q(c, "keys"))));
adminRoutes.get("/fleet/components/:cid/metrics", requireRole("viewer"), async (c) => fleetJson(c, await componentMetrics(c.env, c.req.param("cid"), q(c, "range") ?? "24h", q(c, "keys"))));
adminRoutes.get("/fleet/top", requireRole("viewer"), async (c) => {
  const lim = q(c, "limit");
  if (lim !== undefined && !/^\d{1,3}$/.test(lim)) throw invalidRequest("limit must be an integer 1..100");
  return fleetJson(c, await fleetTop(c.env, q(c, "metric") ?? "cpu", lim === undefined ? undefined : Number(lim)));
});

// ---- issues ---------------------------------------------------------------------------------------------
adminRoutes.get("/issues", requireRole("viewer"), async (c) =>
  c.json(await listIssues(c.env, { severity: q(c, "severity"), site: q(c, "site"), kind: q(c, "kind"), state: q(c, "state"), limit: limitQ(c), cursor: q(c, "cursor"), include_snoozed: q(c, "include_snoozed") === "true" })),
);
adminRoutes.post("/issues/:id/snooze", requireRole("admin"), async (c) => {
  const b = await bodyOf(c, Snooze);
  return c.json(await snoozeIssue(c.env, adminOf(c).email, c.get("ip"), c.req.param("id"), b.for));
});
adminRoutes.delete("/issues/:id/snooze", requireRole("admin"), async (c) => {
  await unsnoozeIssue(c.env, adminOf(c).email, c.get("ip"), c.req.param("id"));
  return c.body(null, 204);
});

// ---- settings -------------------------------------------------------------------------------------------
adminRoutes.get("/settings/fleet-thresholds", requireRole("viewer"), async (c) => c.json(await intent.getThresholds(c.env)));
adminRoutes.put("/settings/fleet-thresholds", requireRole("admin"), async (c) => c.json(await intent.putThresholds(c.env, actorOf(c), await readJson(c.req.raw, MAX_BODY))));
adminRoutes.get("/settings/platform-webhook", requireRole("viewer"), async (c) => c.json(await intent.getPlatformWebhook(c.env)));
adminRoutes.put("/settings/platform-webhook", requireRole("admin"), async (c) => c.json(await intent.putPlatformWebhook(c.env, actorOf(c), await readJson(c.req.raw, MAX_BODY))));
adminRoutes.post("/settings/platform-webhook/test", requireRole("admin"), async (c) => {
  await emptyBody(c);
  return c.json(await intent.testPlatformWebhook(c.env, actorOf(c)));
});
adminRoutes.get("/settings", requireRole("viewer"), async (c) => c.json(await intent.getSettings(c.env)));
adminRoutes.patch("/settings", requireRole("owner"), async (c) => c.json(await intent.patchSettings(c.env, actorOf(c), await readJson(c.req.raw, MAX_BODY))));

// ---- audit ----------------------------------------------------------------------------------------------
adminRoutes.get("/audit", requireRole("admin"), async (c) => c.json(await read.listAudit(c.env, { from: q(c, "from"), to: q(c, "to"), actor: q(c, "actor"), resource: q(c, "resource"), limit: limitQ(c), cursor: q(c, "cursor") })));

let managerUrlKnown = false;

/** Records this manager's own https origin (SSO handoff target) from the first authenticated admin request. */
async function learnManagerUrl(env: Env, url: string): Promise<void> {
  if (managerUrlKnown) return;
  if (env.MANAGER_URL && env.MANAGER_URL.trim()) {
    managerUrlKnown = true;
    return;
  }
  const u = new URL(url);
  if (u.protocol !== "https:") return;
  await env.DB.prepare("UPDATE settings SET manager_url = ?1, updated_at = ?2 WHERE org_id = 'default' AND manager_url IS NULL")
    .bind(u.origin, new Date().toISOString())
    .run();
  managerUrlKnown = true;
}

