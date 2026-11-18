// exp-manager Worker entry. Routes: /api/admin/v1/* (Access JWT verified here), /api/agent/v1/*
// (per-agent bearer), /install.sh and /healthz (public). Everything else is served by the Static
// Assets binding (the admin SPA) via the not-found fallthrough, or from the embedded copy (--embed-ui).
import { Hono } from "hono";
import { adminRoutes } from "./admin/routes";
import { agentRoutes } from "./agent/routes";
import { runScheduled } from "./cron";
import type { AppBindings, Env } from "./env";
import { ApiError, ConfigError, errorResponse, notFound } from "./errors";
import { renderInstallSh } from "./install/install";
import { UI_ASSETS, UI_HEADERS } from "../.generated/ui-assets";
import { serveEmbedded } from "./ui/embedded";

export const app = new Hono<AppBindings>();

app.use("*", async (c, next) => {
  c.set("ip", c.req.header("CF-Connecting-IP") ?? "unknown");
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "no-referrer");
  c.header("X-Frame-Options", "DENY");
  if (!c.res.headers.has("content-security-policy") && (c.res.headers.get("content-type") ?? "").match(/^(text\/html|application\/json)/i) && new URL(c.req.url).pathname.startsWith("/api/")) {
    c.header("Content-Security-Policy", "frame-ancestors 'none'");
  }
});

app.get("/healthz", (c) => c.text("ok", 200, { "cache-control": "no-store" }));

app.get("/install.sh", async (c) => {
  const text = await renderInstallSh(c.env, c.req.raw);
  return new Response(text, { status: 200, headers: { "content-type": "text/x-shellscript; charset=utf-8", "cache-control": "no-store" } });
});

app.route("/api/admin/v1", adminRoutes);
app.route("/api/agent/v1", agentRoutes);

app.notFound(async (c) => {
  const p = new URL(c.req.url).pathname;
  // anything outside the API is the SPA (served from static assets); the API itself answers 404 JSON
  if (!p.startsWith("/api/") && p !== "/install.sh" && p !== "/healthz") {
    if (c.env.ASSETS) return c.env.ASSETS.fetch(c.req.raw);
    // deploy.sh --embed-ui: no ASSETS binding, the UI is bundled into the script (empty map in the default build)
    if (Object.keys(UI_ASSETS).length > 0) return serveEmbedded(c.req.raw, UI_ASSETS, UI_HEADERS);
  }
  return errorResponse(notFound("no such path"));
});

app.onError((err, c) => {
  if (err instanceof ApiError) return errorResponse(err);
  if (err instanceof ConfigError) {
    console.error("config error", err.code);
    return errorResponse(new ApiError(503, "unavailable", err.message, {}, { "retry-after": "60" }));
  }
  // no stack traces or messages (which could carry data) reach the client
  console.error("unhandled error", err instanceof Error ? err.name : typeof err);
  return errorResponse(new ApiError(500, "internal_error", "internal error"));
});

export default {
  fetch: (req: Request, env: Env, ctx: ExecutionContext) => app.fetch(req, env, ctx),
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runScheduled(env, controller.cron));
  },
} satisfies ExportedHandler<Env>;
