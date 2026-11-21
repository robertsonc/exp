// Admission check for speedtest / runner components (CR-m6-manager): the component config is validated and the
// resulting host layout (the "all-in-one" profile: probe + collector + runner + speedtest on ONE box) must not
// bind the same port twice. Refused up front with 422; the compiler also fails closed (compile/speedtest.ts).
import type { z } from "zod";
import { loadWorld } from "../compile/load";
import { portConflicts } from "../compile/speedtest";
import type { WComponent } from "../compile/types";
import type { Env } from "../env";
import { ApiError } from "../errors";
import { CorrelationConfigSchema, SpeedtestComponentConfigSchema } from "./schemas";

const issues = (e: z.ZodError) => ({ errors: e.issues.slice(0, 10).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })) });

export interface Candidate {
  hostId: string;
  componentId: string;
  type: WComponent["type"];
  slug: string;
  config: Record<string, unknown>;
  enabled: boolean;
}

/**
 * Validates the config of a speedtest / runner component and refuses a host layout with colliding listeners.
 * Any component added to (or changed on) a host that runs a speedtest is checked, so a dashboard that would take
 * the speedtest's port 80 is refused too.
 */
export async function checkSpeedtestLayout(env: Env, c: Candidate): Promise<void> {
  if (c.type === "speedtest") {
    const p = SpeedtestComponentConfigSchema.safeParse(c.config);
    if (!p.success) throw new ApiError(422, "invalid_config", "speedtest component config failed validation", issues(p.error));
  } else if (c.config.correlation !== undefined) {
    const p = CorrelationConfigSchema.safeParse(c.config.correlation);
    if (!p.success) throw new ApiError(422, "invalid_config", "runner correlation config failed validation", issues(p.error));
  }
  if (!c.enabled) return;
  const world = await loadWorld(env);
  const host = world.hosts[c.hostId];
  if (!host) return;
  const cand: WComponent = {
    component_id: c.componentId,
    host_id: c.hostId,
    type: c.type,
    slug: c.slug,
    config: c.config,
    enabled: true,
    facts: {},
    created_at: "9999-12-31T23:59:59.999Z",
  };
  world.components = [...world.components.filter((x) => x.component_id !== c.componentId), cand];
  if (!world.components.some((x) => x.host_id === c.hostId && x.enabled && x.type === "speedtest")) return;
  const conflicts = portConflicts(world, c.hostId);
  if (conflicts.length > 0) throw new ApiError(422, "port_collision", `this layout binds a port twice: ${conflicts[0]}`, { conflicts: conflicts.slice(0, 10) });
}
