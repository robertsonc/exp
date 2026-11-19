// Runs for every stored status report (05-manager.md sections 13 and 14): roll-ups first (the issue rules
// read windows from them), then issue rules. Each stage is isolated: a failure is logged without detail
// and never fails the report that was already stored.
import type { StatusReport } from "./agent/status-schema";
import type { Env } from "./env";
import { recordRollups } from "./fleet/rollup";
import { recordProbeRows } from "./fleet/probes";
import { evaluateReport } from "./issues/engine";

export interface StatusStored {
  hostId: string;
  site: string;
  receivedAt: string;
  report: StatusReport;
  components: Array<{ component_id: string; type: string; slug: string }>;
}

export async function onStatusStored(env: Env, evt: StatusStored): Promise<void> {
  const ms = Date.parse(evt.receivedAt);
  try {
    await recordRollups(env, evt.hostId, ms, evt.report, evt.components);
  } catch (e) {
    console.error("rollups failed", e instanceof Error ? e.name : "error");
  }
  try {
    await recordProbeRows(env, evt.receivedAt, evt.report, evt.components);
  } catch (e) {
    console.error("probe rows failed", e instanceof Error ? e.name : "error");
  }
  try {
    await evaluateReport(env, evt.hostId, evt.report, ms);
  } catch (e) {
    console.error("issue evaluation failed", e instanceof Error ? e.name : "error");
  }
}
