// The site lines board (CR-site-lines-board): a probe port's network / reference are the manager's. They reach the
// collector's config as the board map and never the probe's config (the probe contract is unchanged).
import { describe, expect, it } from "vitest";
import { boardPorts, compile } from "../../src/compile/compile";
import type { DesiredBody } from "../../src/compile/types";
import { validateAgainst } from "./schemas";
import { C_PROBE, H_COL, H_PROBE, baseWorld } from "./world";

const build = (host: string, w = baseWorld()) => {
  const r = compile(w, host);
  expect(r.doc, r.warnings.join("; ")).not.toBeNull();
  return r.doc as DesiredBody & { components: Array<Record<string, any>> };
};

function boardWorld() {
  const w = baseWorld();
  const probe = w.components.find((c) => c.component_id === C_PROBE)!;
  const ports = probe.config.ports as Array<Record<string, unknown>>;
  ports[0] = { ...ports[0], network: "event" };
  if (ports[1]) ports[1] = { ...ports[1], network: "control", reference: true };
  return w;
}

describe("board ports", () => {
  it("the probe's config carries no board fields and still validates", () => {
    const d = build(H_PROBE, boardWorld());
    const probe = d.components.find((c) => c.type === "probe")!;
    for (const p of probe.config.ports as Array<Record<string, unknown>>) {
      expect(p).not.toHaveProperty("network");
      expect(p).not.toHaveProperty("reference");
    }
    expect(validateAgainst("probe.config.schema.json", probe.config)).toEqual([]);
  });

  it("the collector's config lists the probe's board ports with medium and reference, and validates", () => {
    const d = build(H_COL, boardWorld());
    const col = d.components.find((c) => c.type === "collector")!;
    const entry = (col.config.probes as Array<Record<string, any>>).find((p) => p.probe_id === "probe-a1")!;
    expect(entry.ports[0]).toEqual({ id: "c01", network: "event", media: "wired", reference: false });
    expect(validateAgainst("collector.config.schema.json", col.config)).toEqual([]);
  });

  it("only client and Wi-Fi ports with a network are on the board", () => {
    expect(boardPorts({ ports: [
      { id: "c01", role: "client", network: "event" }, { id: "w01", role: "wifi", network: "event" },
      { id: "s01", role: "target", network: "event" }, { id: "c02", role: "client" },
    ] })).toEqual([
      { id: "c01", network: "event", media: "wired", reference: false },
      { id: "w01", network: "event", media: "wireless", reference: false },
    ]);
  });

  it("a probe without board ports compiles exactly as before (no ports key in the collector's entry)", () => {
    const d = build(H_COL);
    const col = d.components.find((c) => c.type === "collector")!;
    for (const p of col.config.probes as Array<Record<string, unknown>>) expect(p).not.toHaveProperty("ports");
  });
});
