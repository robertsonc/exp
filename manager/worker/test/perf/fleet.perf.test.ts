// 05-manager.md section 15 item 11: fleet API p95 < 300 ms with 500 hosts x 30 days of roll-ups seeded
// (scripts/lib/seed-fleet.ts, the same generator as `npm run seed:demo -- --scale 500`). Local D1 / miniflare.
// Run with `npm run test:perf` (several minutes: most of the time is seeding ~3 M roll-up rows).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildSeed } from "../../../scripts/lib/seed-fleet";
import { type Harness, harness } from "../admin-harness";
import { env, resetDb } from "../helpers";

const SCALE = Number(process.env.EXP_PERF_SCALE ?? 500);
const SAMPLES = Number(process.env.EXP_PERF_SAMPLES ?? 30);
const P95_BUDGET_MS = 300;

let h: Harness;
let hostId = "";
let probeCid = "";
let colCid = "";

beforeAll(async () => {
  await resetDb();
  const t0 = Date.now();
  const seed = buildSeed({ scale: SCALE, nowMs: Date.now() });
  for (const s of seed.reset) await env.DB.prepare(s).run();
  for (const s of seed.statements) await env.DB.prepare(s).run();
  // seeding takes minutes: bring the hosts' last_seen back to "now" so they are fresh, like a live fleet
  const now = new Date().toISOString();
  await env.DB.prepare("UPDATE hosts SET last_seen = ?1 WHERE state = 'enrolled'").bind(now).run();
  console.log(`perf: seeded ${seed.summary.hosts} hosts / ${seed.summary.components} components in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
  h = await harness();
  hostId = seed.summary.host_ids[10] as string;
  probeCid = ((await env.DB.prepare("SELECT component_id FROM components WHERE type = 'probe' LIMIT 1").first<{ component_id: string }>()) as { component_id: string }).component_id;
  colCid = ((await env.DB.prepare("SELECT component_id FROM components WHERE type = 'collector' LIMIT 1").first<{ component_id: string }>()) as { component_id: string }).component_id;
});
afterAll(() => h?.restore());

function p95(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil(0.95 * s.length) - 1)] as number;
}

describe(`fleet API at ${SCALE} hosts x 30 days`, () => {
  it("has the data the budget is about", async () => {
    const c = async (t: string): Promise<number> => ((await env.DB.prepare(`SELECT count(*) AS n FROM ${t}`).first<{ n: number }>()) as { n: number }).n;
    expect(await c("hosts")).toBe(SCALE);
    // 720 hourly buckets per host (stale / offline scenario hosts stop earlier)
    expect(await c("fleet_host_1h")).toBeGreaterThan(SCALE * 700 - 4 * 720);
    expect(await c("fleet_host_5m")).toBeGreaterThan(SCALE * 570 - 4 * 577);
  });

  const cases: Array<[string, () => string]> = [
    ["GET /fleet/summary", () => "/fleet/summary"],
    ["GET /fleet/sites", () => "/fleet/sites"],
    ["GET /fleet/hosts (first page, 100)", () => "/fleet/hosts?limit=100"],
    ["GET /fleet/hosts (all 500, sorted by cpu)", () => "/fleet/hosts?limit=500&sort=-cpu_pct"],
    ["GET /fleet/hosts (filtered: site + health)", () => "/fleet/hosts?site=hall-a&health=ok&limit=100"],
    ["GET /fleet/hosts (search)", () => "/fleet/hosts?q=probe-04&limit=50"],
    ["GET /fleet/top?metric=cpu", () => "/fleet/top?metric=cpu&limit=10"],
    ["GET /fleet/hosts/{id}/metrics 24h", () => `/fleet/hosts/${hostId}/metrics?range=24h`],
    ["GET /fleet/hosts/{id}/metrics 30d", () => `/fleet/hosts/${hostId}/metrics?range=30d`],
    ["GET /fleet/components/{id}/metrics 7d (probe)", () => `/fleet/components/${probeCid}/metrics?range=7d`],
    ["GET /fleet/components/{id}/metrics 30d (collector)", () => `/fleet/components/${colCid}/metrics?range=30d`],
    ["GET /issues", () => "/issues?limit=100"],
    ["GET /overview", () => "/overview"],
  ];
  for (const [name, path] of cases) {
    it(`${name}: p95 < ${P95_BUDGET_MS} ms`, async () => {
      const p = path();
      const first = await h.api("viewer", "GET", p);
      expect(first.status, await first.clone().text()).toBe(200);
      await first.arrayBuffer();
      const times: number[] = [];
      for (let i = 0; i < SAMPLES; i++) {
        const t = performance.now();
        const res = await h.api("viewer", "GET", p);
        await res.arrayBuffer();
        times.push(performance.now() - t);
        expect(res.status).toBe(200);
      }
      const v = p95(times);
      console.log(`perf: ${name.padEnd(52)} p50 ${[...times].sort((a, b) => a - b)[Math.floor(times.length / 2)]?.toFixed(1)} ms  p95 ${v.toFixed(1)} ms`);
      expect(v).toBeLessThan(P95_BUDGET_MS);
    });
  }
});
