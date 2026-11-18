// Cron handlers (05-manager.md section 11).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { orphanedR2, retireActions, runDaily, runEveryFiveMinutes, runHourly, runScheduled } from "../../src/cron";
import { setClock, isoNow } from "../../src/util/time";
import { type Harness, harness } from "../admin-harness";
import { T0, at, report, useClock, feed } from "../fleet-helpers";
import { env, fullScenario, getDesired, resetDb, seedSiteWithRelease } from "../helpers";
import { createHost } from "../../src/admin/service";
import { ADMIN_ACTOR } from "../helpers";
import { prepareRotateSecret, getSecretByOwner } from "../../src/secrets/store";
import { newToken } from "../../src/secrets/tokens";

let h: Harness;
beforeEach(async () => {
  await resetDb();
  useClock(T0);
  h = await harness();
  await seedSiteWithRelease("hall-b", "0.1.0");
});
afterEach(() => {
  h.restore();
  setClock(null);
});

const n = async (sql: string): Promise<number> => (await env.DB.prepare(sql).first<{ n: number }>())!.n;

describe("every 5 minutes", () => {
  it("expires unused enrol tokens (used ones are kept), drops previous_* secrets past grace, prunes old status history", async () => {
    const t = await createHost(env, ADMIN_ACTOR, { name: "h1", site: "hall-b" });
    expect(await n("SELECT COUNT(*) AS n FROM enrol_tokens")).toBe(1);
    await runEveryFiveMinutes(env, at(30)); // still inside the hour
    expect(await n("SELECT COUNT(*) AS n FROM enrol_tokens")).toBe(1);
    await runEveryFiveMinutes(env, at(61));
    expect(await n("SELECT COUNT(*) AS n FROM enrol_tokens")).toBe(0);
    void t;

    const sc = await fullScenario();
    useClock(T0);
    const sec = (await getSecretByOwner(env, sc.probeId, "ingest_token"))!;
    await env.DB.batch([await prepareRotateSecret(env, sec, newToken("expi"), true)]);
    const hasPrev = async () => (await getSecretByOwner(env, sc.probeId, "ingest_token"))!.previous_ciphertext !== null;
    expect(await hasPrev()).toBe(true);
    await runEveryFiveMinutes(env, T0 + 5 * 60_000);
    expect(await hasPrev()).toBe(true); // 10-minute overlap not over
    await runEveryFiveMinutes(env, T0 + 11 * 60_000);
    expect(await hasPrev()).toBe(false);
    const row = (await getSecretByOwner(env, sc.probeId, "ingest_token"))!;
    expect(row.previous_hash).toBeNull();

    // status_history: rows older than 7 days go
    await env.DB.prepare("INSERT INTO status_history (org_id, host_id, received_at, report_json, created_at, updated_at) VALUES ('default', ?1, ?2, '{}', ?2, ?2)").bind(sc.col.host_id, new Date(T0 - 8 * 86400_000).toISOString()).run();
    await env.DB.prepare("INSERT INTO status_history (org_id, host_id, received_at, report_json, created_at, updated_at) VALUES ('default', ?1, ?2, '{}', ?2, ?2)").bind(sc.col.host_id, new Date(T0 - 86400_000).toISOString()).run();
    const before = await n("SELECT COUNT(*) AS n FROM status_history");
    await runEveryFiveMinutes(env, T0);
    expect(await n("SELECT COUNT(*) AS n FROM status_history")).toBe(before - 1);
  });

  it("retires consumed restart actions after 15 minutes (rotate_agent_secret waits for its own consumption)", async () => {
    const sc = await fullScenario();
    useClock(T0);
    const r = await h.json<{ action_id: string }>("admin", "POST", `/components/${sc.probeId}/restart`, {});
    await h.json("admin", "POST", `/hosts/${sc.probe.host_id}/rotate-agent`, {});
    const acts = async () => ((await (await getDesired(sc.probe.secret)).json()) as { actions: Array<{ id: string; type: string }> }).actions.map((a) => a.type).sort();
    expect(await acts()).toEqual(["restart_component", "rotate_agent_secret"]);
    expect(await retireActions(env, T0 + 10 * 60_000)).toBe(0);
    expect(await retireActions(env, T0 + 20 * 60_000)).toBe(1);
    expect(await acts()).toEqual(["rotate_agent_secret"]);
    void r;
  });

  it("is isolated per job and the scheduled() dispatcher knows all three schedules", async () => {
    await runScheduled(env, "*/5 * * * *");
    await runScheduled(env, "0 * * * *");
    await runScheduled(env, "0 3 * * *");
    await runScheduled(env, "nonsense");
  });
});

describe("hourly and daily", () => {
  it("hourly compacts and prunes (roll-ups, resolved issues > 30 d, expired snoozes)", async () => {
    const sc = await fullScenario();
    await feed(sc.col.host_id, at(0), report({ cpu: 40 }));
    await runHourly(env, at(70));
    expect(await n("SELECT COUNT(*) AS n FROM fleet_host_1h")).toBe(1);
    const old = new Date(at(0) - 31 * 86400_000).toISOString();
    await env.DB.prepare(
      `INSERT INTO issues (issue_id, org_id, kind, severity, host_id, site, opened_at, resolved_at, clean_reports, detail, created_at, updated_at)
       VALUES ('iss_OLD', 'default', 'disk_high', 'warn', ?1, 'hall-b', ?2, ?2, 2, '', ?2, ?2), ('iss_NEW', 'default', 'disk_high', 'warn', ?1, 'hall-b', ?3, ?3, 2, '', ?3, ?3)`,
    ).bind(sc.col.host_id, old, new Date(at(0) - 86400_000).toISOString()).run();
    await env.DB.prepare("INSERT INTO issue_snoozes (org_id, kind, host_id, until, until_resolved, created_by, created_at, updated_at) VALUES ('default', 'disk_high', ?1, ?2, 0, 'x', 'x', 'x')").bind(sc.col.host_id, new Date(at(0) - 3600_000).toISOString()).run();
    await runHourly(env, at(70));
    expect((await env.DB.prepare("SELECT issue_id FROM issues").all<{ issue_id: string }>()).results!.map((r) => r.issue_id)).toEqual(["iss_NEW"]);
    expect(await n("SELECT COUNT(*) AS n FROM issue_snoozes")).toBe(0);
  });

  it("daily prunes the audit log (> 1 year, configurable) and reports orphaned R2 objects without deleting them", async () => {
    await seedSiteWithRelease("hall-c", "0.5.0").catch(() => undefined);
    const keep = (await env.DB.prepare("SELECT r2_key FROM artifacts LIMIT 1").first<{ r2_key: string }>())?.r2_key;
    await env.ARTIFACTS.put("artifacts/art_ORPHAN", new Uint8Array([1, 2, 3]));
    await env.DB.prepare("INSERT INTO audit (evt_id, org_id, ts, actor, action, resource, details_json, created_at, updated_at) VALUES ('evt_old','default',?1,'x','old','r','{}',?1,?1), ('evt_new','default',?2,'x','new','r','{}',?2,?2)")
      .bind(new Date(T0 - 400 * 86400_000).toISOString(), new Date(T0 - 5 * 86400_000).toISOString()).run();
    // fresh objects (possibly mid-import) are not reported; a day later the orphan is
    expect((await orphanedR2(env, Date.now())).count).toBe(0);
    const later = Date.now() + 2 * 86400_000;
    const rep = await orphanedR2(env, later);
    expect(rep.sample).toEqual(["artifacts/art_ORPHAN"]);
    expect(rep.sample).not.toContain(keep);
    await runDaily(env, later);
    expect((await env.DB.prepare("SELECT evt_id FROM audit WHERE evt_id LIKE 'evt_%' AND actor = 'x'").all<{ evt_id: string }>()).results!.map((r) => r.evt_id)).toEqual(["evt_new"]);
    expect(await env.ARTIFACTS.get("artifacts/art_ORPHAN")).not.toBeNull(); // reported, never deleted
    const ev = await env.DB.prepare("SELECT actor, details_json FROM audit WHERE action = 'r2.orphans'").first<{ actor: string; details_json: string }>();
    expect(ev!.actor).toBe("system");
    expect(JSON.parse(ev!.details_json)).toMatchObject({ count: 1, sample: ["artifacts/art_ORPHAN"] });
    void isoNow;
  });
});
