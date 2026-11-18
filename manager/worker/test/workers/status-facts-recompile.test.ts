// A2.5 e2e finding: install.sh enrols with MINIMAL facts (no interfaces), so a collector/dashboard host (no probe ports step
// to trigger a recompile) compiled to an empty document at enrol and never converged. The first full status report must
// recompile the host; identical facts afterwards must not churn the document version.
import { beforeEach, describe, expect, it } from "vitest";
import * as svc from "../../src/admin/service";
import { ADMIN_ACTOR, FACTS, call, env, getDesired, json, postStatus, resetDb, seedSiteWithRelease, statusReport } from "../helpers";

type Doc = { version: number; components: Array<{ type: string; config: Record<string, any> }> };

beforeEach(async () => {
  await resetDb();
  await seedSiteWithRelease("hall-b", "0.1.0");
});

describe("host facts change recompiles", () => {
  it("collector + dashboard host enrolled with minimal facts gets its components from the first full status report", async () => {
    const h = await svc.createHost(env, ADMIN_ACTOR, { name: "all-in-one", site: "hall-b" });
    await svc.addComponent(env, ADMIN_ACTOR, h.host_id, { type: "collector", id: "col-up", config: {} });
    await svc.addComponent(env, ADMIN_ACTOR, h.host_id, { type: "dashboard", id: "dash-up", config: {} });
    const minimal = { hostname: "srv-02", machine_id: "0123456789abcdef0123456789abcdef", os: { id: "ubuntu", version: "24.04" }, arch: "amd64" };
    const r = await call("/api/agent/v1/enrol", json({ token: h.enrol_token, facts: minimal }));
    expect(r.status).toBe(201);
    const secret = ((await r.json()) as { agent_secret: string }).agent_secret;
    const before = (await (await getDesired(secret)).json()) as Doc;
    expect(before.components).toEqual([]); // the management address is not known yet

    expect((await postStatus(secret, statusReport({ facts: FACTS() }))).status).toBe(204);
    const after = (await (await getDesired(secret)).json()) as Doc;
    expect(after.components.map((c) => c.type)).toEqual(["collector", "dashboard"]);
    expect(after.components[0]!.config.listen).toBe("10.32.98.25:8443");
    expect(after.version).toBe(before.version + 1);

    // the same facts again: no recompile, no churn
    expect((await postStatus(secret, statusReport({ facts: FACTS() }))).status).toBe(204);
    const again = (await (await getDesired(secret)).json()) as Doc;
    expect(again.version).toBe(after.version);
  });
});
