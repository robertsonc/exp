// CR-wp5-admin-ui-intent: the add-host wizard sequence (POST hosts -> POST components per shape -> enrol -> PUT ports)
// yields a document that validates against shared/schemas/desired.schema.json at every step; a probe without ports is
// left out of desired state; dashboard intent config.collector_ids compiles to collectors[] filled by the compiler.
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { beforeEach, describe, expect, it } from "vitest";
import * as svc from "../../src/admin/service";
import * as intent from "../../src/admin/intent";
import {
  ADMIN_ACTOR, FACTS, FINGERPRINT, call, enrolHost, env, getDesired, json, postStatus, resetDb, seedSiteWithRelease, statusReport,
} from "../helpers";

const files = import.meta.glob("../../../../shared/schemas/*.schema.json", { eager: true, import: "default" }) as Record<string, object>;
const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats.default(ajv);
for (const [p, s] of Object.entries(files)) ajv.addSchema(s, p.split("/").pop()!);
function validate(doc: unknown): string[] {
  const v = ajv.getSchema("desired.schema.json")!;
  return v(doc) ? [] : (v.errors ?? []).slice(0, 8).map((e) => `${e.instancePath} ${e.message}`);
}

type Doc = { components: Array<{ type: string; id: string; config: Record<string, any> }> };
async function desired(secret: string): Promise<Doc> {
  const r = await getDesired(secret);
  expect(r.status).toBe(200);
  const d = (await r.json()) as Doc;
  expect(validate(d)).toEqual([]);
  return d;
}

beforeEach(async () => {
  await resetDb();
  await seedSiteWithRelease("hall-b", "0.1.0");
});

describe("wizard sequence", () => {
  it("every step compiles to a schema-valid document", async () => {
    // collector host first (a probe needs a collector endpoint to be fully wired)
    const col = await enrolHost("hall-b", "col-host");
    await svc.addComponent(env, ADMIN_ACTOR, col.host_id, { type: "collector", id: "col-hallb", config: {} });
    await desired(col.secret);
    await postStatus(col.secret, statusReport({ components: [{ type: "collector", id: "col-hallb", state: "running", health: "ok", facts: { listen: "10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT } }] }));
    await desired(col.secret);

    const col2 = await enrolHost("hall-b", "col2-host", FACTS({ interfaces: [{ name: "eno1", mac: "18:66:da:00:00:0a", state: "up", speed_mbps: 1000, addrs: ["10.32.98.26/23"], default_route: true, in_use_by: "mgmt" }] }));
    await svc.addComponent(env, ADMIN_ACTOR, col2.host_id, { type: "collector", id: "col-other", config: {} });
    await postStatus(col2.secret, statusReport({ components: [{ type: "collector", id: "col-other", state: "running", health: "ok", facts: { listen: "10.32.98.26:8443", tls_fingerprint_sha256: FINGERPRINT } }] }));

    // POST hosts (pending: no document, no secret yet), then components with minimal intent
    const h = await svc.createHost(env, ADMIN_ACTOR, { name: "probe-host", site: "hall-b" });
    await svc.addComponent(env, ADMIN_ACTOR, h.host_id, { type: "probe", id: "probe-w1", config: {} });
    await svc.addComponent(env, ADMIN_ACTOR, h.host_id, { type: "dashboard", id: "dash-w1", config: { collector_ids: ["col-hallb"] } });
    // enrol
    const r = await call("/api/agent/v1/enrol", json({ token: h.enrol_token, facts: FACTS() }));
    expect(r.status).toBe(201);
    const secret = ((await r.json()) as { agent_secret: string }).agent_secret;
    let d = await desired(secret);
    expect(d.components.map((c) => c.type)).toEqual(["dashboard"]); // probe has no ports yet: left out
    const dash = d.components[0]!;
    expect(dash.config.collectors).toHaveLength(1); // collector_ids selects only col-hallb, not col-other
    expect(dash.config.collectors[0]).toMatchObject({ collector_id: "col-hallb", url: "https://10.32.98.25:8443", tls_fingerprint_sha256: FINGERPRINT });
    // PUT ports
    const probeId = (await env.DB.prepare("SELECT component_id FROM components WHERE slug = 'probe-w1'").first<{ component_id: string }>())!.component_id;
    await intent.putProbePorts(env, ADMIN_ACTOR, probeId, [{ id: "c01", iface: "enp10s0f0", role: "client", vlan: null, dhcp: { hostname: "exp-c01", vendor_class: "exp-probe", client_id: "mac" } }]);
    d = await desired(secret);
    expect(d.components.map((c) => c.type)).toEqual(["dashboard", "probe"]);
    expect(d.components[1]!.config.ports).toHaveLength(1);
  });

  it("a probe whose ports are cleared again disappears from desired state instead of becoming invalid", async () => {
    const col = await enrolHost("hall-b", "col-host");
    await svc.addComponent(env, ADMIN_ACTOR, col.host_id, { type: "collector", id: "col-hallb", config: {} });
    const p = await enrolHost("hall-b", "p-host");
    const c = await svc.addComponent(env, ADMIN_ACTOR, p.host_id, { type: "probe", id: "probe-w2", config: { ports: [] } });
    const d = await desired(p.secret);
    expect(d.components).toEqual([]);
    expect(c.component_id).toBeTruthy();
  });
});
