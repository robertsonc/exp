// CR-wp2-webhook-allowlist: site alert settings may carry webhook_allow, compiled into the collector config.
import { beforeEach, describe, expect, it } from "vitest";
import { isWebhookAllowEntry, putSiteAlerts } from "../../src/admin/intent";
import { ADMIN_ACTOR, env, fullScenario, getDesired, resetDb, seedSiteWithRelease } from "../helpers";

const cfg = { enabled: true, voice: "plain", hold_down_s: 30, hold_back_s: 10, reopen_s: 300, calm_s: 300 };
const colAlerts = async (secret: string) => ((await (await getDesired(secret)).json()) as { components: Array<{ config: { alerts: Record<string, unknown> } }> }).components[0]!.config.alerts;

beforeEach(async () => {
  await resetDb();
  await seedSiteWithRelease("hall-b", "0.1.0");
});

describe("webhook_allow", () => {
  it("is omitted unless set, then compiled into alerts.webhook_allow", async () => {
    const sc = await fullScenario();
    expect(await colAlerts(sc.col.secret)).not.toHaveProperty("webhook_allow");
    await putSiteAlerts(env, ADMIN_ACTOR, "hall-b", { config: { ...cfg, webhook_allow: ["10.1.0.0/16", "chat.corp.example", "fd00::5"] }, webhooks: [] });
    expect((await colAlerts(sc.col.secret)).webhook_allow).toEqual(["10.1.0.0/16", "chat.corp.example", "fd00::5"]);
    await putSiteAlerts(env, ADMIN_ACTOR, "hall-b", { config: { ...cfg, webhook_allow: [] }, webhooks: [] });
    expect(await colAlerts(sc.col.secret)).not.toHaveProperty("webhook_allow");
  });

  it("validates: at most 16 entries, each an IP, CIDR or host name", async () => {
    await fullScenario();
    const put = (webhook_allow: unknown) => putSiteAlerts(env, ADMIN_ACTOR, "hall-b", { config: { ...cfg, webhook_allow }, webhooks: [] });
    await expect(put(Array.from({ length: 17 }, (_, i) => `10.0.0.${i}`))).rejects.toMatchObject({ status: 400 });
    for (const bad of ["http://x.example", "10.0.0.0/33", "999.1.1.1", "a b", "host/24", "-x.example", "", "'; rm"]) await expect(put([bad]), bad).rejects.toMatchObject({ status: 400 });
    await expect(put(Array.from({ length: 16 }, (_, i) => `10.0.0.${i}`))).resolves.toBeDefined();
  });

  it("entry grammar", () => {
    for (const ok of ["10.0.0.1", "10.0.0.0/8", "::1", "fd00::/8", "Chat.Corp.Example", "mm"]) expect(isWebhookAllowEntry(ok), ok).toBe(true);
    for (const bad of ["10.0.0", "1.2.3.4/", "a/b", "::g", "1:2:3:4:5:6:7:8:9", "x_y.example"]) expect(isWebhookAllowEntry(bad), bad).toBe(false);
  });
});
