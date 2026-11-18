import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { app } from "../../src/index";

describe("smoke", () => {
  it("serves /healthz", async () => {
    const r = await app.fetch(new Request("https://m.test/healthz"), env as never);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe("ok");
  });
});
