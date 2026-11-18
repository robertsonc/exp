// GET /install.sh: public, static, three substitutions, fail closed on anything that is not safe to pipe to sh.
import { beforeEach, describe, expect, it } from "vitest";
import { INSTALL_SH, INSTALL_SH_SOURCE } from "../../.generated/install-sh";
import { app } from "../../src/index";
import { call, env, resetDb, seedRelease } from "../helpers";

beforeEach(async () => {
  await resetDb();
});

describe("install.sh", () => {
  it("is public, no-store, and has all three placeholders substituted", async () => {
    await seedRelease("0.1.0");
    await seedRelease("0.10.0");
    await seedRelease("0.9.0");
    const r = await call("/install.sh");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toMatch(/text\/x-shellscript/);
    expect(r.headers.get("cache-control")).toBe("no-store");
    const t = await r.text();
    expect(t).not.toMatch(/@@(MANAGER_URL|AGENT_VERSION|RELEASE_PUBKEY_PEM)@@/);
    expect(t).toContain("https://manager.example.test");
    expect(t).toContain("0.10.0"); // numeric semver ordering, not lexical
    expect(t).toContain("BEGIN PUBLIC KEY");
    expect(t.startsWith("#!")).toBe(true);
  });

  it("the bundled source is the placeholder until agent/install/install.sh exists, and it fails with the documented message", () => {
    if (INSTALL_SH_SOURCE === "placeholder") {
      expect(INSTALL_SH).toContain("agent bootstrap not built yet");
      expect(INSTALL_SH).toMatch(/exit 1/);
    } else {
      expect(INSTALL_SH).toContain("@@MANAGER_URL@@");
    }
  });

  it("with no release imported the version is empty (the script must handle that)", async () => {
    const t = await (await call("/install.sh")).text();
    expect(t).not.toContain("@@AGENT_VERSION@@");
  });

  it("refuses (503) rather than substituting a malformed public key", async () => {
    for (const pem of ["'; rm -rf / #", "-----BEGIN PUBLIC KEY-----\n$(id)\n-----END PUBLIC KEY-----\n", "x\n-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"]) {
      const r = await app.fetch(new Request("https://manager.example.test/install.sh"), { ...env, RELEASE_PUBKEY_PEM: pem });
      expect(r.status).toBe(503);
      expect(await r.text()).not.toContain("rm -rf");
    }
  });

  it("refuses a non-https manager URL (except localhost for development)", async () => {
    const bad = await app.fetch(new Request("http://manager.example.test/install.sh"), env);
    expect(bad.status).toBe(503);
    const local = await app.fetch(new Request("http://localhost:8787/install.sh"), env);
    expect(local.status).toBe(200);
    expect(await local.text()).toContain("http://localhost:8787");
  });

  it("serves the static admin UI for non-API paths and enveloped 404 for unknown API paths", async () => {
    const ui = await call("/");
    expect(ui.status).toBe(200);
    expect(await ui.text()).toMatch(/<html|<!doctype/i);
    expect((await call("/api/agent/v1/definitely-not")).status).toBe(401);
    expect((await call("/api/other")).status).toBe(404);
  });
});
