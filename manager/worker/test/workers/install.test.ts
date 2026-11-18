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

  it("bundles the REAL agent/install/install.sh, each placeholder exactly once", () => {
    expect(INSTALL_SH_SOURCE).toBe("agent/install/install.sh");
    expect(INSTALL_SH).not.toContain("agent bootstrap not built yet");
    for (const t of ["@@MANAGER_URL@@", "@@AGENT_VERSION@@", "@@RELEASE_PUBKEY_PEM@@"]) expect(INSTALL_SH.split(t).length - 1, t).toBe(1);
    expect(INSTALL_SH).toContain("MANAGER_URL='@@MANAGER_URL@@'");
  });

  it("with no release imported there is no valid version: 503 rather than a script that dies on start", async () => {
    expect((await call("/install.sh")).status).toBe(503);
  });

  it("a public key containing a quote (or any shell metacharacter) is refused with 503 and never echoed", async () => {
    await seedRelease("0.1.0");
    const body = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA'; touch /tmp/pwned; echo '\n-----END PUBLIC KEY-----\n";
    for (const pem of [body, "-----BEGIN PUBLIC KEY-----\nAAAA'\n-----END PUBLIC KEY-----\n", "", "-----BEGIN PUBLIC KEY-----\nAA$(id)AA\n-----END PUBLIC KEY-----\n"]) {
      const r = await app.fetch(new Request("https://manager.example.test/install.sh"), { ...env, RELEASE_PUBKEY_PEM: pem });
      expect(r.status).toBe(503);
      const t = await r.text();
      expect(t).not.toContain("pwned");
      expect(t).not.toContain("#!");
    }
  });

  it("refuses a manager origin with unexpected characters", async () => {
    await seedRelease("0.1.0");
    for (const u of ["https://ma_nager.example.test/install.sh"]) {
      const r = await app.fetch(new Request(u), env);
      expect(r.status, u).toBe(503);
    }
  });

  it("refuses (503) rather than substituting a malformed public key", async () => {
    for (const pem of ["'; rm -rf / #", "-----BEGIN PUBLIC KEY-----\n$(id)\n-----END PUBLIC KEY-----\n", "x\n-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"]) {
      const r = await app.fetch(new Request("https://manager.example.test/install.sh"), { ...env, RELEASE_PUBKEY_PEM: pem });
      expect(r.status).toBe(503);
      expect(await r.text()).not.toContain("rm -rf");
    }
  });

  it("refuses a non-https manager URL (except localhost for development)", async () => {
    await seedRelease("0.1.0");
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
