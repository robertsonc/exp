// scripts/prepare.mjs bundles agent/install/install.sh automatically once it exists.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const script = resolve(dirname(fileURLToPath(import.meta.url)), "../../../scripts/prepare.mjs");

function run(env: Record<string, string>): string {
  const out = mkdtempSync(join(tmpdir(), "exp-prepare-"));
  const r = spawnSync(process.execPath, [script], { env: { ...process.env, ...env, EXP_PREPARE_OUT: out }, encoding: "utf8" });
  expect(r.status).toBe(0);
  return readFileSync(join(out, "install-sh.ts"), "utf8");
}

describe("prepare.mjs", () => {
  it("uses a placeholder when the real script is absent", () => {
    const t = run({ EXP_AGENT_INSTALL_SH: join(tmpdir(), "does-not-exist-install.sh") });
    expect(t).toContain("agent bootstrap not built yet");
    expect(t).toContain('"placeholder"');
    expect(t).toContain("@@MANAGER_URL@@");
  });

  it("picks the real install.sh automatically once it exists", () => {
    const d = mkdtempSync(join(tmpdir(), "exp-agent-"));
    const real = join(d, "install.sh");
    writeFileSync(real, "#!/bin/sh\n# REAL @@MANAGER_URL@@ @@AGENT_VERSION@@ @@RELEASE_PUBKEY_PEM@@\n");
    const t = run({ EXP_AGENT_INSTALL_SH: real });
    expect(t).toContain("REAL");
    expect(t).not.toContain("agent bootstrap not built yet");
  });
});
