// scripts/prepare.mjs bundles agent/install/install.sh automatically once it exists.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

describe("prepare.mjs ui-assets", () => {
  function gen(embed: boolean, dist: string) {
    const out = mkdtempSync(join(tmpdir(), "exp-prepare-ui-"));
    const env: Record<string, string> = { ...process.env, EXP_PREPARE_OUT: out, EXP_UI_DIST: dist } as Record<string, string>;
    delete env.EXP_EMBED_UI;
    if (embed) env.EXP_EMBED_UI = "1";
    const r = spawnSync(process.execPath, [script], { env, encoding: "utf8" });
    return { r, text: () => readFileSync(join(out, "ui-assets.ts"), "utf8") };
  }
  function fixture(headers = "/*\n  X-Frame-Options: DENY\n  Content-Security-Policy: frame-ancestors 'none'\n") {
    const d = mkdtempSync(join(tmpdir(), "exp-dist-"));
    mkdirSync(join(d, "assets"));
    writeFileSync(join(d, "index.html"), "<html></html>");
    writeFileSync(join(d, "assets", "app-1.js"), "x=1");
    writeFileSync(join(d, "_headers"), headers);
    return d;
  }

  it("emits an empty map by default", () => {
    const g = gen(false, fixture());
    expect(g.r.status).toBe(0);
    expect(g.text()).toContain("Object.freeze({})");
  });

  it("embeds the dist with etags, types and the /* header rules", () => {
    const g = gen(true, fixture());
    expect(g.r.status).toBe(0);
    const t = g.text();
    expect(t).toContain('"/index.html"');
    expect(t).toContain('"/assets/app-1.js"');
    expect(t).toContain("text/javascript");
    expect(t).toMatch(/"etag":"\\"[0-9a-f]{64}\\""/);
    expect(t).toContain('["X-Frame-Options","DENY"]');
    expect(t).not.toContain('"/_headers"');
  });

  it("fails on unknown _headers syntax, symlinks, oversized files and a missing index", () => {
    expect(gen(true, fixture("/api/*\n  X: y\n")).r.status).not.toBe(0);
    expect(gen(true, fixture("/*\n  ! X-Frame-Options\n")).r.status).not.toBe(0);
    const s = fixture();
    symlinkSync("/etc/hostname", join(s, "link.txt"));
    expect(gen(true, s).r.status).not.toBe(0);
    const big = fixture();
    writeFileSync(join(big, "big.bin"), Buffer.alloc(2 * 1024 * 1024 + 1));
    expect(gen(true, big).r.status).not.toBe(0);
    const noIdx = fixture();
    rmSync(join(noIdx, "index.html"));
    expect(gen(true, noIdx).r.status).not.toBe(0);
  });
});
