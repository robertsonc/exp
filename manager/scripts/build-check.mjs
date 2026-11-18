#!/usr/bin/env node
// Bundle check (second half of `npm run build`, after `tsc --noEmit`): bundles the Worker exactly as
// `wrangler deploy` would (no network, no credentials: --dry-run) and verifies the result is deployable:
// it bundles, fits the Workers size limit, and needs no Node built-ins (nodejs_compat is not enabled).
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { cwd: root, encoding: "utf8", ...opts });

const prep = run(process.execPath, [join(root, "scripts", "prepare.mjs")]);
if (prep.status !== 0) {
  console.error(prep.stderr);
  process.exit(1);
}
process.stdout.write(prep.stdout);

const out = join(root, ".wrangler", "bundle-check");
rmSync(out, { recursive: true, force: true });
const args = ["wrangler", "deploy", "--dry-run", "--outdir", out];
if (!existsSync(join(root, "ui", "dist"))) {
  // the UI (WP-5) is not built yet: bundle against a throwaway assets directory
  const dir = join(root, "worker", ".generated", "test-assets");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "index.html"), "<!doctype html><title>exp</title>\n");
  args.push("--assets", dir);
}
const r = run("npx", ["--no-install", ...args]);
if (r.status !== 0) {
  console.error(r.stdout, r.stderr);
  console.error("build-check: wrangler could not bundle the Worker");
  process.exit(1);
}
const files = readdirSync(out).filter((f) => f.endsWith(".js"));
if (files.length === 0) {
  console.error("build-check: no bundle produced");
  process.exit(1);
}
let failed = false;
for (const f of files) {
  const text = readFileSync(join(out, f), "utf8");
  const gz = gzipSync(text).length;
  console.log(`build-check: ${f} ${(text.length / 1024).toFixed(0)} KiB (${(gz / 1024).toFixed(0)} KiB gzip)`);
  if (gz > 3 * 1024 * 1024) {
    console.error("build-check: bundle exceeds the 3 MiB (gzip) Workers Free limit");
    failed = true;
  }
  const nodeImports = [...text.matchAll(/from\s*["'](node:[a-z/_]+)["']/g)].map((m) => m[1]);
  if (nodeImports.length) {
    console.error(`build-check: bundle imports Node built-ins (${[...new Set(nodeImports)].join(", ")}) but nodejs_compat is off`);
    failed = true;
  }
  if (/\beval\s*\(|new Function\s*\(/.test(text.replace(/\/\*[\s\S]*?\*\//g, "")) && /exp-manager|worker\/src/.test(text)) {
    // hono's router compiles regexes, not code; any eval in OUR modules would be a policy violation
    const ours = text.split("\n").filter((l) => /\beval\s*\(|new Function\s*\(/.test(l) && !l.includes("node_modules"));
    if (ours.length) console.warn("build-check: eval/new Function found in the bundle; verify it is third-party:", ours.length, "line(s)");
  }
}
if (failed) process.exit(1);
console.log("build-check: ok");
