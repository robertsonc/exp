#!/usr/bin/env node
// Local development: bundle install.sh, create .dev.vars (random EXP_MASTER_KEY; gitignored) on first run,
// apply migrations to the local D1, then `wrangler dev`. Admin auth needs a real Access JWT; for UI work
// without Access use test/fakes/mock_admin instead.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sh = (cmd, args) => {
  const r = spawnSync(cmd, args, { cwd: root, stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
};
sh(process.execPath, [join(root, "scripts", "prepare.mjs")]);
const vars = join(root, ".dev.vars");
if (!existsSync(vars)) {
  writeFileSync(vars, `EXP_MASTER_KEY=${randomBytes(32).toString("base64")}\n`, { mode: 0o600 });
  console.log("dev: created .dev.vars with a random EXP_MASTER_KEY (local only)");
}
sh("npx", ["--no-install", "wrangler", "d1", "migrations", "apply", "DB", "--local"]);
sh("npx", ["--no-install", "wrangler", "dev", ...process.argv.slice(2)]);
