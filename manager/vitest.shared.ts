// Shared by vitest.config.ts (npm test) and vitest.perf.config.ts (npm run test:perf).
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const root = dirname(fileURLToPath(import.meta.url));
// make sure the bundled install.sh module exists (real agent/install/install.sh when present)
spawnSync(process.execPath, [join(root, "scripts", "prepare.mjs")], { stdio: "ignore" });

// wrangler.toml serves the UI from ui/dist (built by WP-5). Tests need the directory to exist: when it
// does not, point the assets binding at a throwaway fixture directory instead (never inside manager/ui).
export function testWranglerConfig(): string {
  if (existsSync(join(root, "ui", "dist"))) return join(root, "wrangler.toml");
  const dir = join(root, "worker", ".generated", "test-assets");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "index.html"), "<!doctype html><title>exp</title><p>test fixture</p>\n");
  const toml = `${spawnSync("cat", [join(root, "wrangler.toml")], { encoding: "utf8" }).stdout}`
    .replace('main = "worker/src/index.ts"', `main = "${join(root, "worker/src/index.ts")}"`)
    .replace('directory = "./ui/dist"', `directory = "${dir}"`)
    .replace('migrations_dir = "migrations"', `migrations_dir = "${join(root, "migrations")}"`)
    .replace('command = "node scripts/prepare.mjs"', 'command = ""');
  const out = join(root, "worker", ".generated", "wrangler.test.toml");
  writeFileSync(out, toml);
  return out;
}

export async function workersPlugin() {
  const migrations = await readD1Migrations(resolve(root, "migrations"));
  return cloudflareTest({
    wrangler: { configPath: testWranglerConfig() },
    miniflare: {
      bindings: {
        TEST_MIGRATIONS: migrations,
        EXP_MASTER_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ACCESS_TEAM_DOMAIN: "exp-test.cloudflareaccess.com",
        ACCESS_AUD: "test-aud-0123456789",
        EXP_OWNER_EMAIL: "owner@example.com",
        ORG_NAME: "Test Org",
        MANAGER_URL: "https://manager.example.test",
        RELEASE_PUBKEY_PEM:
          "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rrXAAAA=\n-----END PUBLIC KEY-----\n",
      },
    },
  });
}
