// Demo / development fleet for the LOCAL D1 (docs/spec/11-manager-ui.md section 10).
//
//   npm run seed:demo                 48 hosts, 3 sites, 30 days of roll-ups, open issues  (about 5 s)
//   npm run seed:demo -- --scale 500  perf-test sized fleet
//   npm run seed:demo -- --touch      keep the seeded hosts "fresh" (last_seen = now); add --watch to repeat every 30 s
//   npm run seed:demo -- --out f.sql  write the SQL only (no wrangler)
//
// Local only: there is no --remote. Everything the seed writes is deleted first, so re-running is safe. The data is
// anchored to "now" at seed time: the right edge of the charts does not advance afterwards (re-seed to refresh them);
// without --touch the hosts turn stale after three minutes, which is itself a realistic thing to look at.
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSeed } from "./lib/seed-fleet.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

interface Args {
  scale: number;
  now: number;
  out: string | null;
  touch: boolean;
  watch: boolean;
  migrate: boolean;
  persistTo: string | null;
  config: string | null;
}

function usage(code: number): never {
  console.error(
    "usage: npm run seed:demo -- [--scale N (24..5000, default 48)] [--now ISO8601] [--out file.sql] [--touch [--watch]] [--no-migrate] [--persist-to DIR] [--config wrangler.toml]\n" +
      "Seeds the LOCAL D1 used by `npm run dev` (wrangler dev). It never touches a remote database.",
  );
  process.exit(code);
}

function parse(argv: string[]): Args {
  const a: Args = { scale: 48, now: Date.now(), out: null, touch: false, watch: false, migrate: true, persistTo: null, config: null };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i] as string;
    const v = (): string => {
      const x = argv[++i];
      if (x === undefined) usage(2);
      return x;
    };
    if (k === "--scale") a.scale = Number(v());
    else if (k === "--now") a.now = Date.parse(v());
    else if (k === "--out") a.out = resolve(v());
    else if (k === "--touch") a.touch = true;
    else if (k === "--watch") a.watch = true;
    else if (k === "--no-migrate") a.migrate = false;
    else if (k === "--persist-to") a.persistTo = resolve(v());
    else if (k === "--config") a.config = resolve(v());
    else if (k === "--remote") {
      console.error("seed-demo: refusing --remote. The demo fleet is for local development only.");
      process.exit(2);
    } else if (k === "-h" || k === "--help") usage(0);
    else {
      console.error(`seed-demo: unknown argument ${k}`);
      usage(2);
    }
  }
  if (!Number.isInteger(a.scale) || a.scale < 24 || a.scale > 5000) {
    console.error("seed-demo: --scale must be an integer between 24 and 5000");
    process.exit(2);
  }
  if (!Number.isFinite(a.now)) {
    console.error("seed-demo: --now is not a valid timestamp");
    process.exit(2);
  }
  if (a.watch && !a.touch) {
    console.error("seed-demo: --watch only makes sense with --touch");
    process.exit(2);
  }
  return a;
}

function wrangler(a: Args, args: string[]): void {
  const full = ["--no-install", "wrangler", ...args, "--local"];
  if (a.config) full.push("-c", a.config);
  if (a.persistTo) full.push("--persist-to", a.persistTo);
  const r = spawnSync("npx", full, { cwd: root, stdio: "inherit" });
  if (r.status !== 0) {
    console.error(`seed-demo: wrangler ${args.slice(0, 3).join(" ")} failed (exit ${r.status ?? "signal"})`);
    process.exit(r.status ?? 1);
  }
}

function execFile(a: Args, file: string): void {
  wrangler(a, ["d1", "execute", "DB", "--file", file, "--yes"]);
}

function touchSql(nowMs: number): string {
  const t = new Date(nowMs).toISOString();
  // fresh hosts only: stale/offline hosts keep their scenario timestamps; a few seconds of stagger per host
  return (
    `UPDATE hosts SET last_seen = '${t}', updated_at = '${t}' WHERE state = 'enrolled' AND host_id LIKE 'h_000000000000SEED%';\n` +
    `UPDATE status_latest SET received_at = '${t}', updated_at = '${t}' WHERE host_id IN (SELECT host_id FROM hosts WHERE state = 'enrolled' AND host_id LIKE 'h_000000000000SEED%');\n`
  );
}

function main(): void {
  const a = parse(process.argv.slice(2));
  const dir = join(root, ".wrangler", "seed");
  mkdirSync(dir, { recursive: true });

  if (a.touch) {
    const run = (): void => {
      const f = join(dir, "touch.sql");
      writeFileSync(f, touchSql(Date.now()));
      execFile(a, f);
    };
    run();
    if (a.watch) {
      console.log("seed-demo: touching every 30 s (Ctrl-C to stop)");
      setInterval(run, 30_000);
    }
    return;
  }

  const t0 = Date.now();
  const seed = buildSeed({ scale: a.scale, nowMs: a.now });
  const sql = [...seed.reset, ...seed.statements].map((s) => `${s};`).join("\n") + "\n";
  const file = a.out ?? join(dir, `demo-${a.scale}.sql`);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, sql);
  console.log(`seed-demo: ${seed.summary.hosts} hosts, ${seed.summary.components} components, ${seed.summary.issues_open} open issues -> ${file} (${(sql.length / 1e6).toFixed(1)} MB, ${(Date.now() - t0)} ms)`);
  if (a.out) return;
  if (a.migrate) wrangler(a, ["d1", "migrations", "apply", "DB"]);
  execFile(a, file);
  console.log(`seed-demo: done. Scenario hosts: ${JSON.stringify(seed.summary.scenarios)}`);
  console.log("seed-demo: run `npm run dev`; keep hosts fresh with `npm run seed:demo -- --touch --watch`.");
}

main();
