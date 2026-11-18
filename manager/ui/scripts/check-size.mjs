// Performance budget (docs/spec/11-manager-ui.md section 9): total JS <= 300 KB gzipped, uPlot included.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const BUDGET = 300 * 1024;

function walk(d) {
  return readdirSync(d).flatMap((n) => {
    const p = join(d, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

let js = 0;
let css = 0;
const rows = [];
for (const f of walk(dist)) {
  if (!/\.(js|mjs|css)$/.test(f)) continue;
  const gz = gzipSync(readFileSync(f)).length;
  if (f.endsWith('.css')) css += gz;
  else js += gz;
  rows.push([f.slice(dist.length + 1), gz]);
}
for (const [n, s] of rows) console.log(`  ${n.padEnd(40)} ${(s / 1024).toFixed(1)} KB gz`);
console.log(`JS total ${(js / 1024).toFixed(1)} KB gz (budget ${BUDGET / 1024} KB), CSS ${(css / 1024).toFixed(1)} KB gz`);
if (js > BUDGET) {
  console.error('FAIL: JavaScript exceeds the 300 KB gzipped budget');
  process.exit(1);
}
