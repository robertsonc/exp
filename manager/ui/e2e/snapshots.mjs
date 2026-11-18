// Visual regression snapshots (11-manager-ui.md section 11 item 9). Baselines live in tests/__snapshots__/*.png.
// A missing baseline (or UPDATE_SNAPSHOTS=1) writes it; otherwise the screenshot must match within a small tolerance.
// Volatile content is neutralised before the shot: charts and sparklines (their data follows the clock), relative times
// ("45 s ago") and the freshness indicator. Everything else is the real page.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = path.join(here, '..', 'tests', '__snapshots__');
const out = path.join(here, '.out');
const require = createRequire(import.meta.url);
const { PNG } = require('pngjs');
const pixelmatch = (await import('pixelmatch')).default;

const MAX_DIFF_RATIO = 0.02; // fraction of pixels allowed to differ (values drift with the mock clock)
const PIXEL_THRESHOLD = 0.2;

const HIDE = `
  *, *::before, *::after { animation: none !important; transition: none !important; caret-color: transparent !important; }
  .chart-host, .uplot, svg.spark, .spark, .fresh, .asof, .kpi-asof, .toasts { visibility: hidden !important; }
`;

/** Replace "12 s ago" style text with a constant, in the page only, so the shot does not depend on when it was taken. */
async function normalise(page) {
  // a constructed stylesheet (CSSOM) is allowed under the SPA's style-src 'self', an injected <style> element is not
  await page.evaluate((css) => { const sh = new CSSStyleSheet(); sh.replaceSync(css); document.adoptedStyleSheets = [...document.adoptedStyleSheets, sh]; }, HIDE);
  await page.evaluate(async () => {
    await document.fonts.ready;
    const re = /\b(\d+ ?(s|min|h|d)( \d+ ?(s|min|h))?|just now)( ago)?\b/g;
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (w.nextNode()) nodes.push(w.currentNode);
    for (const n of nodes) if (/ago\b|just now/.test(n.nodeValue ?? '')) n.nodeValue = (n.nodeValue ?? '').replace(re, (m) => (m.endsWith('ago') || m === 'just now' ? 'N ago' : m));
  });
  await page.waitForTimeout(150);
}

export async function snapshot(page, name) {
  await normalise(page);
  const actual = await page.screenshot({ animations: 'disabled', caret: 'hide' });
  mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${name}.png`);
  if (!existsSync(file) || process.env.UPDATE_SNAPSHOTS === '1') {
    writeFileSync(file, actual);
    return { written: true, ratio: 0 };
  }
  const a = PNG.sync.read(readFileSync(file));
  const b = PNG.sync.read(actual);
  if (a.width !== b.width || a.height !== b.height) {
    mkdirSync(out, { recursive: true });
    writeFileSync(path.join(out, `${name}.actual.png`), actual);
    throw new Error(`snapshot ${name}: size ${b.width}x${b.height} differs from baseline ${a.width}x${a.height}`);
  }
  const diff = new PNG({ width: a.width, height: a.height });
  const n = pixelmatch(a.data, b.data, diff.data, a.width, a.height, { threshold: PIXEL_THRESHOLD });
  const ratio = n / (a.width * a.height);
  if (ratio > MAX_DIFF_RATIO) {
    mkdirSync(out, { recursive: true });
    writeFileSync(path.join(out, `${name}.actual.png`), actual);
    writeFileSync(path.join(out, `${name}.diff.png`), PNG.sync.write(diff));
    throw new Error(`snapshot ${name}: ${(ratio * 100).toFixed(2)}% of pixels differ (limit ${MAX_DIFF_RATIO * 100}%); see e2e/.out/${name}.diff.png`);
  }
  return { written: false, ratio };
}
