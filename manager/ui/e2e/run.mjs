// End-to-end smoke tests: vite preview (the production build) + mock_admin on free ports, Playwright Chromium.
// Playwright is the globally installed one (no browser download): resolved through `npm root -g`.
import { spawn, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const here = path.dirname(fileURLToPath(import.meta.url));
const ui = path.join(here, '..');
const repo = path.join(ui, '..', '..');
const require = createRequire(import.meta.url);

function loadPlaywright() {
  try {
    return require('playwright');
  } catch {
    const root = execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim();
    return createRequire(path.join(root, 'x.js'))('playwright');
  }
}
const { chromium } = loadPlaywright();
const { default: AxeBuilder } = await import('@axe-core/playwright');
const { adminTests } = await import('./admin-tests.mjs');
const { allPages } = await import('./pages.mjs');
const { snapshot } = await import('./snapshots.mjs');

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
    s.on('error', reject);
  });
}

async function waitHttp(url, ms = 30000) {
  const end = Date.now() + ms;
  for (;;) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not yet */ }
    if (Date.now() > end) throw new Error(`timeout waiting for ${url}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

const children = [];
function start(cmd, args, env = {}) {
  const c = spawn(cmd, args, { cwd: ui, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  c.stdout.on('data', () => {});
  c.stderr.on('data', () => {});
  children.push(c);
  return c;
}
function killAll() {
  for (const c of children) {
    try { c.kill('SIGKILL'); } catch { /* already gone */ }
  }
}
process.on('exit', killAll);
process.on('SIGINT', () => { killAll(); process.exit(130); });

const python = process.env.EXP_PYTHON ?? (existsSync(path.join(repo, '.venv/bin/python')) ? path.join(repo, '.venv/bin/python') : 'python3');
const mockScript = path.join(repo, 'test/fakes/mock_admin/server.py');
// --enrol-delay-s 4: a host created in the add-host wizard enrols 4 s after its token was issued (default 10).
const startMock = (port) => start(python, [mockScript, '--listen', `127.0.0.1:${port}`, '--no-auth', '--enrol-delay-s', '4']);

if (!existsSync(path.join(ui, 'dist/index.html'))) {
  console.log('dist/ missing: building first');
  execFileSync('npm', ['run', 'build'], { cwd: ui, stdio: 'inherit' });
}

const apiPort = await freePort();
const webPort = await freePort();
let mock = startMock(apiPort);
const vite = start(process.execPath, [path.join(ui, 'node_modules/vite/bin/vite.js'), 'preview', '--port', String(webPort), '--strictPort', '--host', '127.0.0.1'], { EXP_API_TARGET: `http://127.0.0.1:${apiPort}` });
await waitHttp(`http://127.0.0.1:${apiPort}/api/admin/v1/me`);
await waitHttp(`http://127.0.0.1:${webPort}/`);
const BASE = `http://127.0.0.1:${webPort}`;
const API = `${BASE}/api/admin/v1`;
const getJson = async (p) => (await fetch(`${API}${p}`)).json();
const PAGES = await allPages(getJson);

const browser = await chromium.launch();
const results = [];

async function newPage(opts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'dark', acceptDownloads: true, ...opts });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errors.push(m.text()); });
  page.errors = errors;
  return page;
}

const TEST_TIMEOUT_MS = Number(process.env.E2E_TEST_TIMEOUT_MS ?? 150000);
const only = process.env.E2E_ONLY ? new RegExp(process.env.E2E_ONLY, 'i') : null; // debugging aid: run a subset by name
async function test(name, fn) {
  if (only && !only.test(name)) return;
  const t0 = Date.now();
  try {
    // A test that hangs (an unbounded await) must fail, not stall the run.
    let timer;
    await Promise.race([fn(), new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(`test timed out after ${TEST_TIMEOUT_MS / 1000} s`)), TEST_TIMEOUT_MS); })]);
    clearTimeout(timer);
    results.push([name, true]);
    console.log(`  ok   ${name} (${Date.now() - t0} ms)`);
  } catch (e) {
    results.push([name, false]);
    console.log(`  FAIL ${name}\n       ${String(e.stack ?? e).split('\n').slice(0, 6).join('\n       ')}`);
  }
}

const hostsAll = async () => (await getJson('/fleet/hosts?limit=1000')).items;

// ------------------------------------------------------------------------------------------------
await test('overview KPIs match /fleet/summary', async () => {
  const page = await newPage();
  await page.goto(`${BASE}/fleet`);
  await page.waitForSelector('[data-testid="kpis"]');
  const s = await getJson('/fleet/summary');
  const t = (k) => page.locator(`[data-k="${k}"]`).innerText();
  assert.equal((await t('hosts')).replace(/\s+/g, ' '), `${s.hosts_online}/${s.hosts_total} online`);
  const c = { ok: 0, warn: 0, fail: 0 };
  for (const v of Object.values(s.components_by_type_health)) { c.ok += v.ok; c.warn += v.degraded; c.fail += v.fail; }
  assert.equal((await t('components')).replace(/\s+/g, ' '), `${c.ok} ok · ${c.warn} warn · ${c.fail} fail`);
  assert.match(await t('issues'), new RegExp(`^${s.open_issues.warn + s.open_issues.crit}\\b.*${s.open_issues.crit} crit`));
  assert.equal((await t('drift')).trim(), `${s.version_drift_hosts} host${s.version_drift_hosts === 1 ? '' : 's'}`);
  assert.equal((await t('incidents')).trim(), `${s.open_experience_incidents} open`);
  // sidebar badge shows the same count
  assert.equal((await page.locator('.nav-badge').innerText()).trim(), String(s.open_issues.warn + s.open_issues.crit));
  assert.ok(await page.locator('.attn .issue-row').count() > 0, 'needs-attention list has issues');
  assert.ok(await page.locator('.site-card').count() >= 1, 'site cards');
  assert.deepEqual(page.errors, []);
  await page.context().close();
});

await test('stale host renders stale with "as of"; offline shows no current values', async () => {
  const page = await newPage();
  const rows = await hostsAll();
  const stale = rows.filter((r) => r.state === 'stale');
  const offline = rows.filter((r) => r.state === 'offline');
  assert.ok(stale.length > 0 && offline.length > 0, 'mock has stale and offline hosts');
  await page.goto(`${BASE}/hosts?state=stale`);
  await page.waitForSelector('tr.host-row');
  const staleRows = page.locator('tr.host-stale');
  assert.equal(await staleRows.count(), stale.length);
  const first = staleRows.first();
  assert.match(await first.innerText(), /stale/);
  assert.match(await first.innerText(), /as of/);
  await page.goto(`${BASE}/hosts?state=offline`);
  await page.waitForSelector('tr.host-row');
  const offRows = page.locator('tr.host-offline');
  assert.equal(await offRows.count(), offline.length);
  const offText = await offRows.first().innerText();
  assert.match(offText, /offline/);
  assert.ok(!/\d+%/.test(offText), 'offline rows show no percentages');
  // detail page: stale banner with "as of"
  await page.goto(`${BASE}/hosts?state=stale`);
  await page.waitForSelector('tr.host-stale');
  await page.locator('tr.host-stale').first().locator('a.host-link').click();
  await page.waitForSelector('[data-testid="stale-banner"]');
  assert.match(await page.locator('[data-testid="stale-banner"]').innerText(), /as of that time/);
  await page.context().close();
});

await test('hosts: filter, sort, saved view, CSV export; URL carries the state', async () => {
  const page = await newPage();
  await page.goto(`${BASE}/hosts`);
  await page.waitForSelector('tr.host-row');
  const all = await hostsAll();
  const count = () => page.locator('[data-testid="host-count"]').innerText();
  assert.equal(await count(), `${all.length} of ${all.length} hosts`);
  // filter by free text
  await page.fill('input[aria-label="Filter hosts by name, IP or id"]', 'probe');
  const probes = all.filter((h) => h.name.includes('probe'));
  await page.waitForFunction((n) => document.querySelector('[data-testid="host-count"]')?.textContent?.startsWith(`${n} of`), probes.length);
  assert.ok(page.url().includes('q=probe'));
  // site filter via select
  await page.selectOption('select[aria-label="Site"]', 'hall-b');
  const hb = probes.filter((h) => h.site === 'hall-b');
  await page.waitForFunction((n) => document.querySelector('[data-testid="host-count"]')?.textContent?.startsWith(`${n} of`), hb.length);
  // sort by CPU: first click ascending, second descending
  await page.click('th button:has-text("CPU")');
  assert.ok(page.url().includes('sort=cpu'));
  await page.click('th button:has-text("CPU")');
  assert.ok(page.url().includes('sort=-cpu'));
  const names = await page.locator('tr.host-row a.host-link').allInnerTexts();
  const expected = hb.filter((h) => h.state !== 'pending').slice().sort((a, b) => (b.cpu_pct ?? -1) - (a.cpu_pct ?? -1)).map((h) => h.name);
  const present = new Set(names);
  assert.deepEqual(names.filter((n) => expected.includes(n)).length, names.length);
  assert.ok(present.size === names.length);
  const cpuOf = new Map(all.map((h) => [h.name, h.cpu_pct]));
  const withCpu = names.map((n) => cpuOf.get(n)).filter((v) => v != null);
  for (let i = 1; i < withCpu.length; i += 1) assert.ok(withCpu[i - 1] >= withCpu[i], 'descending by cpu');
  // saved view
  await page.click('summary:has-text("Views")');
  await page.fill('input[aria-label="Saved view name"]', 'Hall B probes');
  await page.click('button:has-text("Save view")');
  const stored = await page.evaluate(() => localStorage.getItem('exp.ui.hostViews'));
  assert.match(stored, /Hall B probes/);
  await page.click('button:has-text("Clear filters")');
  await page.waitForFunction((n) => document.querySelector('[data-testid="host-count"]')?.textContent?.startsWith(`${n} of`), all.length);
  await page.click('button:has-text("Hall B probes")');
  await page.waitForFunction((n) => document.querySelector('[data-testid="host-count"]')?.textContent?.startsWith(`${n} of`), hb.length);
  assert.ok(page.url().includes('site=hall-b') && page.url().includes('sort=-cpu'));
  // CSV export of the current view
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('button:has-text("Export CSV")')]);
  assert.match(dl.suggestedFilename(), /^exp-hosts-.*\.csv$/);
  const csv = (await (await import('node:fs/promises')).readFile(await dl.path(), 'utf8')).trim().split('\r\n');
  assert.equal(csv.length, hb.length + 1);
  assert.ok(csv[0].startsWith('name,host_id'));
  await page.context().close();
});

await test('hosts: 500 rows are virtualised and sort in < 100 ms', async () => {
  const page = await newPage();
  const base = await hostsAll();
  const big = Array.from({ length: 500 }, (_, i) => ({ ...base[i % base.length], host_id: `h_BIG${String(i).padStart(4, '0')}`, name: `bulk-host-${String(i).padStart(3, '0')}`, cpu_pct: (i * 37) % 100 }));
  await page.route('**/api/admin/v1/fleet/hosts?*', (r) => r.fulfill({ json: { items: big, next_cursor: null } }));
  await page.goto(`${BASE}/hosts`);
  await page.waitForSelector('tr.host-row');
  assert.equal(await page.locator('[data-testid="host-count"]').innerText(), '500 of 500 hosts');
  const rendered = await page.locator('tr.host-row').count();
  assert.ok(rendered < 60, `only the visible window is rendered (${rendered})`);
  const ms = await page.evaluate(async () => {
    const btn = [...document.querySelectorAll('th button')].find((b) => b.textContent?.includes('Memory'));
    const t0 = performance.now();
    btn.click();
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    return performance.now() - t0;
  });
  assert.ok(ms < 100, `sort took ${ms} ms`);
  // scrolling renders other rows
  await page.locator('.vt-scroll').evaluate((e) => { e.scrollTop = 20000; });
  await page.waitForTimeout(200);
  const names = await page.locator('tr.host-row a.host-link').allInnerTexts();
  assert.ok(names.length > 0 && names.length < 60);
  await page.context().close();
});

await test('host detail: charts for every range, table view, gaps, tabs', async () => {
  const page = await newPage();
  const all = await hostsAll();
  const h = all.find((x) => x.name === 'hb-col-01');
  await page.goto(`${BASE}/hosts/${h.host_id}`);
  await page.waitForSelector('.chart .uplot', { timeout: 15000 });
  for (const r of ['1h', '6h', '24h', '7d', '30d']) {
    await page.click(`.range button[aria-pressed]:text-is("${r.replace('h', ' h').replace('d', ' d')}")`);
    await page.waitForFunction((rr) => (rr === '24h' ? !location.search.includes('range') : location.search.includes(`range=${rr}`)), r);
    await page.waitForSelector('.chart .uplot', { timeout: 15000 });
    assert.ok(await page.locator('.chart .uplot').count() >= 4, `charts render for ${r}`);
    const sum = await page.locator('.chart-summary').first().innerText();
    assert.match(sum, /latest/);
  }
  // table view toggle
  await page.locator('.chart button:has-text("Table view")').first().click();
  await page.waitForSelector('.chart-table table');
  assert.ok(await page.locator('.chart-table tbody tr').count() > 10);
  await page.locator('.chart button:has-text("Chart view")').first().click();
  // tabs via keyboard and URL
  await page.click('#tab-components');
  assert.ok(page.url().includes('tab=components'));
  assert.ok(await page.locator('.comp-panel').count() >= 2);
  await page.click('#tab-interfaces');
  assert.ok(await page.locator('table.plain tbody tr').count() >= 1);
  await page.click('#tab-config');
  assert.match(await page.locator('pre.code').first().innerText(), /schema/);
  await page.click('#tab-actions');
  await page.click('button:has-text("Decommission host")');
  const dlg = page.locator('dialog[open]');
  await dlg.waitFor();
  assert.ok(await dlg.locator('button:has-text("Decommission")').isDisabled(), 'destructive action needs the host name typed');
  await dlg.locator('input').fill(h.name);
  assert.ok(await dlg.locator('button.btn-danger').isEnabled());
  await dlg.locator('button:has-text("Cancel")').click();
  assert.deepEqual(page.errors, []);
  await page.context().close();
});

await test('gaps: a missing bucket is drawn as a gap, not as zero or interpolated', async () => {
  const page = await newPage();
  const all = await hostsAll();
  const h = all.find((x) => x.name === 'hb-col-01');
  const real = await getJson(`/fleet/hosts/${h.host_id}/metrics?range=1h`);
  const pts = real.series.cpu_pct.filter((_, i) => i !== 5 && i !== 6);
  await page.route('**/fleet/hosts/*/metrics?*', (r) => r.fulfill({ json: { ...real, series: { cpu_pct: pts } } }));
  await page.goto(`${BASE}/hosts/${h.host_id}?range=1h`);
  await page.waitForSelector('.chart .uplot');
  assert.match(await page.locator('.chart-summary').first().innerText(), /2 gaps/);
  await page.locator('.chart button:has-text("Table view")').first().click();
  const cells = await page.locator('.chart-table tbody td').allInnerTexts();
  assert.equal(cells.filter((c) => c.trim() === '—').length >= 2, true);
  await page.context().close();
});

await test('probe ports grid and collector days-to-full', async () => {
  const page = await newPage();
  const all = await hostsAll();
  const pr = all.find((x) => x.name === 'hb-probe-05');
  const col = all.find((x) => x.name === 'hb-col-01');
  const comps = (await getJson(`/hosts/${pr.host_id}/components`)).items;
  const status = await getJson(`/hosts/${pr.host_id}/status`);
  const ports = status.report.components[0].metrics.ports;
  await page.goto(`${BASE}/hosts/${pr.host_id}/components/${comps[0].component_id}`);
  await page.waitForSelector('[data-testid="port-tile"]');
  assert.equal(await page.locator('[data-testid="port-tile"]').count(), ports.length);
  const tile = await page.locator('[data-testid="port-tile"]').first().innerText();
  assert.match(tile, /link up/);
  assert.match(tile, new RegExp(ports[0].ip.replace(/\./g, '\\.')));
  assert.match(tile, /pps/);
  assert.match(tile, /dns fail/);
  // collector: the projection the API reports is the one shown (the mock does not report one, so inject it)
  const colComps = (await getJson(`/hosts/${col.host_id}/components`)).items;
  const cc = colComps.find((c) => c.type === 'collector');
  const cstatus = await getJson(`/hosts/${col.host_id}/status`);
  cstatus.report.components.find((c) => c.type === 'collector').metrics.days_to_full = 1.5;
  cstatus.report.components.find((c) => c.type === 'collector').metrics.vm_storage_gb = 40;
  cstatus.report.components.find((c) => c.type === 'collector').metrics.records_db_gb = 10;
  cstatus.report.components.find((c) => c.type === 'collector').metrics.storage_free_gb = 5;
  await page.route(`**/hosts/${col.host_id}/status`, (r) => r.fulfill({ json: cstatus }));
  await page.goto(`${BASE}/hosts/${col.host_id}/components/${cc.component_id}`);
  await page.waitForSelector('[data-testid="days-to-full"]');
  assert.equal(await page.locator('[data-testid="days-to-full"]').innerText(), '1.5 days to full');
  assert.ok(await page.locator('.metric-fail [data-testid="days-to-full"], .metric-fail:has([data-testid="days-to-full"])').count() >= 1, 'under 2 days is red');
  await page.context().close();
});

// Visual regression: overview, hosts, host detail, collector and probe views (baselines in tests/__snapshots__).
await test('visual snapshots: overview, hosts, host detail, collector, probe', async () => {
  const col = PAGES.find((p) => p.name === 'host-overview');
  const shots = [
    ['overview-dark', 'dark', '/fleet', '.site-card'],
    ['overview-light', 'light', '/fleet', '.site-card'],
    ['hosts-dark', 'dark', '/hosts', 'tr.host-row'],
    ['host-detail-dark', 'dark', col.url, '.metric'],
    ['collector-dark', 'dark', PAGES.find((p) => p.name === 'collector').url, '.metric'],
    ['probe-dark', 'dark', PAGES.find((p) => p.name === 'probe').url, '[data-testid="port-tile"]'],
  ];
  const problems = [];
  for (const [name, scheme, url, ready] of shots) {
    const page = await newPage({ colorScheme: scheme, reducedMotion: 'reduce' });
    await page.goto(`${BASE}${url}`);
    await page.waitForSelector(ready);
    await page.waitForTimeout(800);
    try {
      const r = await snapshot(page, name);
      console.log(`       snapshot ${name}: ${r.written ? 'baseline written' : `${(r.ratio * 100).toFixed(3)}% differ`}`);
    } catch (e) {
      problems.push(String(e.message ?? e));
    }
    await page.context().close();
  }
  assert.deepEqual(problems, []);
});

await test('snoozing an issue hides it and writes an audit event', async () => {
  const page = await newPage();
  await page.goto(`${BASE}/issues`);
  await page.waitForSelector('tr.vt-row, .vt-table tbody tr:not(.vt-pad)');
  const before = (await getJson('/issues?state=open&limit=1000')).items.filter((i) => !i.snoozed_until);
  const target = before.find((i) => i.severity === 'warn');
  const shown = await page.locator('.vt-table tbody tr:not(.vt-pad)').count();
  assert.ok(shown >= 1);
  const row = page.locator('.vt-table tbody tr:not(.vt-pad)').filter({ hasText: target.detail }).first();
  await row.locator('button:has-text("Snooze")').click();
  await row.locator('button:text-is("1 h")').click();
  await page.waitForFunction((d) => ![...document.querySelectorAll('.vt-table tbody tr')].some((r) => r.textContent?.includes(d) && !r.classList.contains('vt-pad')), target.detail, { timeout: 10000 });
  const after = (await getJson('/issues?state=open&limit=1000')).items.find((i) => i.issue_id === target.issue_id);
  assert.ok(after.snoozed_until && after.snoozed_until !== 'resolved', 'snoozed on the server');
  const audit = await getJson('/audit?limit=5');
  assert.ok(audit.items.some((e) => e.action === 'issue.snooze' && Date.now() - Date.parse(e.ts) < 60000), 'audit event written');
  // visible again when asked for
  await page.check('input[type="checkbox"]');
  await page.waitForFunction((d) => [...document.querySelectorAll('.vt-table tbody tr')].some((r) => r.textContent?.includes(d)), target.detail);
  await page.context().close();
});

await test('global search jumps to a host; deep links work (SPA fallback)', async () => {
  const page = await newPage();
  const all = await hostsAll();
  const h = all.find((x) => x.name === 'hc-probe-02');
  await page.goto(`${BASE}/fleet`);
  await page.fill('input[role="combobox"]', h.mgmt_ip);
  await page.waitForSelector('[role="option"]');
  await page.keyboard.press('Enter');
  await page.waitForURL(`**/hosts/${h.host_id}`);
  await page.waitForSelector(`h1:text-is(${JSON.stringify(h.name)})`);
  // hard reload of a deep link is served by the SPA fallback
  await page.reload();
  await page.waitForSelector(`h1:text-is(${JSON.stringify(h.name)})`);
  const r = await fetch(`${BASE}/some/unknown/path`);
  assert.equal(r.status, 200);
  assert.match(await r.text(), /<div id="app">/);
  await page.context().close();
});

await test('theme toggle switches and persists', async () => {
  const page = await newPage();
  await page.goto(`${BASE}/fleet`);
  await page.waitForSelector('[data-testid="kpis"]');
  assert.equal(await page.evaluate(() => document.documentElement.getAttribute('data-theme')), null);
  await page.click('button[aria-label^="Switch to"]');
  assert.equal(await page.evaluate(() => document.documentElement.getAttribute('data-theme')), 'light');
  await page.reload();
  await page.waitForSelector('[data-testid="kpis"]');
  assert.equal(await page.evaluate(() => document.documentElement.getAttribute('data-theme')), 'light');
  await page.context().close();
});

await test('390 px viewport: no horizontal scroll on any page, both themes', async () => {
  const urls = PAGES.map((p) => p.url);
  for (const scheme of ['dark', 'light']) {
    const page = await newPage({ viewport: { width: 390, height: 844 }, colorScheme: scheme });
    for (const u of urls) {
      await page.goto(`${BASE}${u}`);
      await page.waitForSelector('main h1');
      await page.waitForTimeout(600);
      const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, bw: document.body.scrollWidth }));
      assert.ok(m.sw <= m.cw && m.bw <= m.cw, `${scheme} ${u}: scrollWidth ${m.sw} > ${m.cw}`);
    }
    // mobile nav drawer works
    await page.goto(`${BASE}/fleet`);
    await page.click('button[aria-label="Open navigation"]');
    await page.waitForSelector('.drawer a.nav-item');
    await page.click('.drawer a:has-text("Hosts")');
    await page.waitForURL('**/hosts');
    assert.ok(await page.locator('.vt-card').count() > 0, 'card list below 768 px');
    await page.context().close();
  }
});

await adminTests({ test, newPage, BASE, API, getJson, hostsAll, python, repo });

await test('auth states: 401 explains the expired Access session; 403 says not an admin', async () => {
  let page = await newPage();
  await page.route('**/api/admin/v1/fleet/summary', (r) => r.fulfill({ status: 401, json: { error: { code: 'unauthenticated', message: 'Access JWT missing' } } }));
  await page.goto(`${BASE}/fleet`);
  const b = page.locator('[data-kind="unauthorized"]');
  await b.waitFor();
  assert.match(await b.innerText(), /Access session expired/);
  assert.ok(await b.locator('button:has-text("Reload")').isVisible());
  await page.context().close();
  page = await newPage();
  await page.route('**/api/admin/v1/fleet/summary', (r) => r.fulfill({ status: 403, json: { error: { code: 'unknown_admin', message: 'no admin row' } } }));
  await page.goto(`${BASE}/fleet`);
  const f = page.locator('[data-kind="forbidden"]');
  await f.waitFor();
  assert.match(await f.innerText(), /not an admin/);
  await page.context().close();
});

await test('untrusted text is rendered as text, never as markup', async () => {
  const page = await newPage();
  const base = await hostsAll();
  const evil = '<img src=x onerror="window.__pwned=1">';
  const rows = base.map((h, i) => (i === 0 ? { ...h, name: evil } : h));
  await page.route('**/api/admin/v1/fleet/hosts?*', (r) => r.fulfill({ json: { items: rows, next_cursor: null } }));
  await page.goto(`${BASE}/hosts`);
  await page.waitForSelector('tr.host-row');
  assert.ok(await page.locator(`a.host-link:text-is(${JSON.stringify(evil)})`).count() === 1);
  assert.equal(await page.evaluate(() => window.__pwned), undefined);
  assert.equal(await page.locator('tr.host-row img').count(), 0);
  await page.context().close();
});

await test('axe-core: no serious or critical violations on every page, both themes', async () => {
  const bad = [];
  for (const scheme of ['dark', 'light']) {
    const page = await newPage({ colorScheme: scheme });
    for (const { name, url } of PAGES) {
      await page.goto(`${BASE}${url}`);
      await page.waitForSelector('main h1');
      await page.waitForTimeout(700);
      const res = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
      for (const v of res.violations.filter((x) => x.impact === 'serious' || x.impact === 'critical')) {
        bad.push(`${scheme} ${name} ${url}: ${v.id} (${v.impact}) ${JSON.stringify(v.nodes.slice(0, 3).map((n) => `${n.target.join(' ')} :: ${(n.failureSummary ?? '').split('\n').slice(0, 2).join(' ')}`))}`);
      }
    }
    await page.context().close();
  }
  assert.deepEqual(bad, []);
});

await test('axe-core: dialogs (create site, NOC token, confirmation) in both themes', async () => {
  const bad = [];
  for (const scheme of ['dark', 'light']) {
    const page = await newPage({ colorScheme: scheme });
    const check = async (label) => {
      const res = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
      for (const v of res.violations.filter((x) => x.impact === 'serious' || x.impact === 'critical')) bad.push(`${scheme} ${label}: ${v.id} ${JSON.stringify(v.nodes.slice(0, 2).map((n) => n.target.join(' ')))}`);
    };
    await page.goto(`${BASE}/sites`);
    await page.getByRole('button', { name: 'Create site' }).click();
    await page.locator('dialog[open]').waitFor();
    await check('create-site dialog');
    await page.keyboard.press('Escape');
    await page.goto(`${BASE}/hosts/${PAGES.find((p) => p.name === 'host-actions').url.split('/hosts/')[1]}`);
    await page.getByRole('button', { name: 'Decommission host' }).click();
    await page.locator('dialog[open]').waitFor();
    await check('decommission dialog');
    await page.context().close();
  }
  assert.deepEqual(bad, []);
});

// Last: kill the API. Time is driven with Playwright's clock so the 90 s / 5 min thresholds run in seconds.
await test('manager unreachable: freshness amber, then red, banner, automatic recovery', async () => {
  const page = await newPage();
  await page.clock.install();
  await page.goto(`${BASE}/fleet`);
  await page.waitForSelector('[data-testid="kpis"]');
  await page.clock.runFor(2000);
  assert.equal(await page.locator('.fresh').getAttribute('data-level'), 'ok');
  assert.equal(await page.locator('.conn-banner').count(), 0);
  mock.kill('SIGKILL');
  await page.clock.runFor(31000);
  const banner = page.locator('.conn-banner');
  await banner.waitFor({ timeout: 10000 });
  assert.match(await banner.innerText(), /Can.t reach the manager/);
  assert.equal(await banner.getAttribute('data-kind'), 'retrying');
  await page.clock.runFor(70000);
  await page.waitForFunction(() => document.querySelector('.fresh')?.getAttribute('data-level') === 'amber', null, { timeout: 10000 });
  await page.clock.runFor(240000);
  await page.waitForFunction(() => document.querySelector('.fresh')?.getAttribute('data-level') === 'red', null, { timeout: 10000 });
  assert.equal(await banner.getAttribute('data-kind'), 'down');
  assert.ok(await page.locator('[data-testid="kpis"]').isVisible(), 'last known data stays on screen');
  mock = startMock(apiPort);
  await waitHttp(`http://127.0.0.1:${apiPort}/api/admin/v1/me`);
  await page.clock.runFor(310000);
  await page.waitForFunction(() => !document.querySelector('.conn-banner') && document.querySelector('.fresh')?.getAttribute('data-level') === 'ok', null, { timeout: 15000 });
  await page.context().close();
});

await browser.close();
killAll();
const failed = results.filter(([, ok]) => !ok);
console.log(`\n${results.length - failed.length}/${results.length} e2e tests passed`);
process.exit(failed.length ? 1 : 0);
