// M6 Speedtest settings page against vite preview + mock_admin (CR-m6-manager): branding preview, consent versioning,
// logo upload bounds, zones, QR signage, pause switch, device key, connectors, roles, no results/evidence anywhere (SR-20).
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const PNG_1PX = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
const OUT = process.env.E2E_ARTIFACTS ?? '';

export async function speedtestTests(ctx) {
  const { test, newPage, BASE, API, getJson } = ctx;
  const URL_ = `${BASE}/sites/hall-b/speedtest`;
  const send = async (method, p, body, headers = {}) => {
    const r = await fetch(`${API}${p}`, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    return { status: r.status, body: text ? JSON.parse(text) : null };
  };
  const shot = async (page, name) => {
    if (!OUT) return;
    mkdirSync(OUT, { recursive: true });
    await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: true });
  };
  const open = async (page) => {
    await page.goto(URL_);
    await page.getByLabel('Page title').waitFor();
    await page.locator('[data-testid="st-preview"]').waitFor();
  };
  const toast = (page, re) => page.locator('.toast').filter({ hasText: re }).first().waitFor({ timeout: 10000 });

  await test('speedtest settings: the page shows the seeded settings with a live branding preview and no CSP errors', async () => {
    const page = await newPage();
    await open(page);
    assert.equal(await page.getByLabel('Page title').inputValue(), 'Summit speed check');
    assert.equal(await page.locator('[data-testid="st-preview-title"]').innerText(), 'Summit speed check');
    assert.equal(await page.getByLabel('Listen address').inputValue(), '10.0.0.9');
    assert.match(await page.locator('[data-testid="consent-version"]').innerText(), /Current version 3/);
    await page.getByLabel('Page title').fill('Hall B speed check');
    assert.equal(await page.locator('[data-testid="st-preview-title"]').innerText(), 'Hall B speed check');
    await page.getByLabel('Primary colour').fill('#ff0000');
    const bg = await page.locator('.st-preview-btn').evaluate((e) => getComputedStyle(e).backgroundColor);
    assert.equal(bg, 'rgb(255, 0, 0)');
    await shot(page, 'speedtest-settings');
    assert.deepEqual(page.errors, []);
    await page.context().close();
  });

  await test('speedtest settings: save writes the PUT, one audit event, and the change survives a reload', async () => {
    const page = await newPage();
    await open(page);
    const submit = page.getByRole('button', { name: 'Save settings' });
    assert.ok(await submit.isDisabled(), 'nothing to save yet');
    const before = (await getJson('/audit?limit=200')).items.filter((e) => e.action === 'speedtest.settings').length;
    await page.getByLabel('Page title').fill('Saved by e2e');
    await page.getByLabel('Download target (Mb/s)').fill('40');
    const put = page.waitForRequest((r) => r.method() === 'PUT' && r.url().endsWith('/sites/hall-b/speedtest'));
    await submit.click();
    const req = await put;
    const body = req.postDataJSON();
    assert.equal(body.branding.title, 'Saved by e2e');
    assert.equal(body.targets.down_mbps, 40);
    assert.equal(body.consent.version, undefined, 'the client never sends a consent version');
    assert.equal(req.headers()['x-exp-request'], '1');
    await toast(page, /saved/i);
    const after = (await getJson('/audit?limit=200')).items.filter((e) => e.action === 'speedtest.settings');
    assert.equal(after.length, before + 1);
    assert.ok(!JSON.stringify(after[0]).includes('Saved by e2e'), 'the audit event names fields, not content');
    await page.reload();
    await page.getByLabel('Page title').waitFor();
    assert.equal(await page.getByLabel('Page title').inputValue(), 'Saved by e2e');
    assert.equal((await getJson('/sites/hall-b/speedtest')).targets.down_mbps, 40);
    await page.context().close();
  });

  await test('speedtest settings: editing the consent text bumps the version and keeps the history', async () => {
    const page = await newPage();
    await open(page);
    const v0 = (await getJson('/sites/hall-b/speedtest')).consent.version;
    await page.getByLabel('Consent text', { exact: true }).fill('We measure your speed and look at Wi-Fi metadata. No names.');
    assert.match(await page.locator('[data-testid="consent-version"]').innerText(), new RegExp(`version ${v0 + 1}`));
    await page.getByRole('button', { name: 'Save settings' }).click();
    await toast(page, new RegExp(`version ${v0 + 1}`));
    assert.match(await page.locator('[data-testid="consent-version"]').innerText(), new RegExp(`Current version ${v0 + 1}`));
    const hist = await getJson('/sites/hall-b/speedtest/consent-history');
    assert.deepEqual(hist.items.map((i) => i.version).slice(0, 2), [v0 + 1, v0]);
    await page.getByRole('button', { name: /Show history/ }).click();
    await page.locator('[data-testid="consent-history"] li').first().waitFor();
    assert.equal(await page.locator('[data-testid="consent-history"] li').count(), hist.items.length);
    // an unchanged text does not bump again
    await page.getByLabel('Page title').fill('Another title');
    await page.getByRole('button', { name: 'Save settings' }).click();
    await toast(page, /saved/i);
    assert.equal((await getJson('/sites/hall-b/speedtest')).consent.version, v0 + 1);
    await page.context().close();
  });

  await test('speedtest settings: validation explains itself and blocks saving', async () => {
    const page = await newPage();
    await open(page);
    await page.getByLabel('Listen address').fill('0.0.0.0');
    assert.ok(await page.getByRole('button', { name: 'Save settings' }).isDisabled());
    assert.match(await page.locator('main').innerText(), /unicast address of the speedtest box/);
    await page.getByLabel('Listen address').fill('10.0.0.9');
    await page.getByLabel('Consent text', { exact: true }).fill('   ');
    assert.match(await page.locator('main').innerText(), /consent text is required/);
    assert.ok(await page.getByRole('button', { name: 'Save settings' }).isDisabled());
    await page.getByRole('button', { name: 'Discard changes' }).click();
    assert.ok(await page.getByRole('button', { name: 'Save settings' }).isDisabled());
    await page.context().close();
  });

  await test('speedtest settings: zones and subnet labels can be added and removed', async () => {
    const page = await newPage();
    await open(page);
    const before = await getJson('/sites/hall-b/speedtest');
    await page.getByRole('button', { name: 'Add zone' }).click();
    const z = page.getByRole('group', { name: /^zone \d+$/ }).last();
    await z.getByLabel('Zone id').fill('hallc');
    await z.getByLabel('Zone name').fill('Hall C');
    await page.getByRole('button', { name: 'Add subnet' }).click();
    const sub = page.getByRole('group', { name: /^subnet \d+$/ }).last();
    await sub.getByLabel('Subnet', { exact: true }).fill('10.62.0.0/16');
    await sub.getByLabel('Zone', { exact: true }).selectOption('hallc');
    // removing a zone that a subnet still points at is explained, and fixed by removing that subnet too
    const first = before.zones[0].id;
    await page.getByRole('button', { name: 'Remove zone 1' }).click();
    assert.match(await page.locator('main').innerText(), /Not one of the zones above/);
    const idx = before.zone_labels.subnets.findIndex((n) => n.zone === first);
    assert.ok(idx >= 0);
    await page.getByRole('button', { name: `Remove subnet ${idx + 1}` }).click();
    assert.deepEqual(await page.locator('.field-error').allInnerTexts(), [], 'no remaining problems');
    await page.getByRole('button', { name: 'Save settings' }).click();
    await toast(page, /saved/i);
    const s = await getJson('/sites/hall-b/speedtest');
    assert.deepEqual(s.zones.map((x) => x.id), [...before.zones.slice(1).map((x) => x.id), 'hallc']);
    assert.deepEqual(s.zone_labels.subnets.map((x) => x.cidr), [...before.zone_labels.subnets.filter((n) => n.zone !== first).map((n) => n.cidr), '10.62.0.0/16']);
    await page.context().close();
  });

  await test('speedtest settings: logo upload enforces type and size, previews, and stores the artifact', async () => {
    const page = await newPage();
    await open(page);
    const file = page.getByLabel('Logo image file');
    await file.setInputFiles({ name: 'big.png', mimeType: 'image/png', buffer: Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47]), Buffer.alloc(256 * 1024)]) });
    assert.match(await page.locator('main').innerText(), /at most 256 KiB/);
    await file.setInputFiles({ name: 'x.gif', mimeType: 'image/gif', buffer: Buffer.from('GIF89a') });
    assert.match(await page.locator('main').innerText(), /PNG, SVG or JPEG/);
    await file.setInputFiles({ name: 'fake.png', mimeType: 'image/png', buffer: Buffer.from('not really a png') });
    assert.match(await page.locator('main').innerText(), /not a PNG/);
    assert.ok(await page.getByRole('button', { name: 'Upload logo' }).isDisabled());
    await file.setInputFiles({ name: 'logo.png', mimeType: 'image/png', buffer: PNG_1PX });
    await page.locator('[data-testid="logo-chosen"]').waitFor();
    await page.locator('.st-preview img.st-preview-logo').waitFor();
    assert.match((await page.locator('.st-preview img.st-preview-logo').getAttribute('src')) ?? '', /^data:image\/png;base64,/);
    const up = page.waitForRequest((r) => r.method() === 'POST' && r.url().endsWith('/speedtest/logo'));
    await page.getByRole('button', { name: 'Upload logo' }).click();
    const req = await up;
    assert.equal(req.headers()['content-type'], 'image/png');
    assert.deepEqual(req.postDataBuffer(), PNG_1PX);
    await toast(page, /Logo uploaded/);
    await page.locator('[data-testid="logo-state"]').filter({ hasText: 'logo set' }).waitFor();
    const s = await getJson('/sites/hall-b/speedtest');
    assert.match(s.branding.logo_artifact, /^art_/);
    await shot(page, 'speedtest-logo');
    await page.context().close();
  });

  await test('speedtest signage: one QR per zone, printable, text rendered as text', async () => {
    const page = await newPage();
    await open(page);
    await page.getByRole('button', { name: /Open printable signage/ }).click();
    const sheet = page.locator('[data-testid="signage"]');
    await sheet.waitFor();
    const zones = (await getJson('/sites/hall-b/speedtest/qr')).items;
    assert.ok(zones.length >= 2);
    assert.equal(await sheet.locator('svg.qr').count(), zones.length);
    assert.match(await sheet.innerText(), new RegExp(zones[0].url.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')));
    // each QR is a real, dense matrix, black on white
    const d = await sheet.locator('svg.qr path').first().getAttribute('d');
    assert.ok(d.length > 200);
    assert.equal(await sheet.locator('svg.qr rect').first().getAttribute('fill'), '#fff');
    await shot(page, 'speedtest-signage');
    await page.keyboard.press('Escape');
    await page.context().close();
  });

  await test('speedtest settings: pause switch (operator) and device key (owner) with their role limits', async () => {
    const page = await newPage();
    await open(page);
    const paused0 = (await getJson('/sites/hall-b/speedtest')).internet_leg.paused;
    await page.getByRole('button', { name: paused0 ? 'Resume internet leg' : 'Pause internet leg' }).click();
    await toast(page, paused0 ? /resumed/ : /paused/);
    assert.equal((await getJson('/sites/hall-b/speedtest')).internet_leg.paused, !paused0);
    assert.ok(await page.getByRole('button', { name: /Pause internet leg|Resume internet leg/ }).isEnabled());
    // device key: confirm dialog, then only its state is shown
    const dk0 = await send('POST', '/settings/speedtest-device-key', {}); // owner creates/rotates once to know the id
    assert.equal(dk0.status, 200);
    await page.reload();
    await page.getByRole('button', { name: /device key/ }).click();
    await page.locator('dialog[open]').waitFor();
    await page.locator('dialog[open]').getByRole('button', { name: /Rotate key|Create key/ }).click();
    await toast(page, /Device key k\d+ is in place/);
    const txt = await page.locator('main').innerText();
    assert.ok(!/expk_/.test(txt), 'the secret is never shown');
    await page.context().close();
    // a viewer sees everything but can change nothing
    const v = await newPage();
    await v.route('**/api/admin/v1/**', (route) => route.continue({ headers: { ...route.request().headers(), 'x-mock-role': 'viewer' } }));
    await v.goto(URL_);
    await v.getByLabel('Page title').waitFor();
    assert.ok(await v.getByLabel('Page title').isDisabled());
    assert.ok(await v.getByRole('button', { name: /Pause internet leg|Resume internet leg/ }).isDisabled());
    assert.ok(await v.getByRole('button', { name: /device key/ }).isDisabled());
    assert.ok(await v.getByRole('button', { name: 'Save settings' }).isDisabled());
    assert.equal(await v.getByRole('button', { name: /Show history/ }).count(), 0, 'consent history is admin-only');
    const rr = await send('PUT', '/sites/hall-b/speedtest', { consent: { text: 'x' } }, { 'x-mock-role': 'viewer' });
    assert.equal(rr.status, 403);
    await v.context().close();
  });

  await test('speedtest settings: connectors (Mist, EdgeConnect) are write-only; SSE has no connector', async () => {
    const page = await newPage();
    await open(page);
    const mist = page.locator('[data-testid="connector-mist"]');
    await mist.waitFor();
    await mist.getByLabel('API base URL').fill('https://api.mist.example.test');
    await mist.getByLabel('API token').fill('MIST-E2E-TOKEN');
    await mist.getByRole('button', { name: /Save Juniper Mist/ }).click();
    await toast(page, /Juniper Mist saved/);
    const g = await getJson('/integrations/mist');
    assert.equal(g.credentials.set, true);
    assert.ok(!JSON.stringify(g).includes('MIST-E2E-TOKEN'), 'the token is never returned');
    assert.equal(await mist.getByLabel('API token').inputValue(), '', 'and never shown again');
    assert.match(await page.locator('main').innerText(), /HPE Aruba SSE has no API connector/);
    assert.equal((await send('GET', '/integrations/sse')).status, 404);
    await page.context().close();
  });

  await test('speedtest: the speedtest + runner shapes show on the host list and component pages; runner sources are editable', async () => {
    const page = await newPage();
    const hosts = (await getJson('/fleet/hosts?limit=1000')).items;
    const box = hosts.find((h) => h.shapes.includes('speedtest'));
    assert.ok(box && box.shapes.includes('runner'), 'the seeded all-in-one box');
    await page.goto(`${BASE}/hosts?shape=speedtest`);
    await page.waitForSelector('tr.host-row');
    assert.ok((await page.locator('tr.host-row').count()) >= 1);
    const comps = (await getJson(`/hosts/${box.host_id}/components`)).items;
    const spd = comps.find((c) => c.type === 'speedtest');
    const run = comps.find((c) => c.type === 'runner');
    await page.goto(`${BASE}/hosts/${box.host_id}/components/${spd.component_id}`);
    await page.getByText('Tests / hour').waitFor();
    assert.ok(await page.getByRole('link', { name: /speedtest settings/ }).isVisible());
    assert.match(await page.locator('main').innerText(), /test results never reach the manager/);
    await page.goto(`${BASE}/hosts/${box.host_id}/components/${run.component_id}`);
    await page.getByText('Correlations / h').waitFor();
    await page.goto(`${BASE}/hosts/${box.host_id}/components/${run.component_id}?view=configure`);
    await page.getByRole('button', { name: 'Add appliance' }).click();
    const grp = page.getByRole('group', { name: 'Appliance 2' });
    await grp.getByLabel('Appliance id (nePk)').fill('2.NE');
    await page.getByLabel('Accept from (CIDR)').fill('10.0.0.0/8, 192.0.2.0/24');
    await page.getByRole('button', { name: 'Save configuration' }).click();
    await toast(page, /Saved/);
    const after = (await getJson(`/hosts/${box.host_id}/components`)).items.find((c) => c.type === 'runner');
    assert.deepEqual(after.config.correlation.sources.ec.appliances.map((a) => a.ne_pk), ['1.NE', '2.NE']);
    assert.deepEqual(after.config.correlation.sources.syslog.allow, ['10.0.0.0/8', '192.0.2.0/24']);
    assert.equal(after.config.correlation.sources.sse, undefined, 'sse is never part of the intent (the compiler pins it off)');
    await page.context().close();
  });

  await test('speedtest: nav entry, site page link and the index redirect', async () => {
    const page = await newPage();
    await page.goto(`${BASE}/sites/hall-b`);
    await page.getByRole('link', { name: 'Open speedtest settings' }).click();
    await page.waitForURL('**/sites/hall-b/speedtest');
    await page.goto(`${BASE}/fleet`);
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Speedtest' }).click();
    await page.waitForURL('**/speedtest');
    await page.getByRole('link', { name: 'Hall B' }).waitFor();
    await page.context().close();
  });

  await test('SR-20: the manager UI and the mock API expose no test results or evidence', async () => {
    for (const p of ['/speedtests', '/evidence', '/results', '/sites/hall-b/speedtests', '/sites/hall-b/speedtest/results', '/sites/hall-b/speedtest/evidence']) {
      assert.equal((await send('GET', p)).status, 404, p);
    }
    const page = await newPage();
    const seen = [];
    page.on('request', (r) => { if (r.url().includes('/api/')) seen.push(new URL(r.url()).pathname); });
    await open(page);
    await page.waitForTimeout(500);
    assert.ok(seen.length > 3);
    assert.ok(!seen.some((p) => /speedtests|evidence|results|\/sessions/.test(p)), seen.join(','));
    await page.context().close();
  });
}
