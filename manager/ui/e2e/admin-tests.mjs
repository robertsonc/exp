// Administration flows against vite preview + mock_admin (docs/spec/11-manager-ui.md section 4.7 and 05-manager.md section 10).
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
import path from 'node:path';

const FP = /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/;

export async function adminTests(ctx) {
  const { test, newPage, BASE, API, getJson, hostsAll, python, repo } = ctx;
  const send = async (method, p, body, headers = {}) => {
    const r = await fetch(`${API}${p}`, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    return { status: r.status, body: text ? JSON.parse(text) : null, text };
  };
  const audit = async (n = 80) => (await getJson(`/audit?limit=${n}`)).items;
  const fresh = (items, action, resource) => items.some((e) => e.action === action && (!resource || e.resource === resource) && Date.now() - Date.parse(e.ts) < 120000);
  // A dashboard that has an address (the seeded ones); hosts added by the wizard tests have none until an admin sets it.
  const seededDashboard = async () => {
    const ov = await getJson('/overview');
    for (const h of ov.hosts) {
      for (const c of h.components.filter((x) => x.type === 'dashboard' && x.health === 'ok')) {
        const full = (await getJson(`/hosts/${h.host_id}/components`)).items.find((x) => x.component_id === c.component_id);
        if (full?.config?.url) return { dh: h, dc: c };
      }
    }
    throw new Error('no seeded dashboard with an address');
  };
  // Clipboard reads only work in a focused page and can hang otherwise: focus first and never wait unbounded.
  const clip = async (page) => {
    await page.bringToFront();
    return Promise.race([page.evaluate(() => navigator.clipboard.readText()), new Promise((_, rej) => setTimeout(() => rej(new Error('clipboard read timed out')), 8000))]);
  };
  const toast = (page, re) => page.locator('.toast').filter({ hasText: re }).first().waitFor({ timeout: 10000 });

  // ------------------------------------------------------------------------------------------------------------------
  await test('add-host wizard end to end against the simulated enrolment', async () => {
    const page = await newPage({ permissions: ['clipboard-read', 'clipboard-write'] });
    await page.goto(`${BASE}/hosts/new`);
    await page.getByLabel('Host name').waitFor();
    // step 1: name, site, shapes
    const create = page.getByRole('button', { name: 'Create host and get the install command' });
    assert.ok(await create.isDisabled(), 'cannot continue without a name');
    await page.getByLabel('Host name').fill('e2e-probe-9');
    await page.getByLabel('Site', { exact: true }).selectOption('hall-c');
    await page.getByLabel('Dashboard', { exact: true }).check();
    await page.getByLabel('Probe', { exact: true }).check();
    const reqs = [];
    page.on('request', (r) => { if (r.method() !== 'GET') reqs.push(r); });
    await create.click();
    // step 2: the one-liner, a one-hour countdown and live waiting
    const cmd = page.locator('code[aria-label="install command"]');
    await cmd.waitFor();
    const first = await cmd.innerText();
    assert.match(first, /^curl .*install\.sh.* expe_[A-Za-z0-9_-]+$/);
    assert.match(page.url(), /\/hosts\/new\?host=h_/);
    assert.match(await page.locator('.countdown').innerText(), /^(59|60):\d\d$/);
    assert.match(await page.locator('[data-testid="waiting"]').innerText(), /Waiting for the host/);
    await page.getByRole('button', { name: 'Copy install command' }).click();
    await page.getByRole('button', { name: 'Copy install command' }).filter({ hasText: 'Copied' }).waitFor();
    assert.equal(await clip(page), first, 'the copy button copies the one-liner');
    // a new token replaces the command
    await page.getByRole('button', { name: 'Create a new token' }).click();
    await page.waitForFunction((old) => document.querySelector('code[aria-label="install command"]')?.textContent !== old, first);
    // step 3: the host enrols (the mock simulates it) and its facts appear
    const hostId = new URL(page.url()).searchParams.get('host');
    await page.locator('[data-testid="host-facts"]').waitFor({ timeout: 40000 });
    assert.match(await page.locator('[data-testid="host-facts"]').innerText(), /e2e-probe-9/);
    const host = await getJson(`/hosts/${hostId}`);
    assert.equal(host.state, 'enrolled');
    const mgmt = host.facts.interfaces.find((i) => i.default_route || i.in_use_by === 'mgmt');
    const others = host.facts.interfaces.filter((i) => i !== mgmt);
    assert.ok(mgmt && others.length >= 2);
    // the management interface is disabled and the reason is shown
    const row = page.locator(`tr[data-iface="${mgmt.name}"]`);
    assert.equal(await row.getAttribute('data-blocked'), 'true');
    assert.ok(await row.locator('select').isDisabled());
    assert.match(await row.locator('[data-testid="iface-reason"]').innerText(), /Management interface.*default route/);
    for (const i of others) assert.equal(await page.locator(`tr[data-iface="${i.name}"]`).getAttribute('data-blocked'), 'false');
    const apply = page.getByRole('button', { name: 'Apply', exact: true });
    assert.ok(await apply.isDisabled(), 'a probe needs at least one assigned interface');
    // assign roles and a target address
    const [a, b] = others;
    await page.getByLabel(`Test role for ${a.name}`).selectOption('client');
    await page.getByLabel(`Test role for ${b.name}`).selectOption('target');
    await page.getByLabel(`Target address for ${b.name}`).fill('10.1.0.999/24');
    assert.ok(await apply.isDisabled(), 'an invalid target address blocks Apply');
    assert.match(await page.locator('.form-error').innerText(), /a\.b\.c\.d\/len/);
    await page.getByLabel(`Target address for ${b.name}`).fill('10.1.0.250/24');
    await page.getByLabel(`Gateway for ${b.name}`).fill('10.1.0.1');
    await page.waitForFunction(() => ![...document.querySelectorAll('button')].find((x) => x.textContent === 'Apply')?.disabled);
    const put = page.waitForRequest((r) => r.method() === 'PUT' && /\/components\/cmp_[^/]+\/ports$/.test(r.url()));
    await apply.click();
    const pr = await put;
    assert.deepEqual(pr.postDataJSON(), { ports: [{ id: 'c01', iface: a.name, role: 'client' }, { id: 's01', iface: b.name, role: 'target', address: '10.1.0.250/24', gateway: '10.1.0.1' }] });
    assert.ok(!JSON.stringify(pr.postDataJSON()).includes(mgmt.name), 'the management interface is never sent');
    assert.equal(pr.headers()['x-exp-request'], '1', 'every mutation carries the CSRF header');
    assert.match(pr.headers()['content-type'], /^application\/json/);
    // step 4: progress until every component is healthy
    await page.locator('[data-testid="apply-progress"]').waitFor();
    await page.waitForFunction(() => /All 2 components are healthy/.test(document.querySelector('[data-testid="apply-progress"]')?.textContent ?? ''), null, { timeout: 30000 });
    assert.ok(page.url().includes('step=apply'));
    const comps = (await getJson(`/hosts/${hostId}/components`)).items;
    assert.deepEqual(comps.map((c) => c.type).sort(), ['dashboard', 'probe']);
    assert.ok(comps.every((c) => c.health === 'ok'));
    const probe = comps.find((c) => c.type === 'probe');
    assert.deepEqual(probe.config.ports.map((p) => p.id), ['c01', 's01']);
    assert.ok(probe.config.ports.every((p) => p.iface !== mgmt.name));
    const log = await audit();
    for (const [act, res] of [['host.create', 'host:e2e-probe-9'], ['component.create', null], ['component.ports', null]]) assert.ok(fresh(log, act, res), `audit has ${act}`);
    // a reload resumes the same step
    await page.reload();
    await page.locator('[data-testid="apply-progress"]').waitFor();
    assert.ok(reqs.every((r) => (r.headers()['x-exp-request'] ?? '') === '1'), 'all mutations carried X-Exp-Request');
    assert.deepEqual(page.errors, []);
    await page.context().close();
  });

  await test('forbidden: the management interface is refused by the API as well', async () => {
    const host = (await hostsAll()).find((h) => h.name === 'hb-probe-05');
    const comps = (await getJson(`/hosts/${host.host_id}/components`)).items;
    const st = await getJson(`/hosts/${host.host_id}`);
    const mgmt = st.facts.interfaces.find((i) => i.default_route);
    const r = await send('PUT', `/components/${comps[0].component_id}/ports`, { ports: [{ id: 'c01', iface: mgmt.name, role: 'client' }] });
    assert.equal(r.status, 422);
    assert.equal(r.body.error.code, 'mgmt_interface_refused');
  });

  // ------------------------------------------------------------------------------------------------------------------
  await test('host actions: restart, rotate credentials, rotate agent secret, new enrol token, typed decommission', async () => {
    const page = await newPage({ permissions: ['clipboard-read', 'clipboard-write'] });
    const all = await hostsAll();
    const h = all.find((x) => x.name === 'hb-probe-05');
    await page.goto(`${BASE}/hosts/${h.host_id}?tab=actions`);
    await page.getByRole('button', { name: 'Restart component' }).click();
    let dlg = page.locator('dialog[open]');
    await dlg.getByRole('button', { name: 'Restart', exact: true }).click();
    await toast(page, /Restart of .* queued/);
    await page.getByRole('button', { name: 'Rotate credentials' }).click();
    await page.locator('dialog[open]').getByRole('button', { name: 'Rotate', exact: true }).click();
    await toast(page, /being rotated/);
    await page.getByRole('button', { name: 'Rotate agent secret' }).click();
    await page.locator('dialog[open]').getByRole('button', { name: 'Rotate', exact: true }).click();
    await toast(page, /agent secret .* rotated/);
    const log = await audit();
    assert.ok(fresh(log, 'component.restart') && fresh(log, 'component.rotate') && fresh(log, 'host.rotate_agent'));
    // rotated credentials are delivered through desired state only: the page never shows a token
    assert.ok(!/exp[aeidn]_[A-Za-z0-9_-]{20,}/.test(await page.content()));
    // new enrol token for a pending host
    const pending = all.filter((x) => x.state === 'pending');
    await page.goto(`${BASE}/hosts/${pending[0].host_id}?tab=actions`);
    await page.getByRole('button', { name: 'Create enrol token' }).click();
    dlg = page.locator('dialog[open]');
    assert.match(await dlg.locator('code[aria-label="install command"]').innerText(), /expe_/);
    assert.match(await dlg.locator('.countdown').innerText(), /^(59|60):\d\d$/);
    await dlg.getByRole('button', { name: 'Done' }).click();
    assert.ok(fresh(await audit(), 'host.enrol_token'));
    // decommission needs the host name typed
    const victim = all.filter((x) => x.state === 'enrolled').pop();
    await page.goto(`${BASE}/hosts/${victim.host_id}?tab=actions`);
    await page.getByRole('button', { name: 'Decommission host' }).click();
    dlg = page.locator('dialog[open]');
    const go = dlg.locator('button.btn-danger');
    assert.ok(await go.isDisabled());
    await dlg.locator('input').fill(victim.name.slice(0, -1));
    assert.ok(await go.isDisabled(), 'a partial name does not confirm');
    await dlg.locator('input').fill(victim.name);
    await go.click();
    await toast(page, /being decommissioned/);
    assert.equal((await getJson(`/hosts/${victim.host_id}`)).state, 'decommissioning');
    assert.ok(fresh(await audit(), 'host.decommission'));
    await page.context().close();
  });

  // ------------------------------------------------------------------------------------------------------------------
  await test('probe editor: edit heartbeat and app targets, validation blocks bad values, saves an audited update', async () => {
    const page = await newPage();
    const h = (await hostsAll()).find((x) => x.name === 'hb-probe-05');
    const c = (await getJson(`/hosts/${h.host_id}/components`)).items.find((x) => x.type === 'probe');
    await page.goto(`${BASE}/hosts/${h.host_id}/components/${c.component_id}?view=configure`);
    await page.getByLabel('Interval (seconds)').waitFor();
    const save = page.getByRole('button', { name: 'Save configuration' });
    assert.ok(await save.isDisabled(), 'nothing to save yet');
    await page.getByLabel('Interval (seconds)').fill('2');
    assert.match(await page.locator('.field-error').first().innerText(), /5 to 60/);
    assert.ok(await save.isDisabled(), 'an invalid value blocks saving');
    await page.getByLabel('Interval (seconds)').fill('20');
    await page.getByLabel('Ping targets').fill('9.9.9.9\n1.1.1.1');
    await page.getByRole('button', { name: 'Add app target' }).click();
    const grp = page.getByRole('group', { name: /App target \d+/ }).last();
    await grp.getByLabel('App name').fill('e2e-app');
    await grp.getByLabel('URL').fill('https://e2e.example.com/health');
    await grp.getByLabel('Apdex T (ms)').fill('750');
    await page.getByRole('button', { name: 'Add label' }).click();
    const lab = page.getByRole('group', { name: /Label \d+/ }).last();
    await lab.getByLabel('Name').fill('area');
    await lab.getByLabel('Value').fill('keynote');
    await page.getByLabel('Path test').uncheck().catch(() => undefined);
    const patch = page.waitForRequest((r) => r.method() === 'PATCH');
    await save.click();
    const req = await patch;
    assert.equal(req.headers()['x-exp-request'], '1');
    await toast(page, /Saved .*applies it on its next poll/);
    const after = (await getJson(`/hosts/${h.host_id}/components`)).items.find((x) => x.type === 'probe');
    assert.equal(after.config.heartbeat.interval_s, 20);
    assert.deepEqual(after.config.heartbeat.ping, ['9.9.9.9', '1.1.1.1']);
    assert.ok(after.config.tests.app.targets.some((t) => t.app === 'e2e-app' && t.apdex_t_ms === 750));
    assert.equal(after.config.labels.area, 'keynote');
    assert.equal(after.config.labels.zone, 'floor-1', 'existing labels survive');
    assert.ok(after.config.ports.length >= 1, 'unrelated keys survive the edit');
    assert.ok(fresh(await audit(), 'component.update'));
    await page.context().close();
  });

  await test('collector editor: retention and alerts', async () => {
    const page = await newPage();
    const h = (await hostsAll()).find((x) => x.name === 'hb-col-01');
    const c = (await getJson(`/hosts/${h.host_id}/components`)).items.find((x) => x.type === 'collector');
    await page.goto(`${BASE}/hosts/${h.host_id}/components/${c.component_id}?view=configure`);
    await page.getByLabel('Records (days)').fill('14');
    await page.getByLabel('Voice').selectOption('plain');
    await page.getByLabel('Board URL').fill('http://insecure.example.com');
    assert.match(await page.locator('.field-error').first().innerText(), /https/);
    assert.ok(await page.getByRole('button', { name: 'Save configuration' }).isDisabled());
    await page.getByLabel('Board URL').fill('https://board.example.com/hall-b');
    await page.getByRole('button', { name: 'Save configuration' }).click();
    await toast(page, /Saved/);
    const after = (await getJson(`/hosts/${h.host_id}/components`)).items.find((x) => x.type === 'collector');
    assert.equal(after.config.retention.records_days, 14);
    assert.equal(after.config.alerts.voice, 'plain');
    assert.equal(after.config.alerts.board_url, 'https://board.example.com/hall-b');
    await page.context().close();
  });

  // ------------------------------------------------------------------------------------------------------------------
  await test('dashboard editor: title, TLS fingerprint, collectors', async () => {
    const page = await newPage();
    const { dh, dc } = await seededDashboard();
    await page.goto(`${BASE}/hosts/${dh.host_id}/components/${dc.component_id}?view=configure`);
    await page.getByLabel('Title', { exact: true }).fill('Hall B wall board');
    assert.equal(await page.locator('[data-testid="tls-fp"]').innerText(), '—', 'no fingerprint is shown until the dashboard reports one');
    const fp = 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89';
    const status = await getJson(`/hosts/${dh.host_id}/status`);
    status.report.components.find((c) => c.type === 'dashboard').facts = { ...(status.report.components.find((c) => c.type === 'dashboard').facts ?? {}), tls_fingerprint_sha256: fp };
    await page.route(`**/hosts/${dh.host_id}/status`, (r) => r.fulfill({ json: status }));
    await page.reload();
    await page.getByLabel('Title', { exact: true }).fill('Hall B wall board');
    assert.equal(await page.locator('[data-testid="tls-fp"]').innerText(), fp, 'the reported TLS fingerprint is shown');
    assert.match(fp, FP);
    await page.getByLabel('Certificate mode').selectOption('provided');
    assert.match(await page.locator('.hint').filter({ hasText: 'write-only' }).first().innerText(), /no upload/);
    await page.getByLabel('Certificate mode').selectOption('self_signed');
    await page.getByRole('button', { name: 'Save configuration' }).click();
    await toast(page, /Saved/);
    const after = (await getJson(`/hosts/${dh.host_id}/components`)).items.find((x) => x.component_id === dc.component_id);
    assert.equal(after.config.title, 'Hall B wall board');
    await page.context().close();
  });

  await test('dashboard local user: the password is hashed in the browser and only the hash is sent', async () => {
    const page = await newPage();
    const PW = `Pw-${randomBytes(6).toString('hex')}-correct-horse`;
    const leaked = [];
    page.on('request', (r) => { if ((r.postData() ?? '').includes(PW) || r.url().includes(PW)) leaked.push(`${r.method()} ${r.url()}`); });
    const { dh, dc } = await seededDashboard();
    await page.goto(`${BASE}/hosts/${dh.host_id}/components/${dc.component_id}?view=configure`);
    await page.getByLabel('Username').fill('e2e.operator');
    await page.getByLabel('Role', { exact: true }).selectOption('operator');
    await page.getByLabel('Password', { exact: true }).fill(PW);
    await page.getByLabel('Repeat password').fill(`${PW}x`);
    assert.match(await page.locator('.field-error').filter({ hasText: 'do not match' }).innerText(), /do not match/);
    assert.ok(await page.getByRole('button', { name: 'Add user' }).isDisabled());
    await page.getByLabel('Repeat password').fill(PW);
    const post = page.waitForRequest((r) => r.method() === 'POST' && r.url().endsWith(`/dashboards/${dc.id}/users`));
    await page.getByRole('button', { name: 'Add user' }).click();
    const req = await post;
    const raw = req.postData();
    assert.ok(!raw.includes(PW), 'the plaintext password is not in the request body');
    const body = JSON.parse(raw);
    assert.deepEqual(Object.keys(body).sort(), ['hash', 'role', 'username']);
    assert.match(body.hash, /^pbkdf2_sha256\$600000\$[A-Za-z0-9+/]{22}==\$[A-Za-z0-9+/]{43}=$/, '16-byte salt and 32-byte key, standard base64');
    await page.getByRole('row', { name: /e2e\.operator/ }).waitFor();
    // the dashboard's own verifier accepts the browser-made hash for the right password only
    const verify = (pw) => execFileSync(python, ['-I', '-c', `import sys; sys.path[:0]=[${JSON.stringify(path.join(repo, 'dashboard'))}, ${JSON.stringify(path.join(repo, 'shared/python'))}]\nfrom exp_dashboard.auth import verify_password\nprint(verify_password(sys.argv[1], sys.argv[2]))`, pw, body.hash], { encoding: 'utf8' }).trim();
    assert.equal(verify(PW), 'True');
    assert.equal(verify(`${PW}!`), 'False');
    // nothing keeps the password: fields are cleared, storage is empty of it
    assert.equal(await page.getByLabel('Password', { exact: true }).inputValue(), '');
    const stored = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
    assert.ok(!stored.includes(PW));
    assert.deepEqual(leaked, [], 'no request ever contained the plaintext');
    const users = await getJson(`/dashboards/${dc.id}/users`);
    assert.ok(users.items.some((u) => u.username === 'e2e.operator' && u.role === 'operator'));
    assert.ok(!JSON.stringify(users).includes('pbkdf2'), 'the manager never returns hashes');
    // delete with a typed confirmation
    await page.getByRole('button', { name: 'Delete user e2e.operator' }).click();
    const dlg = page.locator('dialog[open]');
    const del = dlg.locator('button.btn-danger');
    assert.ok(await del.isDisabled());
    await dlg.locator('input').fill('e2e.operator');
    await del.click();
    await page.getByRole('row', { name: /e2e\.operator/ }).waitFor({ state: 'detached' });
    await page.context().close();
  });

  await test('NOC tokens: shown once with copy and NOC URL, never again; revoke asks first', async () => {
    const page = await newPage({ permissions: ['clipboard-read', 'clipboard-write'] });
    const { dh, dc } = await seededDashboard();
    await page.goto(`${BASE}/hosts/${dh.host_id}/components/${dc.component_id}?view=configure`);
    await page.getByLabel('Label', { exact: true }).fill('Hall B wall display');
    await page.getByLabel('Expires after (hours)').fill('24');
    await page.getByRole('button', { name: 'Create NOC token' }).click();
    const dlg = page.locator('dialog[open]');
    const token = await dlg.locator('code[aria-label="NOC token"]').innerText();
    const url = await dlg.locator('code[aria-label="NOC URL"]').innerText();
    assert.match(token, /^expn_[A-Za-z0-9_-]{20,}$/);
    assert.match(url, /^https:\/\/[^/#?]+\/noc#t=expn_[A-Za-z0-9_-]+$/);
    assert.equal(url, `${new URL(url).origin}/noc#t=${token}`);
    await dlg.getByRole('button', { name: 'Copy NOC URL' }).click();
    assert.equal(await clip(page), url);
    await dlg.getByRole('button', { name: 'Copy NOC token' }).click();
    assert.equal(await clip(page), token);
    await dlg.getByRole('button', { name: 'I have copied it' }).click();
    await page.getByRole('row', { name: /Hall B wall display/ }).waitFor();
    assert.ok(!(await page.content()).includes(token), 'the token is gone from the page after closing');
    await page.reload();
    await page.getByRole('row', { name: /Hall B wall display/ }).waitFor();
    assert.ok(!(await page.content()).includes(token), 'and never comes back');
    assert.ok(!JSON.stringify(await getJson(`/dashboards/${dc.id}/noc-tokens`)).includes(token), 'the API does not list it');
    assert.ok(!(await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]))).includes(token));
    // revoke
    await page.getByRole('button', { name: 'Revoke NOC token Hall B wall display' }).click();
    await page.locator('dialog[open]').getByRole('button', { name: 'Revoke token' }).click();
    await page.getByRole('row', { name: /Hall B wall display.*revoked/ }).waitFor();
    await page.context().close();
  });

  await test('Open dashboard: the SSO handoff form is POSTed to the dashboard, the token never in a URL', async () => {
    const page = await newPage();
    const { dh, dc } = await seededDashboard();
    const seen = [];
    await page.context().route('**/auth/sso', async (route) => {
      seen.push({ method: route.request().method(), url: route.request().url(), body: route.request().postData() });
      await route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>dashboard</title><p>signed in</p>' });
    });
    await page.goto(`${BASE}/dashboards`);
    const row = page.locator(`tr[data-dashboard="${dc.id}"]`);
    await row.getByRole('button', { name: /Open dashboard/ }).click();
    await page.waitForFunction(() => true);
    for (let i = 0; i < 50 && seen.length === 0; i += 1) await page.waitForTimeout(100);
    assert.equal(seen.length, 1, 'exactly one handoff');
    assert.equal(seen[0].method, 'POST');
    assert.match(seen[0].url, /^https:\/\/[^/?#]+\/auth\/sso$/, 'no query string, no fragment');
    assert.match(seen[0].body, /^token=eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const claims = JSON.parse(Buffer.from(seen[0].body.split('=')[1].split('.')[1], 'base64url').toString());
    assert.equal(claims.aud, dc.id);
    assert.equal(claims.exp - claims.iat, 120);
    assert.equal(claims.role, 'admin');
    assert.ok(fresh(await audit(), 'dashboard.sso'));
    // the same button on the component page
    await page.goto(`${BASE}/hosts/${dh.host_id}/components/${dc.component_id}`);
    await page.getByRole('button', { name: /Open dashboard/ }).waitFor();
    await page.context().close();
  });

  // ------------------------------------------------------------------------------------------------------------------
  const SECRET_URL = 'https://hooks.example.com/services/T0000/B0000/SECRETVALUE0123';
  await test('sites: create, edit, release and rollback, alert settings with a write-only webhook and a test, delete', async () => {
    const page = await newPage();
    await page.goto(`${BASE}/sites`);
    await page.getByRole('button', { name: 'Create site' }).click();
    const dlg = page.locator('dialog[open]');
    await dlg.getByLabel('Name', { exact: true }).fill('E2E Hall');
    assert.equal(await dlg.getByLabel('Slug').inputValue(), 'e2e-hall');
    await dlg.getByLabel('Time zone').fill('Mars/Olympus Mons');
    assert.ok(await dlg.getByRole('button', { name: 'Create site' }).isDisabled(), 'an invalid time zone blocks creating');
    await dlg.getByLabel('Time zone').fill('America/Chicago');
    await dlg.getByLabel('Edge label').fill('EC');
    await dlg.getByRole('button', { name: 'Create site' }).click();
    await page.waitForURL('**/sites/e2e-hall');
    await page.locator('h1:text-is("E2E Hall")').waitFor();
    assert.equal((await getJson('/sites/e2e-hall')).timezone, 'America/Chicago');
    // edit
    await page.getByRole('button', { name: 'Edit site' }).click();
    const ed = page.locator('dialog[open]');
    assert.ok(await ed.getByLabel('Slug').isDisabled(), 'the slug cannot change');
    await ed.getByLabel('Name', { exact: true }).fill('E2E Hall North');
    await ed.getByRole('button', { name: 'Save site' }).click();
    await page.locator('h1:text-is("E2E Hall North")').waitFor();
    // release: set, then roll back
    await page.getByRole('button', { name: 'Set release…' }).click();
    let rd = page.locator('dialog[open]');
    await rd.getByRole('combobox', { name: 'Release' }).selectOption('0.1.1');
    await rd.getByRole('button', { name: 'Set release', exact: true }).click();
    await page.locator('[data-testid="site-release"]').filter({ hasText: '0.1.1' }).waitFor();
    await page.getByRole('button', { name: 'Roll back…' }).click();
    rd = page.locator('dialog[open]');
    await rd.getByRole('combobox', { name: 'Roll back to' }).selectOption('0.1.0');
    await rd.getByRole('button', { name: 'Roll back', exact: true }).click();
    await page.locator('[data-testid="site-release"]').filter({ hasText: '0.1.0' }).waitFor();
    assert.equal((await getJson('/sites/e2e-hall')).release_version, '0.1.0');
    // alerts: a webhook URL is write-only
    const alerts = page.getByRole('form', { name: 'Alert settings' });
    await alerts.getByRole('button', { name: 'Add webhook' }).click();
    await alerts.getByLabel('Webhook URL').fill('http://insecure.example.com/x');
    assert.match(await alerts.locator('.field-error').first().innerText(), /https/);
    assert.ok(await alerts.getByRole('button', { name: 'Save alert settings' }).isDisabled());
    await alerts.getByLabel('Webhook URL').fill(SECRET_URL);
    await alerts.getByRole('button', { name: 'Save alert settings' }).click();
    await toast(page, /Alert settings saved/);
    const st = page.locator('[data-testid="secret-state"]');
    assert.match(await st.innerText(), /^set · updated /);
    assert.equal(await alerts.getByLabel('Webhook URL').inputValue(), '', 'a stored secret is never prefilled');
    assert.ok(!(await page.content()).includes('SECRETVALUE0123'), 'the URL is not in the page');
    assert.ok(!(await send('GET', '/sites/e2e-hall/alerts')).text.includes('SECRETVALUE0123'), 'nor in the API answer');
    assert.ok(!JSON.stringify(await audit(200)).includes('SECRETVALUE0123'), 'nor in the audit log');
    await alerts.getByRole('button', { name: 'Send test' }).click();
    await page.locator('[data-testid="alert-test-results"]').getByText('delivered').waitFor();
    // delete the empty site with the slug typed
    await page.getByRole('button', { name: 'Delete site' }).click();
    const del = page.locator('dialog[open]');
    assert.ok(await del.locator('button.btn-danger').isDisabled());
    await del.locator('input').fill('e2e-hall');
    await del.locator('button.btn-danger').click();
    await page.waitForURL('**/sites');
    assert.equal((await send('GET', '/sites/e2e-hall')).status, 404);
    assert.ok(fresh(await audit(), 'site.create') && fresh(await audit(), 'alerts.update') && fresh(await audit(), 'site.release'));
    await page.context().close();
  });

  await test('releases: imported versions, import by version, upload (bad hash refused, good accepted), canary, rollback', async () => {
    const page = await newPage();
    await page.goto(`${BASE}/releases`);
    const table = page.locator('[data-testid="release-table"]');
    await table.waitFor();
    assert.match(await table.innerText(), /0\.1\.1/);
    assert.ok(!/0\.2\.0/.test(await table.innerText()));
    // import by version
    await page.getByRole('textbox', { name: 'Version' }).fill('9.9.9');
    await page.getByRole('button', { name: 'Import from GitHub' }).click();
    assert.match(await page.locator('.form-error').first().innerText(), /not found in the releases repository/);
    await page.getByRole('textbox', { name: 'Version' }).fill('0.2.0');
    await page.getByRole('button', { name: 'Import from GitHub' }).click();
    await table.getByRole('row', { name: /0\.2\.0/ }).waitFor();
    await page.getByRole('textbox', { name: 'Version' }).fill('0.2.0');
    await page.getByRole('button', { name: 'Import from GitHub' }).click();
    assert.match(await page.locator('.form-error').first().innerText(), /already imported/);
    // upload: a manifest whose artifact does not match is refused and nothing is stored
    const art = Buffer.from('e2e artifact bytes');
    const manifest = (sha) => ({ schema: 'exp.manifest/1', version: '0.3.0', created: '2026-11-18T19:00:00.000Z', min_agent_version: '0.1.0', artifacts: [{ name: 'exp-agent-0.3.0-noarch.tar.gz', component: 'agent', arch: 'noarch', sha256: sha, size: art.length }] });
    const sig = randomBytes(64).toString('base64');
    const files = (m) => [{ sel: '#up-manifest', f: { name: 'manifest.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(m)) } }, { sel: '#up-sig', f: { name: 'manifest.sig', mimeType: 'text/plain', buffer: Buffer.from(sig) } },
      { sel: '#up-arts', f: { name: 'exp-agent-0.3.0-noarch.tar.gz', mimeType: 'application/gzip', buffer: art } }];
    for (const { sel, f } of files(manifest('0'.repeat(64)))) await page.setInputFiles(sel, f);
    await page.getByRole('button', { name: 'Upload and verify' }).click();
    assert.match(await page.locator('form[aria-label="Upload a release"] .form-error').innerText(), /does not match the hash in the signed manifest/);
    assert.ok(!(await table.innerText()).includes('0.3.0'), 'nothing was stored');
    for (const { sel, f } of files(manifest(createHash('sha256').update(art).digest('hex')))) await page.setInputFiles(sel, f);
    await page.getByRole('button', { name: 'Upload and verify' }).click();
    await table.getByRole('row', { name: /0\.3\.0.*upload/ }).waitFor();
    // per-site target with a canary
    const hc = (await hostsAll()).filter((h) => h.site === 'hall-c' && h.state === 'enrolled');
    await page.getByRole('button', { name: 'Set release for Hall C' }).click();
    const dlg = page.locator('dialog[open]');
    await dlg.getByRole('combobox', { name: 'Release' }).selectOption('0.2.0');
    await dlg.getByRole('combobox', { name: 'Canary host' }).selectOption(hc[0].host_id);
    await dlg.getByRole('button', { name: 'Start canary' }).click();
    const rowC = page.locator('tr[data-site="hall-c"]');
    await rowC.getByText(/pending|healthy waiting/).waitFor();
    assert.ok(await rowC.getByRole('button', { name: /Set release for/ }).isDisabled(), 'no second rollout while the canary runs');
    assert.ok(['pending', 'healthy_waiting'].includes((await getJson('/sites/hall-c')).canary_state));
    // roll hall-b back
    await page.getByRole('button', { name: 'Roll back Hall B' }).click();
    const rb = page.locator('dialog[open]');
    const cur = (await getJson('/sites/hall-b')).release_version;
    await rb.getByRole('combobox', { name: 'Roll back to' }).selectOption('0.1.0');
    await rb.getByRole('button', { name: 'Roll back', exact: true }).click();
    await page.locator('tr[data-site="hall-b"]').getByText('0.1.0').waitFor();
    assert.notEqual(cur, '0.1.0');
    assert.ok(fresh(await audit(), 'release.import') && fresh(await audit(), 'release.upload'));
    await page.context().close();
  });

  await test('audit: filters by actor, resource and time; secrets never appear', async () => {
    const page = await newPage();
    await page.goto(`${BASE}/audit`);
    await page.locator('[data-testid="audit-table"]').waitFor();
    const total = Number((await page.locator('[data-testid="audit-count"]').innerText()).split(' ')[0]);
    assert.ok(total > 10);
    await page.getByLabel('Actor').fill('owner@example.com');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await page.waitForFunction(() => location.search.includes('actor='));
    await page.waitForFunction((t) => Number(document.querySelector('[data-testid="audit-count"]')?.textContent?.split(' ')[0]) !== t, total);
    const actors = await page.locator('[data-testid="audit-table"] tbody tr td:nth-child(2)').allInnerTexts();
    assert.ok(actors.length > 0 && actors.every((a) => a === 'owner@example.com'));
    await page.getByLabel('Resource starts with').fill('site:e2e-hall');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await page.waitForFunction(() => location.search.includes('resource='));
    await page.locator('[data-testid="audit-table"] tbody tr').first().waitFor();
    assert.ok((await page.locator('[data-testid="audit-table"] tbody td:nth-child(4)').allInnerTexts()).every((r) => r === 'site:e2e-hall'));
    // a time window in the far future is empty
    await page.getByRole('button', { name: 'Clear' }).click();
    await page.getByLabel('From').fill('2099-01-01T00:00');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await page.getByText('No audit events match').waitFor();
    assert.ok(page.url().includes('from=2099-01-01T'));
    assert.ok(!(await page.content()).includes('SECRETVALUE0123'));
    await page.context().close();
  });

  await test('settings: org name, admins, drills switches, thresholds, write-only platform webhook', async () => {
    const page = await newPage();
    await page.goto(`${BASE}/settings`);
    const org = page.getByRole('form', { name: 'Organisation settings' });
    await org.getByLabel('Organisation name').waitFor();
    await org.getByLabel('Organisation name').fill('E2E Event NOC');
    await org.getByLabel('Drills enabled').check();
    await org.getByLabel('Two-person approval').uncheck();
    await org.getByRole('button', { name: 'Save settings' }).click();
    await toast(page, /Settings saved/);
    await page.locator('.org', { hasText: 'E2E Event NOC' }).waitFor();
    const s = await getJson('/settings');
    assert.equal(s.org_name, 'E2E Event NOC');
    assert.equal(s.drills_enabled, true);
    assert.equal(s.drills_two_person, false);
    // admins: invite by email and role
    const inv = page.getByRole('form', { name: 'Invite an admin' });
    await inv.getByLabel('Email address').fill('not-an-email');
    assert.ok(await inv.getByRole('button', { name: 'Invite' }).isDisabled());
    await inv.getByLabel('Email address').fill('New.Person@example.com');
    await inv.getByLabel('Role').selectOption('operator');
    await inv.getByRole('button', { name: 'Invite' }).click();
    const row = page.getByRole('row', { name: /new\.person@example\.com/ });
    await row.waitFor();
    assert.equal(await row.getByRole('combobox').inputValue(), 'operator');
    assert.ok((await getJson('/settings')).admins.some((a) => a.email === 'new.person@example.com' && a.role === 'operator'));
    await row.getByRole('button', { name: /Disable/ }).click();
    await row.getByText('disabled').waitFor();
    // thresholds
    const thr = page.getByRole('form', { name: 'Fleet thresholds' });
    await thr.getByLabel('Warn at (%)').fill('96');
    assert.match(await thr.locator('.field-error').first().innerText(), /not be below/);
    assert.ok(await thr.getByRole('button', { name: 'Save thresholds' }).isDisabled());
    await thr.getByLabel('Warn at (%)').fill('80');
    await thr.getByRole('button', { name: 'Save thresholds' }).click();
    await toast(page, /thresholds saved/);
    assert.equal((await getJson('/settings/fleet-thresholds')).disk_high.warn_pct, 80);
    // platform webhook: write-only
    const pw = page.getByRole('form', { name: 'Platform webhook' });
    await pw.getByLabel('Format').selectOption('teams');
    await pw.getByLabel('Webhook URL').fill(SECRET_URL);
    await pw.getByRole('button', { name: 'Save webhook' }).click();
    await toast(page, /Platform webhook saved/);
    assert.match(await pw.locator('[data-testid="secret-state"]').innerText(), /^set · updated /);
    assert.equal(await pw.getByLabel('Webhook URL').inputValue(), '');
    assert.ok(!(await page.content()).includes('SECRETVALUE0123'));
    assert.ok(!(await send('GET', '/settings/platform-webhook')).text.includes('SECRETVALUE0123'));
    await pw.getByRole('button', { name: 'Send test' }).click();
    await page.locator('[data-testid="pw-test"]').getByText('delivered').waitFor();
    await page.context().close();
  });

  await test('dashboards list, drills placeholder (no fake functionality)', async () => {
    const page = await newPage();
    await page.goto(`${BASE}/dashboards`);
    await page.locator('[data-testid="dashboards-table"]').waitFor();
    assert.ok(await page.locator('[data-testid="dashboards-table"] tbody tr').count() >= 1);
    await page.goto(`${BASE}/drills`);
    await page.getByRole('heading', { name: 'Drills arrive in M5' }).waitFor();
    assert.equal(await page.locator('main button').count(), 0, 'no buttons that could pretend to start a drill');
    assert.equal(await page.locator('main form, main input, main select').count(), 0);
    await page.context().close();
  });

  await test('roles: a viewer sees read-only screens and the API refuses a viewer mutation', async () => {
    const page = await newPage();
    await page.route('**/api/admin/v1/**', (route) => route.continue({ headers: { ...route.request().headers(), 'x-mock-role': 'viewer' } }));
    await page.goto(`${BASE}/settings`);
    await page.getByLabel('Organisation name').waitFor();
    await page.waitForSelector('.banner:has-text("Only the owner")');
    assert.ok(await page.getByLabel('Organisation name').isDisabled());
    await page.goto(`${BASE}/sites`);
    await page.getByRole('button', { name: 'Create site' }).waitFor();
    assert.ok(await page.getByRole('button', { name: 'Create site' }).isDisabled());
    await page.goto(`${BASE}/hosts`);
    await page.waitForSelector('tr.host-row');
    assert.equal(await page.getByRole('link', { name: 'Add host' }).count(), 0);
    await page.goto(`${BASE}/releases`);
    await page.getByRole('textbox', { name: 'Version' }).waitFor();
    assert.ok(await page.getByRole('button', { name: 'Import from GitHub' }).isDisabled());
    await page.goto(`${BASE}/audit`);
    await page.getByText('visible to admins and owners').waitFor();
    const r = await send('POST', '/sites', { site: 'viewer-try', name: 'x', timezone: 'UTC' }, { 'x-mock-role': 'viewer' });
    assert.equal(r.status, 403);
    assert.equal(r.body.error.code, 'insufficient_role');
    await page.context().close();
  });
}
