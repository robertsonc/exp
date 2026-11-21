// Browser scenarios for the speedtest analytics views (Playwright + Chromium, global). Same protocol as scenarios.js:
// the pytest driver owns the world; "@@NEED" lines are answered with "@@OK" lines.
"use strict";
const fs = require("fs");
const path = require("path");
const readline = require("readline");
const assert = require("assert");
const { chromium } = require("playwright");

const [scenario, cfgPath] = process.argv.slice(2);
const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const rl = readline.createInterface({ input: process.stdin });
const waiters = [];
rl.on("line", (l) => { const w = waiters.shift(); if (w) w(l); });
function need(op, args) {
  console.log("@@NEED " + JSON.stringify({ op, ...(args || {}) }));
  return new Promise((res) => waiters.push(res)).then((l) => JSON.parse(l.replace(/^@@OK /, "")));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log("[ui]", ...a);

// role: "viewer" (password login), "admin" (SSO handoff token), "noc"
async function open(role, viewport) {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: viewport || { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  const seen = { dialogs: [], csp: [], errors: [], requests: [] };
  page.on("dialog", async (d) => { seen.dialogs.push(d.message()); await d.dismiss(); });
  page.on("console", (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) seen.csp.push(m.text()); });
  page.on("pageerror", (e) => seen.errors.push(String(e)));
  page.on("request", (r) => seen.requests.push(r.url()));
  const hdr = { Origin: cfg.base };
  let r;
  if (role === "admin") r = await ctx.request.post(cfg.base + "/auth/sso", { data: { token: cfg.sso_tokens.shift() }, headers: hdr });
  else r = await ctx.request.post(cfg.base + "/auth/login", { data: { username: "vera", password: cfg.passwords.vera }, headers: hdr });
  assert.strictEqual(r.status(), 200, "login as " + role);
  return { browser, ctx, page, seen };
}
const shot = async (page, name) => { fs.mkdirSync(cfg.out, { recursive: true }); await page.screenshot({ path: path.join(cfg.out, name + ".png"), fullPage: true }); };
const clean = (seen) => {
  assert.deepStrictEqual(seen.dialogs, [], "no dialog may fire");
  assert.deepStrictEqual(seen.csp, [], "CSP must not be violated");
  assert.deepStrictEqual(seen.errors, [], "no page errors");
  assert.ok(seen.requests.every((u) => u.startsWith(cfg.base)), "no request leaves the dashboard: " + seen.requests.filter((u) => !u.startsWith(cfg.base)).join(","));
};
const noHScroll = async (page, name) => {
  const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, bw: document.body.scrollWidth, iw: window.innerWidth }));
  assert.ok(m.sw <= m.iw && m.bw <= m.iw, name + " scrolls horizontally: " + JSON.stringify(m));
};
const S = {};

S.overview = async () => {
  const { browser, page, seen } = await open("viewer");
  await page.goto(cfg.base + "/speedtests?static=1");
  await page.waitForSelector("#st-dist .bar-row");
  await page.waitForSelector("#st-zones .zone-tile");
  await page.waitForSelector("#st-vs .dot");
  await page.waitForSelector("#st-list .tests-table tbody tr");
  assert.ok((await page.locator("#st-causes .bar-row").count()) >= 3, "top causes");
  assert.ok((await page.locator(".stats .stat").count()) === 4);
  assert.ok((await page.locator(".legs-table tbody tr").count()) === 2, "local and internet legs");
  assert.ok(await page.locator("svg.hours rect").count() >= 3, "tests per hour bars");
  assert.ok((await page.locator("#st-vs-summary").textContent()).includes("Median user score"));
  // zones coloured by p50 score: state attribute + icon + word, never colour alone
  const z = await page.locator(".zone-tile").first().evaluate((n) => ({ state: n.dataset.state, txt: n.textContent, ico: !!n.querySelector(".ico") }));
  assert.ok(["ok", "warn", "fail"].includes(z.state) && z.ico && /Good|Fair|Poor/.test(z.txt));
  // XSS: the hostile AP / SSID shows up as text, nothing is injected
  const txt = await page.locator("#st-list").textContent();
  assert.ok(txt.includes(cfg.xss), "hostile AP name shown as text");
  assert.strictEqual(await page.locator("img[src='x'], [onerror]").count(), 0);
  // viewer: no raw identifiers anywhere on the page
  const all = await page.locator("body").textContent();
  for (const raw of cfg.raw) assert.ok(!all.includes(raw), "viewer sees raw identifier " + raw);
  // partial results flag is hidden while every collector answers
  assert.strictEqual(await page.locator(".banner-partial:not([hidden])").count(), 0);
  // filters
  await page.selectOption("#f-zone", "lobby");
  const zones = await page.locator("#st-list tbody tr td:nth-child(3)").allTextContents();
  assert.ok(zones.length > 0 && zones.every((t) => t === "lobby"));
  await page.selectOption("#f-zone", "");
  // range
  await page.selectOption("#st-range", "1h");
  await sleep(700);
  await shot(page, "overview-dark-desktop");
  await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
  await page.selectOption("#st-range", "24h");
  await sleep(700);
  await shot(page, "overview-light-desktop");
  clean(seen);
  await browser.close();
};

S.breakdowns = async () => {
  const { browser, page, seen } = await open("viewer");
  await page.goto(cfg.base + "/speedtests/breakdowns?min=2");
  await page.waitForSelector("#st-breakdown .bar-row");
  await page.waitForSelector("#st-worst tbody tr");
  const worst = await page.locator("#st-worst tbody tr").evaluateAll((rows) => rows.map((r) => ({ ap: r.dataset.ap, n: Number(r.lastElementChild.textContent.split(" ")[0]) })));
  assert.ok(worst.length >= 1 && worst.length <= 10);
  assert.ok(worst.every((w) => w.n >= 2), "AP ranking honours the minimum test count");
  await page.selectOption("#b-min", "20");
  await sleep(200);
  assert.ok((await page.locator("#st-worst tbody tr").count()) === 0 || (await page.locator("#st-worst .empty").count()) === 0);
  for (const g of ["ap", "ssid", "band", "os_family", "hour"]) {
    await page.selectOption("#b-group", g);
    await page.waitForFunction((gg) => document.querySelector("#st-breakdown h2").textContent.toLowerCase().includes(gg.replace("_", " ")) || gg === "hour", g);
    await page.waitForSelector("#st-breakdown .bar-row");
  }
  await page.selectOption("#b-group", "zone");
  await page.selectOption("#b-metric", "down_p50");
  await sleep(500);
  await shot(page, "breakdowns-dark-desktop");
  assert.strictEqual(await page.locator("img[src='x']").count(), 0);
  clean(seen);
  await browser.close();
};

async function detailChecks(page, admin) {
  await page.waitForSelector("#st-legs .leg-card");
  assert.strictEqual(await page.locator(".leg-card").count(), 2, "two legs side by side");
  const boxes = await page.locator(".leg-card").evaluateAll((n) => n.map((x) => x.getBoundingClientRect()));
  assert.ok(Math.abs(boxes[0].top - boxes[1].top) < 4, "legs are side by side");
  assert.ok((await page.locator("#st-score .bar-row").count()) >= 3, "score parts");
  assert.ok((await page.locator("#st-diagnosis .cause").count()) === 1);
  assert.ok((await page.locator("#st-diagnosis .cite").count()) >= 1, "cited evidence");
  assert.ok((await page.locator("#st-timeline .lane").count()) >= 7, "timeline lanes");
  assert.strictEqual(await page.locator("#st-evidence .ev-card").count(), 8, "one card per evidence kind");
  await page.waitForFunction(() => document.querySelector(".lane[data-lane='Probe beats'] svg rect.beat"), null, { timeout: 8000 }).catch(() => log("no probe beats drawn (probe has no data for this window)"));
  const lanes = await page.locator(".lane-label strong").allTextContents();
  for (const want of ["Wi-Fi events", "Wi-Fi signal", "AP utilization", "Top flows", "WAN utilization", "Security hits", "Probe beats"]) assert.ok(lanes.includes(want), "lane " + want);
  assert.ok((await page.locator("#ev-flows tbody tr").count()) >= 1);
  assert.ok((await page.locator("#ev-security tbody tr").count()) >= 1);
  const body = await page.locator("body").textContent();
  for (const raw of cfg.raw) {
    if (admin) continue;
    assert.ok(!body.includes(raw), "non-admin sees raw identifier " + raw);
  }
  if (admin) {
    const dev = await page.locator("#st-device").textContent();
    assert.ok(dev.includes(cfg.raw[0]) && dev.includes(cfg.raw[1]) && dev.includes(cfg.raw[3]), "admin sees device metadata");
    assert.ok((await page.locator("#st-purge button").count()) >= 2);
  } else {
    assert.strictEqual(await page.locator("#st-purge").count(), 0, "no purge for a viewer");
    assert.ok((await page.locator("#st-ident-note").textContent()).includes("admins only"));
  }
}

S.detail = async () => {
  const v = await open("viewer");
  await v.page.goto(cfg.base + "/speedtests/test/" + cfg.ids.normal);
  await detailChecks(v.page, false);
  await shot(v.page, "detail-viewer-dark-desktop");
  clean(v.seen);
  await v.browser.close();
  const a = await open("admin");
  await a.page.goto(cfg.base + "/speedtests/test/" + cfg.ids.normal);
  await detailChecks(a.page, true);
  await shot(a.page, "detail-admin-dark-desktop");
  await a.page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
  await shot(a.page, "detail-admin-light-desktop");
  clean(a.seen);
  await a.browser.close();
};

S.xss = async () => {
  for (const role of ["viewer", "admin"]) {
    const { browser, page, seen } = await open(role);
    await page.goto(cfg.base + "/speedtests/test/" + cfg.ids.hostile);
    await page.waitForSelector("#st-comment-text");
    assert.strictEqual(await page.locator("#st-comment-text").textContent(), "slow " + cfg.xss);
    assert.ok((await page.locator("#st-diagnosis").textContent()).includes(cfg.xss), "AP name in the NOC text is text");
    assert.ok((await page.locator("#ev-wifi").textContent()).includes(cfg.xss));
    if (role === "admin") assert.ok((await page.locator("#st-device").textContent()).includes(cfg.xss_host), "hostile hostname as text");
    assert.strictEqual(await page.locator("svg[onload]").count(), 0);
    await sleep(400);
    assert.strictEqual(await page.locator("img[src='x']").count(), 0);
    assert.strictEqual(await page.locator("[onerror]").count(), 0);
    await shot(page, "detail-xss-" + role);
    clean(seen);
    await browser.close();
  }
};

S.support = async () => {
  const { browser, page, seen } = await open("viewer");
  await page.goto(cfg.base + "/speedtests/support");
  await page.waitForSelector("#support-input");
  // garbage: a clear message, no navigation
  await page.fill("#support-input", "https://box.example/st/r/not-an-id#k=abc");
  await page.click(".support-form button[type=submit]");
  assert.ok((await page.locator("#support-error").textContent()).includes("test id"));
  // a pasted share link lands on the detail with full evidence; the key never reaches the URL or the server
  await page.fill("#support-input", "http://10.0.0.9/st/r/" + cfg.ids.normal + "#k=SECRETKEY123");
  await page.click(".support-form button[type=submit]");
  await page.waitForURL((u) => u.pathname === "/speedtests/test/" + cfg.ids.normal);
  await page.waitForSelector("#st-evidence .ev-card");
  assert.strictEqual(await page.evaluate(() => location.hash), "");
  assert.ok(!seen.requests.some((u) => u.includes("SECRETKEY123")), "the #k key was sent somewhere");
  // opening the share path on the dashboard host works too
  await page.goto(cfg.base + "/st/r/" + cfg.ids.normal + "#k=SECRETKEY456");
  await page.waitForURL((u) => u.pathname === "/speedtests/test/" + cfg.ids.normal);
  await page.waitForSelector("#st-legs");
  assert.strictEqual(await page.evaluate(() => location.hash), "");
  assert.ok(!seen.requests.some((u) => u.includes("SECRETKEY456")));
  // a bare id
  await page.goto(cfg.base + "/speedtests/support");
  await page.fill("#support-input", cfg.ids.hostile);
  await page.press("#support-input", "Enter");
  await page.waitForURL((u) => u.pathname === "/speedtests/test/" + cfg.ids.hostile);
  // an unknown id: a plain explanation
  await page.goto(cfg.base + "/speedtests/test/st_00000000000000000000009999");
  await page.waitForSelector(".banner-error:not([hidden])");
  assert.ok((await page.locator(".banner-error").textContent()).includes("No test with this id"));
  // viewer: no admin tools on the support page
  await page.goto(cfg.base + "/speedtests/support");
  await page.waitForSelector("#support-admin-note");
  assert.strictEqual(await page.locator("#st-purge-form").count(), 0);
  await page.goto(cfg.base + "/speedtests/support");
  await shot(page, "support-dark-desktop");
  clean(seen);
  await browser.close();
};

S.purge = async () => {
  const { browser, page, seen } = await open("admin");
  // from the detail page: dry run, cancel (nothing deleted), dry run again, confirm
  await page.goto(cfg.base + "/speedtests/test/" + cfg.ids.normal);
  await page.waitForSelector("#st-purge button[data-by='test']");
  await page.click("#st-purge button[data-by='test']");
  await page.waitForSelector("#purge-confirm", { timeout: 5000 }).catch(async () => { throw new Error("no confirm: msg=" + (await page.locator(".purge-msg").textContent()) + " errors=" + seen.errors.join("|")); });
  assert.ok((await page.locator(".purge-warn").textContent()).includes("1 test(s)"));
  await shot(page, "purge-confirm-dark-desktop");
  await page.click(".purge-msg button:has-text('Cancel')");
  assert.strictEqual(await page.locator("#purge-confirm").count(), 0);
  assert.strictEqual((await need("exists", { id: cfg.ids.normal })).exists, true, "cancel must not delete");
  await page.click("#st-purge button[data-by='test']");
  await page.waitForSelector("#purge-confirm");
  await page.click("#purge-confirm");
  await page.waitForURL((u) => u.pathname === "/speedtests");
  assert.strictEqual((await need("exists", { id: cfg.ids.normal })).exists, false, "end state: the test is gone");
  // from the support page: by device key (every test of the device on every collector)
  await page.goto(cfg.base + "/speedtests/support");
  await page.waitForSelector("#st-purge-form");
  await page.selectOption("#purge-kind", "device_key");
  await page.fill("#purge-value", cfg.device_key);
  await page.click("#st-purge-form > button");
  await page.waitForSelector("#purge-confirm");
  const warn = await page.locator(".purge-warn").textContent();
  assert.ok(/\d+ test\(s\)/.test(warn));
  await page.click("#purge-confirm");
  await page.waitForSelector(".purge-done");
  assert.strictEqual((await need("count")).count, 0, "end state: no test of the device remains");
  clean(seen);
  await browser.close();
};

S.noc = async () => {
  // a NOC wall token is a viewer: same gating
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  const r = await ctx.request.post(cfg.base + "/auth/noc", { data: { token: cfg.noc_token }, headers: { Origin: cfg.base } });
  assert.strictEqual(r.status(), 200);
  await page.goto(cfg.base + "/speedtests/test/" + cfg.ids.normal);
  await page.waitForSelector("#st-legs");
  assert.strictEqual(await page.locator("#st-purge").count(), 0);
  const body = await page.locator("body").textContent();
  for (const raw of cfg.raw) assert.ok(!body.includes(raw));
  await browser.close();
};

S.partial = async () => {
  const { browser, page, seen } = await open("viewer");
  await page.goto(cfg.base + "/speedtests?static=1");
  await page.waitForSelector("#st-list tbody tr");
  await need("stop_collector", { collector: "col-b" });
  await page.click("button:has-text('Refresh')");
  await page.waitForSelector(".banner-partial:not([hidden])");
  const t = await page.locator(".banner-partial").textContent();
  assert.ok(t.includes("Partial results") && /Hall B/i.test(t) && t.includes("unreachable"), t);
  assert.ok((await page.locator("#st-list tbody tr").count()) > 0, "the other collectors still answer");
  await shot(page, "overview-partial-dark-desktop");
  clean(seen);
  await browser.close();
};

S.mobile = async () => {
  const vp = { width: 390, height: 844 };
  const a = await open("admin", vp);
  const page = a.page;
  for (const [name, url, sel] of [["overview", "/speedtests?static=1", "#st-list tbody tr"], ["breakdowns", "/speedtests/breakdowns", "#st-worst"],
    ["detail", "/speedtests/test/" + cfg.ids.normal, "#st-evidence .ev-card"], ["detail-xss", "/speedtests/test/" + cfg.ids.hostile, "#st-comment-text"], ["support", "/speedtests/support", "#st-purge-form"]]) {
    await page.goto(cfg.base + url);
    await page.waitForSelector(sel);
    await sleep(700);
    await noHScroll(page, name);
    await shot(page, name + "-dark-390");
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
    await noHScroll(page, name + "-light");
    await shot(page, name + "-light-390");
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
  }
  clean(a.seen);
  await a.browser.close();
};

(async () => {
  if (!S[scenario]) { console.error("unknown scenario " + scenario); process.exit(2); }
  const watchdog = setTimeout(() => { console.error("scenario timed out"); process.exit(3); }, cfg.timeout_ms || 90000);
  try {
    await S[scenario]();
    console.log("@@PASS " + scenario);
    clearTimeout(watchdog);
    rl.close();
    process.exit(0);
  } catch (e) {
    console.error("@@FAIL " + scenario + ": " + (e && e.stack || e));
    process.exit(1);
  }
})();
