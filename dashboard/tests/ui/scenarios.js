// Browser scenarios for the dashboard SPA (Playwright + Chromium, pre-installed globally).
// Usage: node scenarios.js <scenario> <config.json>
// The pytest driver (tests/test_ui_browser.py) owns the world (fake collectors + dashboard) and answers
// "@@NEED {json}" lines on stdout with "@@OK {json}" on stdin (ingest an event, stop a collector, ...).
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

async function open(opts) {
  const o = opts || {};
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: o.viewport || { width: 1280, height: 900 }, reducedMotion: o.reducedMotion || "no-preference" });
  const page = await ctx.newPage();
  const seen = { dialogs: [], csp: [], errors: [], requests: [] };
  page.on("dialog", async (d) => { seen.dialogs.push(d.message()); await d.dismiss(); });
  page.on("console", (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) seen.csp.push(m.text()); });
  page.on("pageerror", (e) => seen.errors.push(String(e)));
  page.on("request", (r) => seen.requests.push(r.url()));
  if (o.user) {
    const r = await ctx.request.post(cfg.base + "/auth/login", { data: { username: o.user, password: cfg.passwords[o.user] }, headers: { Origin: cfg.base } });
    assert.strictEqual(r.status(), 200, "login as " + o.user);
  }
  return { browser, ctx, page, seen };
}

const stateOfDom = (page) => page.evaluate(() => ({
  headline: document.querySelector("#headline").textContent,
  sub: document.querySelector("#sub").textContent,
  lines: [...document.querySelectorAll(".board .line")].map((n) => ({ key: n.dataset.line, state: n.dataset.state, word: n.dataset.word, since: n.dataset.since || null,
    detail: (n.querySelector(".line-detail") || { textContent: "" }).textContent })),
}));

const apiJson = (page, p) => page.evaluate(async (u) => (await fetch(u, { credentials: "same-origin" })).json(), p);

async function settle(page, ms) { await page.waitForLoadState("domcontentloaded"); await sleep(ms || 300); }

const S = {};

// SR-13 / spec 7.4: attacker-controlled text renders as text; no dialog, no injected element, CSP intact.
S.xss = async () => {
  const { browser, page, seen } = await open({ user: "alice" });
  const evil = cfg.xss;
  await page.goto(cfg.base + "/");
  await page.waitForSelector(".row[data-probe='probe-g1']");
  assert.strictEqual(await page.locator(".row[data-probe='probe-g1'] .row-name").textContent(), evil);
  await page.goto(cfg.base + "/probe/probe-g1");
  await page.waitForSelector(".board .line");
  await sleep(600);
  assert.strictEqual(await page.locator(".probe-title").textContent(), evil);
  assert.ok((await page.locator("#sub").textContent()).includes(evil));
  assert.ok((await page.locator(".line-detail").first().textContent()).includes(evil));
  assert.ok((await page.locator(".failing .what").first().textContent()).includes(evil));
  await page.goto(cfg.base + "/incidents");
  await page.waitForSelector(".incident");
  assert.ok((await page.locator(".inc-facts").allTextContents()).some((t) => t.includes(evil)), "incident fact shown as text");
  for (const u of ["/", "/probe/probe-g1", "/incidents"]) {
    await page.goto(cfg.base + u);
    await sleep(500);
    assert.strictEqual(await page.locator("img[src='x']").count(), 0, "no injected <img> on " + u);
    assert.strictEqual(await page.locator("[onerror]").count(), 0);
  }
  assert.deepStrictEqual(seen.dialogs, [], "no dialog may fire");
  assert.deepStrictEqual(seen.csp, [], "CSP must not be violated by the SPA");
  assert.deepStrictEqual(seen.errors, [], "no page errors");
  await browser.close();
};

// spec 7.6: ?at=T shows exactly the collector's state?at=T, pauses live updates, and can go back to live.
S.rewind = async () => {
  const { browser, page, seen } = await open({ user: "alice" });
  const T = new Date(cfg.t_mid).toISOString();
  await page.goto(cfg.base + "/probe/probe-a1?at=" + encodeURIComponent(T));
  await page.waitForSelector(".board[data-mode='rewind'] .line");
  await page.waitForFunction(() => document.querySelector("#headline").textContent.length > 3 && !/Connecting/.test(document.querySelector("#headline").textContent));
  await sleep(500);
  let want = await apiJson(page, "/api/v1/state?probe=probe-a1&at=" + encodeURIComponent(T) + "&voice=" + (cfg.voice || "sysadmin"));
  let got = await stateOfDom(page);
  assert.strictEqual(got.headline, want.verdict.headline);
  assert.strictEqual(got.sub, want.verdict.sub);
  assert.deepStrictEqual(got.lines.map((l) => [l.key, l.state, l.word, l.since]), want.lines.map((l) => [l.key, l.state, l.word, l.since]));
  assert.deepStrictEqual(got.lines.map((l) => l.detail), want.lines.map((l) => l.detail || ""));
  const dns = got.lines.find((l) => l.key === "dns");
  assert.strictEqual(dns.state, "fail", "at T the DNS line was failing");
  assert.ok(await page.locator(".banner-rewind").isVisible(), "rewind banner");
  assert.ok(await page.getByRole("button", { name: "Back to live" }).first().isVisible());
  assert.strictEqual(await page.locator(".board").getAttribute("data-stale"), "false", "a rewound board is never 'stale'");
  assert.ok((await page.locator(".line[data-line='dns'] .beat.fail").count()) > 0, "failing beats drawn in the window");
  assert.ok((await page.locator(".line[data-line='dns'] .playhead").count()) === 1, "playhead drawn");
  // live updates are paused: the feeder keeps beating but the picture must not move
  const before = JSON.stringify(await stateOfDom(page));
  const beatsBefore = await page.locator(".line[data-line='network'] .beat").count();
  await sleep(4000);
  assert.strictEqual(JSON.stringify(await stateOfDom(page)), before);
  assert.strictEqual(await page.locator(".line[data-line='network'] .beat").count(), beatsBefore);
  // keyboard: Left steps back 10 s and the board follows the collector
  await page.locator(".scrub").focus();
  await page.keyboard.press("ArrowLeft");
  await page.waitForFunction((t) => new URL(location.href).searchParams.get("at") !== t, T);
  await sleep(700);
  const T2 = new URL(page.url()).searchParams.get("at");
  assert.strictEqual(Date.parse(T) - Date.parse(T2), 10000);
  want = await apiJson(page, "/api/v1/state?probe=probe-a1&at=" + encodeURIComponent(T2) + "&voice=" + (cfg.voice || "sysadmin"));
  got = await stateOfDom(page);
  assert.strictEqual(got.headline, want.verdict.headline);
  assert.deepStrictEqual(got.lines.map((l) => [l.key, l.state]), want.lines.map((l) => [l.key, l.state]));
  // clicking a beat in the strip rewinds there; Escape goes back to live
  const box = await page.locator(".line[data-line='network'] svg.strip").boundingBox();
  await page.mouse.click(box.x + box.width * 0.5, box.y + box.height / 2);
  await sleep(600);
  assert.ok(new URL(page.url()).searchParams.get("at"));
  await page.keyboard.press("Escape");
  await page.waitForSelector(".board[data-mode='live']");
  assert.strictEqual(new URL(page.url()).searchParams.get("at"), null);
  await sleep(800);
  const live = await apiJson(page, "/api/v1/state?probe=probe-a1&voice=" + (cfg.voice || "sysadmin"));
  assert.strictEqual((await stateOfDom(page)).lines.find((l) => l.key === "dns").state, live.lines.find((l) => l.key === "dns").state);
  assert.strictEqual(await page.locator(".banner-rewind").isVisible(), false);
  // the browser Back button returns to the rewound view
  await page.goBack();
  await page.waitForSelector(".board[data-mode='rewind']");
  assert.deepStrictEqual(seen.errors, []);
  await browser.close();
};

// SSE: a collector event reaches the board within 2 s; the strip gains the failing beat.
S.live = async () => {
  const { browser, page, seen } = await open({ user: "vera" });
  await page.goto(cfg.base + "/probe/probe-a1");
  await page.waitForSelector(".line[data-line='dns'][data-state='ok']");
  await sleep(1500);
  assert.strictEqual(await page.locator(".board").getAttribute("data-stale"), "false");
  assert.ok(/As of \d\d:\d\d:\d\d/.test(await page.locator(".asof").textContent()), "as-of freshness shown");
  const failBefore = await page.locator(".line[data-line='dns'] .beat.fail").count();
  await need("inject_fail", { probe: "probe-a1", line: "dns" });
  const t0 = Date.now();
  await page.waitForSelector(".line[data-line='dns'][data-state='fail']", { timeout: 2000 });
  const dt = Date.now() - t0;
  log("state flipped in", dt, "ms");
  assert.ok(dt < 2000);
  assert.ok((await page.locator(".board").getAttribute("data-sev")) !== "ok");
  await page.waitForFunction((n) => document.querySelectorAll(".line[data-line='dns'] .beat.fail").length > n, failBefore, { timeout: 2000 });
  await need("clear_fail", { probe: "probe-a1", line: "dns" });
  await page.waitForSelector(".line[data-line='dns'][data-state='ok']", { timeout: 4000 });
  // viewer: no acknowledge buttons anywhere
  assert.strictEqual(await page.locator("button.ack").count(), 0);
  assert.deepStrictEqual(seen.dialogs, []);
  await browser.close();
};

// A silent probe is never shown as current: loud banner, headline overridden, overview marks it stale.
S.stale = async () => {
  const { browser, page } = await open({ user: "vera" });
  await page.goto(cfg.base + "/probe/probe-b1");
  await page.waitForSelector(".banner-stale:not([hidden])");
  assert.ok((await page.locator(".banner-stale").textContent()).includes("Nothing on this screen is current"));
  assert.strictEqual(await page.locator("#headline").textContent(), "Nothing on this screen is current.");
  assert.strictEqual(await page.locator(".board").getAttribute("data-stale"), "true");
  assert.strictEqual(await page.locator(".board").getAttribute("data-sev"), "unknown");
  assert.ok(await page.locator(".line").first().evaluate((n) => getComputedStyle(n).opacity < 1), "stale lines are dimmed");
  await page.goto(cfg.base + "/");
  await page.waitForSelector(".row[data-probe='probe-b1']");
  assert.strictEqual(await page.locator(".row[data-probe='probe-b1']").getAttribute("data-live"), "false");
  assert.ok((await page.locator(".row[data-probe='probe-b1'] .fresh").textContent()).startsWith("stale"));
  assert.strictEqual(await page.locator(".row[data-probe='probe-c1']").getAttribute("data-live"), "true");
  // a live probe turns stale when its feed stops
  await page.goto(cfg.base + "/probe/probe-c1");
  await page.waitForSelector(".line[data-state='ok']");
  assert.strictEqual(await page.locator(".board").getAttribute("data-stale"), "false");
  await need("stop_feed", {});
  await page.waitForSelector(".banner-stale:not([hidden])", { timeout: 45000 });
  assert.strictEqual(await page.locator("#headline").textContent(), "Nothing on this screen is current.");
  await need("start_feed", {});
  await page.waitForSelector(".banner-stale", { state: "hidden", timeout: 15000 });
  assert.notStrictEqual(await page.locator("#headline").textContent(), "Nothing on this screen is current.");
  await browser.close();
};

// Federation: overview grouped by site, partial results when a collector is down, boards of the others still work.
S.overview = async () => {
  const { browser, page } = await open({ user: "vera" });
  await page.goto(cfg.base + "/");
  await page.waitForSelector(".row[data-probe='probe-c1']");
  const sites = await page.locator(".site").evaluateAll((n) => n.map((x) => x.dataset.site));
  assert.deepStrictEqual([...sites].sort(), ["hall-a", "hall-b", "hall-c"]);
  assert.ok(/\d+ of \d+ probes? need a look/.test(await page.locator("#headline").textContent()), await page.locator("#headline").textContent());
  assert.strictEqual(await page.locator(".banner-partial").isVisible(), false);
  assert.ok((await page.locator(".row[data-probe='probe-a1'] .chip").count()) >= 4);
  await need("stop_collector", { collector: "col-b" });
  await page.waitForSelector(".banner-partial:not([hidden])", { timeout: 20000 });
  await page.waitForFunction(() => document.querySelector(".banner-partial").textContent.includes("Hall B collector unreachable"), null, { timeout: 20000 });
  await page.waitForFunction(() => document.querySelectorAll(".row[data-probe='probe-b1']").length === 0, null, { timeout: 15000 });
  await page.waitForFunction(() => document.querySelector(".banner-partial").textContent.includes("Hall B collector unreachable"), null, { timeout: 20000 });
  await page.click(".row[data-probe='probe-a1']");
  await page.waitForSelector(".board .line");
  assert.strictEqual(new URL(page.url()).pathname, "/probe/probe-a1");
  await page.waitForFunction(() => document.querySelector(".probe-title").textContent === "Registration desk");
  await browser.close();
};

// The site lines board (CR-site-lines-board): reached from the overview, renders the collector's exp.lines/1 only,
// the finding card and its pattern strip, the ribbon pins a moment and goes back to live, no horizontal scroll at 390 px.
S.lines = async () => {
  const { browser, page } = await open({ user: "vera" });
  await page.goto(cfg.base + "/");
  await page.waitForSelector(".site[data-site='hall-b'] .site-lines");
  await page.click(".site[data-site='hall-b'] .site-lines");
  await page.waitForFunction(() => location.pathname === "/site/hall-b/lines");
  await page.waitForFunction(() => document.querySelector(".lines-h1").textContent.includes("Same failure, 2 networks"), null, { timeout: 20000 });
  assert.strictEqual(await page.locator(".lines").getAttribute("data-phase"), "down");
  assert.strictEqual((await page.locator(".lines-chip").textContent()).trim(), "INVESTIGATING");
  assert.ok((await page.locator(".lines-sub").textContent()).includes("it is the resolver"), "by-IP evidence reaches the words");
  const card = page.locator(".lines-card").first();
  assert.ok((await card.locator("h3").textContent()).startsWith("Stopped at DNS"));
  assert.strictEqual(await card.locator(".lines-sig li[data-state='stopped']").textContent(), "DNS");
  assert.ok((await card.locator(".lines-ev").first().textContent()).includes("Names fail, the path is fine."));
  assert.ok(await page.locator("canvas.lines-map").isVisible() && await page.locator("canvas.lines-ribbon").isVisible());
  // the ribbon pins a moment (history mode) and "Back to live" returns
  const box = await page.locator("canvas.lines-ribbon").boundingBox();
  await page.mouse.click(box.x + box.width * 0.5, box.y + 12);
  await page.waitForSelector(".lines-pinned:not([hidden])");
  assert.strictEqual(await page.locator(".lines").getAttribute("data-mode"), "history");
  await page.click(".lines-pinned button");
  await page.waitForFunction(() => document.querySelector(".lines").dataset.mode === "live");
  await page.setViewportSize({ width: 1440, height: 1000 });
  await sleep(500);
  await page.screenshot({ path: cfg.out + "/lines-desktop.png", fullPage: true });
  await page.emulateMedia({ colorScheme: "dark" });
  await sleep(300);
  await page.screenshot({ path: cfg.out + "/lines-desktop-dark.png", fullPage: true });
  await page.emulateMedia({ colorScheme: "light" });
  // phone width: nothing scrolls sideways
  await page.setViewportSize({ width: 390, height: 844 });
  await sleep(300);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "no horizontal scroll at 390 px");
  await browser.close();
};

S.incidents = async () => {
  // viewer: list, filters, link to the board at the incident time; no acknowledge buttons
  let ctxs = await open({ user: "vera" });
  let page = ctxs.page;
  await page.goto(cfg.base + "/incidents");
  await page.waitForSelector(".incident");
  assert.strictEqual(await page.locator("button.ack").count(), 0, "viewer sees no ack buttons");
  assert.ok((await page.locator(".incident[data-open='true']").count()) >= 1);
  assert.strictEqual(await page.locator(".incident[data-open='false']").count(), 0, "default filter is Open");
  await page.selectOption("#f-open", "false");
  await page.waitForSelector(".incident[data-open='false']");
  assert.strictEqual(await page.locator(".incident[data-open='true']").count(), 0);
  await page.selectOption("#f-open", "");
  await page.waitForFunction(() => document.querySelectorAll(".incident").length >= 2);
  await page.selectOption("#f-line", "network");
  assert.ok((await page.locator(".incident").count()) >= 1);
  assert.strictEqual(await page.locator(".incident[data-incident] h3", { hasText: "DNS" }).count(), 0);
  // silent-probe incident (line "probe") is labelled "Probe" and filterable
  await page.selectOption("#f-line", "probe");
  await page.waitForSelector(".incident[data-incident] h3");
  assert.ok((await page.locator(".incident[data-incident] h3", { hasText: "Probe" }).count()) >= 1, "line probe renders as Probe");
  assert.strictEqual(await page.locator(".incident[data-incident] h3", { hasText: "Network" }).count(), 0);
  await page.selectOption("#f-line", "");
  await page.selectOption("#f-open", "true");
  await page.waitForSelector(".incident[data-open='true']");
  const href = await page.locator(".incident[data-open='true'] a.btn").first().getAttribute("href");
  assert.ok(/^\/probe\/probe-a1\?at=/.test(href), href);
  await page.locator(".incident[data-open='true'] a.btn").first().click();
  await page.waitForSelector(".board[data-mode='rewind'] .line");
  assert.strictEqual(await page.locator(".banner-rewind").isVisible(), true);
  await ctxs.browser.close();
  // operator acknowledges (CSRF header added by the SPA)
  ctxs = await open({ user: "alice" });
  page = ctxs.page;
  await page.goto(cfg.base + "/incidents");
  await page.waitForSelector("button.ack");
  const id = await page.locator(".incident[data-acked='false'][data-open='true']").first().getAttribute("data-incident");
  const reqs = [];
  page.on("request", (r) => { if (r.method() === "POST") reqs.push({ url: r.url(), csrf: r.headers()["x-exp-csrf"] }); });
  await page.locator(`.incident[data-incident='${id}'] button.ack`).click();
  await page.waitForSelector(`.incident[data-incident='${id}'][data-acked='true']`);
  assert.ok(reqs.some((r) => r.url.endsWith(`/incidents/${id}/ack`) && r.csrf && r.csrf.length > 10), "ack carried the CSRF header");
  assert.strictEqual(await page.locator(`.incident[data-incident='${id}'] button.ack`).count(), 0);
  const acked = await need("acked_by", { id });
  assert.strictEqual(acked.acked_by, "alice");
  await ctxs.browser.close();
};

// Spec 7.2 / task 4: NOC fragment flow ends logged in; the fragment never survives in the address bar.
S.noc = async () => {
  const { browser, page, seen } = await open({});
  await page.goto(cfg.base + "/noc#t=" + cfg.noc_token);
  await page.waitForURL((u) => u.pathname === "/" && u.search === "?kiosk=1", { timeout: 10000 });
  assert.strictEqual(new URL(page.url()).hash, "");
  assert.ok(!page.url().includes("expn_"));
  const me = await apiJson(page, "/auth/session");
  assert.strictEqual(me.role, "viewer");
  assert.strictEqual(me.kind, "noc");
  assert.ok(!(await page.evaluate(() => document.documentElement.outerHTML)).includes("expn_"));
  assert.ok(seen.requests.every((u) => !u.includes("expn_")), "the token is only ever in a POST body");
  // an invalid link ends logged out with a message
  const b2 = await open({});
  await b2.page.goto(cfg.base + "/noc#t=expn_" + "A".repeat(43));
  await b2.page.waitForFunction(() => /invalid|expired/.test(document.querySelector("#msg").textContent));
  assert.strictEqual(new URL(b2.page.url()).hash, "");
  await b2.browser.close();
  await browser.close();
};

// Spec 7.8: kiosk rotation, big type, no interactive chrome.
S.kiosk = async () => {
  const { browser, page, seen } = await open({ user: "alice", viewport: { width: 1920, height: 1080 } });
  await page.goto(cfg.base + "/?kiosk=1&rotate=2");
  const slides = new Set();
  const end = Date.now() + 14000;
  while (Date.now() < end) {
    const s = await page.evaluate(() => document.querySelector("#app").dataset.slide || "");
    if (s) slides.add(s);
    if (slides.size >= 4) break;
    await sleep(300);
  }
  log("slides", [...slides]);
  assert.ok(slides.has("overview"), "overview slide");
  assert.ok([...slides].filter((s) => s.startsWith("probe-")).length >= 2, "rotates through probes: " + [...slides]);
  assert.strictEqual(await page.locator("#chrome").isVisible(), false, "no header/nav");
  const interactive = await page.locator("button:visible, input:visible, select:visible, a:visible, [tabindex]:not([tabindex='-1']):visible").evaluateAll((n) => n.map((x) => x.outerHTML.slice(0, 80)));
  assert.deepStrictEqual(interactive, [], "no interactive chrome");
  assert.ok(await page.evaluate(() => document.body.classList.contains("kiosk")));
  const px = await page.locator("#headline").evaluate((n) => parseFloat(getComputedStyle(n).fontSize));
  assert.ok(px >= 48, "room-readable headline, got " + px);
  assert.strictEqual(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  assert.deepStrictEqual(seen.errors, []);
  assert.deepStrictEqual(seen.csp, []);
  await browser.close();
};

// 390 px: no horizontal scroll on the board, overview, incidents and login; screenshots kept for review.
S.mobile = async () => {
  fs.mkdirSync(cfg.out, { recursive: true });
  const vp = { width: 390, height: 844 };
  const check = async (page, name) => {
    await sleep(900);
    const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, bw: document.body.scrollWidth, iw: window.innerWidth }));
    await page.screenshot({ path: path.join(cfg.out, name + ".png"), fullPage: true });
    log(name, JSON.stringify(m));
    assert.ok(m.sw <= m.iw && m.bw <= m.iw, name + " scrolls horizontally: " + JSON.stringify(m));
  };
  let c = await open({ viewport: vp });
  await c.page.goto(cfg.base + "/login");
  await c.page.waitForSelector("#username");
  await check(c.page, "login");
  await c.page.goto(cfg.base + "/auth/login");
  await check(c.page, "login-server");
  await c.browser.close();
  c = await open({ user: "alice", viewport: vp });
  const page = c.page;
  for (const [name, url, sel] of [["overview", "/", ".row"], ["incidents", "/incidents", ".incident"], ["board", "/probe/probe-a1", ".line[data-line='dns']"],
    ["board-rich", "/probe/probe-g1", ".failing .what"], ["board-rewind", "/probe/probe-a1?at=" + encodeURIComponent(new Date(cfg.t_mid).toISOString()), ".board[data-mode='rewind'] .line"],
    ["board-static", "/probe/probe-a1?static=1", ".line"], ["board-stale", "/probe/probe-b1", ".banner-stale:not([hidden])"]]) {
    await page.goto(cfg.base + url);
    await page.waitForSelector(sel);
    await check(page, name);
  }
  await page.goto(cfg.base + "/probe/probe-g1");
  await page.waitForSelector(".failing .what");
  const small = await page.evaluate(() => [...document.querySelectorAll("button, a.btn, .nav-link")].filter((n) => n.offsetParent).map((n) => n.getBoundingClientRect().height));
  assert.ok(small.every((h) => h >= 28), "tap targets: " + small);
  await c.browser.close();
};

// Login / logout through the UI; role-aware chrome; theme toggle and reduced motion.
S.login = async () => {
  const { browser, page, ctx } = await open({ viewport: { width: 1280, height: 800 }, reducedMotion: "reduce" });
  await page.goto(cfg.base + "/");
  await page.waitForURL((u) => u.pathname === "/login");
  assert.ok(new URL(page.url()).searchParams.get("next") === "/");
  await page.fill("#username", "vera");
  await page.fill("#password", "wrong-password");
  await page.click("button[type=submit]");
  await page.waitForFunction(() => /wrong/.test(document.querySelector("#login-error").textContent));
  assert.strictEqual(await page.inputValue("#password"), "", "password is cleared after a failure");
  await page.fill("#password", cfg.passwords.vera);
  await page.click("button[type=submit]");
  await page.waitForURL((u) => u.pathname === "/");
  await page.waitForSelector(".row");
  assert.ok((await page.locator(".who").textContent()).includes("viewer"));
  // open-redirect attempt is neutralised
  const p2 = await ctx.newPage();
  await p2.goto(cfg.base + "/login?next=" + encodeURIComponent("//evil.example/x"));
  await p2.waitForSelector("#username");
  await p2.fill("#username", "vera");
  await p2.fill("#password", cfg.passwords.vera);
  await p2.click("button[type=submit]");
  await p2.waitForURL((u) => u.origin === cfg.base && u.pathname === "/");
  await p2.close();
  // theme toggle: dark -> light -> auto
  assert.strictEqual(await page.evaluate(() => document.documentElement.getAttribute("data-theme")), "dark");
  await page.click(".chrome .btn-quiet >> text=Theme");
  assert.strictEqual(await page.evaluate(() => document.documentElement.getAttribute("data-theme")), "light");
  await page.reload();
  await page.waitForSelector(".row");
  assert.strictEqual(await page.evaluate(() => document.documentElement.getAttribute("data-theme")), "light");
  // keyboard: Tab reaches the skip link first, then the nav
  await page.keyboard.press("Tab");
  assert.strictEqual(await page.evaluate(() => document.activeElement.className), "skip");
  // logout
  await page.click("text=Sign out");
  await page.waitForURL((u) => u.pathname === "/login");
  const r = await ctx.request.get(cfg.base + "/auth/session");
  assert.strictEqual(r.status(), 401);
  await browser.close();
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
