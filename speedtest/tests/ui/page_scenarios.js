// Browser scenarios for the speedtest page (Playwright + Chromium, pre-installed globally).
// Usage: node page_scenarios.js <scenario> <config.json>
// The pytest driver (tests/test_page_browser.py) owns the world (exp-speedtest daemon + fake collector + fake Cloudflare);
// "@@NEED {json}" lines on stdout are answered with "@@OK {json}" on stdin, the final "@@RESULT {json}" line is the outcome.
// The browser reaches everything through --host-resolver-rules: the page is http://<host>/ (port 80, a NON-secure origin like a
// real event), the DNS-leg names *.<zone> and speed.cloudflare.com are mapped to the in-process fakes.
"use strict";
const fs = require("fs");
const path = require("path");
const readline = require("readline");
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
const step = (...a) => console.log('[step]', ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const BASE = `http://${cfg.host}`;

async function launch() {
  const rules = [`MAP ${cfg.host} 127.0.0.1:${cfg.boxPort}`, `MAP *.${cfg.zone} 127.0.0.1:${cfg.boxPort}`, `MAP speed.cloudflare.com 127.0.0.1:${cfg.cfPort}`];
  // --no-proxy-server: the sandbox's agent proxy must never be used (tests never touch the public internet)
  return chromium.launch({ args: [`--host-resolver-rules=${rules.join(",")}`, "--no-proxy-server"] });
}

async function open(browser, o) {
  o = o || {};
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: o.viewport || { width: 390, height: 844 }, deviceScaleFactor: o.dpr || 2,
    colorScheme: o.colorScheme || "light", reducedMotion: o.reducedMotion || "no-preference", isMobile: o.mobile !== false && (o.viewport || { width: 390 }).width < 700, hasTouch: true });
  const page = await ctx.newPage();
  const seen = { dialogs: [], csp: [], errors: [], requests: [], submissions: [], console: [], failed: [] };
  page.on("dialog", async (d) => { seen.dialogs.push(d.message()); await d.dismiss(); });
  page.on("console", (m) => { const t = m.text(); seen.console.push(t); if (/Content Security Policy|Refused to/i.test(t)) seen.csp.push(t); });
  page.on("pageerror", (e) => seen.errors.push(String(e)));
  page.on("request", (r) => {
    seen.requests.push(r.url());
    if (/\/result$/.test(r.url()) && r.method() === "POST") seen.submissions.push({ req: JSON.parse(r.postData() || "null") });
  });
  page.on("requestfailed", (r) => seen.failed.push(r.url() + " " + (r.failure() || {}).errorText));
  page.on("response", async (r) => {
    if (/\/result$/.test(r.url()) && r.request().method() === "POST") { try { seen.submissions[seen.submissions.length - 1].res = await r.json(); seen.submissions[seen.submissions.length - 1].status = r.status(); } catch (e) { /* ignore */ } }
  });
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener("securitypolicyviolation", (e) => window.__csp.push(e.violatedDirective + " " + e.blockedURI));
    window.__phases = [];
    document.addEventListener("DOMContentLoaded", () => {
      const t = document.getElementById("phaseText");
      new MutationObserver(() => { const v = t.textContent; if (window.__phases[window.__phases.length - 1] !== v) window.__phases.push(v); }).observe(t, { childList: true, characterData: true, subtree: true });
    });
  });
  return { ctx, page, seen };
}

const text = (page, sel) => page.evaluate((s) => { const e = document.querySelector(s); return e ? e.textContent : null; }, sel);
const shot = async (page, name, full) => { if (cfg.out) await page.screenshot({ path: path.join(cfg.out, name + ".png"), fullPage: !!full }); };

async function startTest(page) {
  await page.waitForFunction(() => !document.getElementById("go").disabled, null, { timeout: 15000 });
  await page.click("#go");
  const consent = await page.waitForSelector("#consent:not([hidden])", { timeout: 5000 }).then(() => true, () => false);
  let consentText = null;
  if (consent) { consentText = await text(page, "#cText"); await page.click("#cAnon"); }
  return { consent, consentText };
}

async function snapshot(page) {
  return page.evaluate(() => {
    const t = (id) => { const e = document.getElementById(id); return e ? e.textContent : null; };
    const legs = {};
    document.querySelectorAll("#path .leg").forEach((li) => { const n = li.querySelector(".name").firstChild.textContent; legs[n] = { val: li.querySelector(".val").firstChild.nodeValue, small: li.querySelector(".val small").textContent, cls: li.className }; });
    return {
      scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth, innerWidth: window.innerWidth,
      score: t("scoreN"), verdict: t("verdict"), why: t("why"), parts: [...document.querySelectorAll("#parts .part")].map((e) => e.textContent),
      speeds: [...document.querySelectorAll("#speeds .sp")].map((e) => ({ k: e.querySelector(".k").textContent, v: e.querySelector(".v").textContent, note: (e.querySelector(".note") || { textContent: "" }).textContent,
        scale: e.querySelector(".bar i").style.transform })),
      wf: [...document.querySelectorAll("#wfKey span")].map((e) => e.textContent), wfLabel: document.getElementById("wf").getAttribute("aria-label"), wfNote: t("wfNote"),
      colo: t("colo"), goodFor: [...document.querySelectorAll("#goodFor .gf")].map((e) => e.textContent),
      checks: [...document.querySelectorAll("#checks li")].map((e) => e.textContent), flags: t("flagNote"), notice: document.getElementById("notice").hidden ? null : t("notice"),
      where: document.getElementById("whereLine").hidden ? null : t("whereLine"), chip: document.getElementById("zoneChip").hidden ? null : t("zoneChipText"),
      share: t("shareLink"), note: document.getElementById("noteView").hidden ? null : t("noteView"), title: t("title"), docTitle: document.title,
      phase: t("phaseText"), legs, resultsHidden: document.getElementById("results").hidden, anims: document.getAnimations().length,
      csp: window.__csp.slice(), secure: window.isSecureContext, subtle: typeof (window.crypto && window.crypto.subtle), wakeLock: typeof navigator.wakeLock,
      clipboard: typeof (navigator.clipboard), fontsLoaded: [...document.fonts].filter((f) => f.status === "loaded").map((f) => f.family),
      scriptCount: document.querySelectorAll("script").length, imgs: [...document.querySelectorAll("img")].map((i) => i.getAttribute("src")),
    };
  });
}

async function waitResults(page, ms) { await page.waitForSelector("#results:not([hidden])", { timeout: ms || 120000 }); await page.waitForFunction(() => document.getElementById("scoreN").textContent !== "0" || document.getElementById("scoreN").textContent === "—", null, { timeout: 15000 }).catch(() => {}); }

function hostsOf(urls) {
  const out = {};
  for (const u of urls) { if (/^(data|blob|about):/.test(u)) continue; const h = new URL(u).host; out[h] = (out[h] || 0) + 1; }
  return out;
}

// ----------------------------------------------------------------------------------------------------------- scenarios
async function full(browser, o) {
  const { ctx, page, seen } = await open(browser, o);
  if (o.noExec) await page.addInitScript(() => { document.execCommand = () => false; });
  const resp = await page.goto(BASE + (o.query || "") + "/", { waitUntil: "load" }).catch(async () => page.goto(BASE + "/"));
  const cspHeader = resp.headers()["content-security-policy"];
  const pre = await snapshot(page);
  if (o.shotPre) await shot(page, o.shotPre);
  // keyboard: the first Tab stops land on interactive controls only
  await page.keyboard.press("Tab");
  const firstFocus = await page.evaluate(() => document.activeElement && (document.activeElement.id || document.activeElement.tagName));
  step('start'); const t0 = Date.now(), started = await startTest(page);
  const phases = [], midAnims = [];
  let doneAt = null;
  const poll = setInterval(async () => { try { const p = await text(page, "#phaseText"); if (p && phases[phases.length - 1] !== p) phases.push(p); midAnims.push(await page.evaluate(() => document.getAnimations().length)); } catch (e) { /* page closed */ } }, 120);
  if (o.midShot) { await page.waitForFunction(() => /download/i.test(document.getElementById("phaseText").textContent), null, { timeout: 60000 }).catch(() => {}); await sleep(900); await shot(page, o.midShot); }
  await waitResults(page, o.timeout);
  doneAt = Date.now() - t0; step('results after', doneAt);
  clearInterval(poll);
  phases.length = 0; (await page.evaluate(() => window.__phases)).forEach((p) => phases.push(p));
  await sleep(1800);                                   // let the sweep-in finish
  const first = await snapshot(page); step('first snapshot');
  if (o.shotResults) { await page.evaluate(() => document.getElementById("results").scrollIntoView()); await sleep(300); await shot(page, o.shotResults); await shot(page, o.shotResults + "-full", true); }
  let flipped = null;
  if (o.correlate) {
    step('correlate'); await need("correlate"); step('correlated');
    await page.waitForFunction(() => document.querySelectorAll("#checks li .wait").length === 0 && document.getElementById("checks").children.length > 0, null, { timeout: 30000 }).catch(() => {});
    await sleep(600);
    flipped = await snapshot(page);
    if (o.shotFinal) { await page.evaluate(() => document.getElementById("results").scrollIntoView()); await sleep(300); await shot(page, o.shotFinal, true); }
  }
  const final = flipped || first;
  const res = { cspHeader, pre, first, flipped, phases, firstFocus, started, doneAt, hosts: hostsOf(seen.requests), requests: seen.requests, csp: seen.csp, cspEvents: final.csp,
    errors: seen.errors, dialogs: seen.dialogs, submissions: seen.submissions, failed: seen.failed, midAnimsMax: Math.max(0, ...midAnims), midAnimsMin: midAnims.length ? Math.min(...midAnims) : null };
  step('flipped'); if (o.report) {
    await page.click("#reportBtn"); await page.fill("#rText", o.report); await page.click("#report button[type=submit]");
    await page.waitForFunction(() => /Saved/.test(document.getElementById("rDone").textContent), null, { timeout: 8000 }).catch(() => {});
    res.afterReport = await snapshot(page); res.rDone = await text(page, "#rDone");
  }
  if (o.zoneFix) {
    await page.click("#fixZone"); await page.fill("#zText", o.zoneFix); await page.click("#zonefix button[type=submit]");
    await page.waitForFunction(() => /Thanks/.test(document.getElementById("zDone").textContent), null, { timeout: 8000 }).catch(() => {});
    res.zDone = await text(page, "#zDone");
  }
  if (o.copy) {
    await page.click("#copy"); await sleep(300);
    res.copyStat = await text(page, "#copyStat");
    res.selection = await page.evaluate(() => String(window.getSelection()));
  }
  if (o.share) {
    step('share'); const link = first.share;
    const c2 = await open(browser, { viewport: { width: 390, height: 844 }, colorScheme: o.colorScheme });
    await c2.page.goto(link, { waitUntil: "load" });
    await c2.page.waitForSelector("#results:not([hidden])", { timeout: 15000 }).catch(() => {});
    await sleep(500);
    res.shared = await snapshot(c2.page);
    res.sharedHidden = await c2.page.evaluate(() => ({ again: document.getElementById("again").textContent, shareBox: document.getElementById("shareBox").hidden, reportBtn: document.getElementById("reportBtn").hidden,
      stageDisplay: getComputedStyle(document.getElementById("stage")).display }));
    if (o.shotShared) await shot(c2.page, o.shotShared, true);
    await c2.ctx.close();
    const bad = link.replace(/#k=.{43}$/, "#k=" + "A".repeat(43));
    const c3 = await open(browser, { viewport: { width: 390, height: 844 } });
    await c3.page.goto(bad, { waitUntil: "load" });
    await sleep(1500);
    res.badKey = await snapshot(c3.page);
    await c3.ctx.close();
  }
  if (o.contrast) res.contrast = await contrast(page);
  if (o.keyboard) res.keyboard = await keyboardWalk(page);
  res.final = await snapshot(page);
  await ctx.close();
  return res;
}

async function keyboardWalk(page) {
  const ids = [];
  await page.evaluate(() => { document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0); });
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press("Tab");
    ids.push(await page.evaluate(() => { const a = document.activeElement; if (!a || a === document.body) return null; const r = a.getBoundingClientRect(); return { id: a.id || a.tagName, w: Math.round(r.width), h: Math.round(r.height) }; }));
  }
  return ids;
}

async function contrast(page) {
  return page.evaluate(() => {
    function parse(c) {
      let m = /^rgba?\(([^)]+)\)$/.exec(c);
      if (m) { const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; }
      m = /^color\(srgb ([^)]+)\)$/.exec(c);
      if (m) { const p = m[1].split(/[ /]+/).filter(Boolean).map(Number); return [p[0] * 255, p[1] * 255, p[2] * 255, p.length > 3 ? p[3] : 1]; }
      return null;
    }
    const lum = (r, g, b) => [r, g, b].map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }).reduce((s, x, i) => s + x * [0.2126, 0.7152, 0.0722][i], 0);
    const over = (fg, bg) => [0, 1, 2].map((i) => fg[i] * fg[3] + bg[i] * (1 - fg[3])).concat([1]);
    function bgOf(e) {
      const stack = [];
      for (let n = e; n; n = n.parentElement) {
        const cs = getComputedStyle(n);
        if (cs.backgroundImage !== "none") return { skip: true };
        const c = parse(cs.backgroundColor);
        if (c && c[3] > 0) { stack.push(c); if (c[3] >= 0.99) break; }
      }
      let b = [255, 255, 255, 1];
      for (let i = stack.length - 1; i >= 0; i--) b = over(stack[i], b);
      return { c: b };
    }
    const out = { checked: 0, fails: [], min: 99 };
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const seenEl = new Set();
    for (let t = walker.nextNode(); t; t = walker.nextNode()) {
      if (!t.nodeValue.trim()) continue;
      const e = t.parentElement;
      if (!e || seenEl.has(e) || e.closest("[hidden]") || e.closest("svg") || e.closest(".sr") || e.closest("script,style,noscript")) continue;
      const cs = getComputedStyle(e);
      if (cs.visibility === "hidden" || cs.display === "none") continue;
      const r = e.getBoundingClientRect(); if (r.width === 0 || r.height === 0) continue;
      if (e.closest("button:disabled")) continue;
      seenEl.add(e);
      const b = bgOf(e); if (b.skip) continue;
      const fg = parse(cs.color); if (!fg) continue;
      const f = over(fg, b.c);
      const l1 = lum(f[0], f[1], f[2]), l2 = lum(b.c[0], b.c[1], b.c[2]);
      const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
      const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight, 10) >= 700;
      const need = (size >= 24 || (size >= 18.66 && bold)) ? 3 : 4.5;
      out.checked++; out.min = Math.min(out.min, ratio);
      if (ratio < need) out.fails.push({ text: t.nodeValue.trim().slice(0, 40), ratio: Math.round(ratio * 100) / 100, need, cls: e.className });
    }
    return out;
  });
}

async function viewproof(browser) {
  // the page's own HMAC/SHA-256 against the server contract: returns what the page sent so python can recompute it
  const { ctx, page, seen } = await open(browser, {});
  const sess = { create: null, headers: [] };
  page.on("request", (r) => {
    if (/\/sessions$/.test(r.url()) && r.method() === "POST") sess.create = JSON.parse(r.postData());
    const h = r.headers()["x-exp-view-proof"]; if (h) sess.headers.push(h);
  });
  await page.goto(BASE + "/"); await startTest(page); await waitResults(page, 120000);
  const link = await text(page, "#shareLink");
  await ctx.close();
  return { link, create: sess.create, proofs: [...new Set(sess.headers)] };
}

async function sha256Check(browser) {
  const { ctx, page } = await open(browser, {});
  await page.goto(BASE + "/");
  // the page's pure-JS crypto is internal; exercise it through the public behaviour only (see viewproof). Here: insecure context facts
  const r = await page.evaluate(() => ({ secure: window.isSecureContext, subtle: typeof (window.crypto && window.crypto.subtle) }));
  await ctx.close();
  return r;
}

async function plainHttp(browser) {
  // an insecure origin: no crypto.subtle, no clipboard API, no wake lock; the test still runs and the copy falls back to select-the-code
  const r = await full(browser, { copy: true, correlate: false });
  return r;
}

async function main() {
  fs.mkdirSync(cfg.out || ".", { recursive: true });
  const browser = await launch();
  let res;
  try {
    const o = cfg.opts || {};
    if (scenario === "full") res = await full(browser, o);
    else if (scenario === "viewproof") res = await viewproof(browser);
    else if (scenario === "plain") res = await plainHttp(browser);
    else if (scenario === "insecure") res = await sha256Check(browser);
    else throw new Error("unknown scenario " + scenario);
  } finally { await browser.close(); }
  console.log("@@RESULT " + JSON.stringify(res));
  rl.close();
  process.exit(0);
}
main().catch((e) => { console.log("@@ERROR " + String(e && e.stack || e)); process.exit(1); });
