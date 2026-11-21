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

// A stand-in for the engine worker that misbehaves on cue (test_page_browser.py::test_engine_worker_misbehaving_*), installed by an
// init script: no product hook. Messages and the error event go to the handlers the page set when it started the worker, captured
// at that moment, so they still arrive after the page terminated it (events already queued at that point); the page must ignore
// every one of them once the leg ended or fell back to the main thread. Other workers (the on-network transfer) are the real ones.
function fakeWorker(mode) {
  const Real = window.Worker;
  const F = window.__fakeWorker = { mode, made: 0, terminated: 0, sentAfterTerminate: 0 };
  const pts = (bps) => [0, 1, 2, 3].map(() => ({ bps, bytes: 1e6, duration: 1600, transferSize: 1e6, ping: null }));
  const snap = { down: 50e6, up: 20e6, idle: 12, jitter: 1, ldown: 30, lup: 35, dp: pts(50e6), upp: pts(20e6), lp: [12, 13, 12] };
  window.Worker = function (url, opts) {
    if (!/\/cf-engine\.js$/.test(String(url))) return new Real(url, opts);
    const w = this;
    let dead = false;
    F.made++;
    w.terminate = () => { if (!dead) F.terminated++; dead = true; };
    w.postMessage = (m) => {
      if (!m || m.cmd !== "start") return;
      const onmsg = w.onmessage, onerr = w.onerror;
      const send = (data) => { if (dead) F.sentAfterTerminate++; onmsg({ data }); };
      setTimeout(() => send({ t: "started" }), 50);
      if (mode === "fatal_before_snapshot") {        // the page falls back once, whatever else still arrives
        setTimeout(() => { send({ t: "fatal", msg: "no engine" }); send({ t: "fatal", msg: "again" }); onerr(new Event("error")); send({ t: "phase", type: "upload" }); }, 80);
        return;
      }
      setTimeout(() => { send({ t: "phase", type: "download" }); send({ t: "results", type: "download", snap }); }, 80);
      setTimeout(() => { if (mode === "error_after_start") onerr(new Event("error")); else send({ t: "fatal", msg: "engine broke" }); }, 300);
      setTimeout(() => { send({ t: "phase", type: "upload" }); send({ t: "finish", snap: Object.assign({}, snap, { down: 1e6 }) }); }, 350);
    };
  };
}

// A stand-in for the on-network transfer worker (/st/assets/local-leg.js) that misbehaves on cue
// (test_page_browser.py::test_local_worker_misbehaving_*), installed by an init script: no product hook. Every other worker (the
// internet engine) is the real one. "throw": new Worker throws; "silent": never says ready (the page's start timeout);
// "fatal_mid": ready, one valid and one malformed progress message, then 'fatal', a late 'done' and an error event, all to the
// handlers captured when the transfer was sent (they still arrive after terminate(), as queued events would).
function fakeLocalWorker(mode) {
  const Real = window.Worker;
  const F = window.__fakeLocal = { mode, made: 0, terminated: 0, sentAfterTerminate: 0, commands: [] };
  window.Worker = function (url, opts) {
    if (!/\/local-leg\.js$/.test(String(url))) return new Real(url, opts);
    if (mode === "throw") throw new Error("no worker today");
    const w = this;
    let dead = false;
    F.made++;
    w.terminate = () => { if (!dead) F.terminated++; dead = true; };
    const send = (h, data) => { if (dead) F.sentAfterTerminate++; if (h) h({ data }); };
    w.postMessage = (m) => {
      F.commands.push(m && m.cmd);
      if (mode !== "fatal_mid" || !m || m.cmd !== "transfer") return;
      const onmsg = w.onmessage, onerr = w.onerror;
      setTimeout(() => send(onmsg, { t: "progress", id: m.id, mbps: 123.4, bytes: 2e6, at: 250 }), 100);
      setTimeout(() => send(onmsg, { t: "progress", id: m.id, mbps: "9999", bytes: -5, at: "x" }), 150);
      setTimeout(() => {
        send(onmsg, { t: "fatal", id: m.id, msg: "broke" });
        send(onmsg, { t: "done", id: m.id, res: { mbps: 999, cv: 0, failures: 0, bytes: 1e6, loaded_ms: 1, samples: 9 } });
        if (dead) F.sentAfterTerminate++;
        if (onerr) onerr(new Event("error"));
      }, 400);
    };
    if (mode === "fatal_mid") setTimeout(() => send(w.onmessage, { t: "ready" }), 30);
  };
}

// A passthrough observer of the REAL transfer worker (test_page_browser.py::test_on_network_speed_matches_the_emulated_link):
// every Worker is the real one; for /st/assets/local-leg.js a second 'message' listener copies each 'done' result (the page's
// own onmessage handler is untouched). No product hook: the worker's `res.method` says which estimator produced the figure.
function spyLocalWorker() {
  const Real = window.Worker;
  const S = window.__localSpy = { done: [] };
  if (!Real) return;                       // noWorker: there is no Worker to observe, and none may appear
  window.Worker = function (url, opts) {
    const w = new Real(url, opts);
    if (/\/local-leg\.js$/.test(String(url))) w.addEventListener("message", (ev) => { const m = ev.data; if (m && m.t === "done") S.done.push(m.res); });
    return w;
  };
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
  seen.reqLog = [];                     // [{u, t}] every request (page AND workers), with its wall-clock time
  page.on("request", (r) => {
    seen.requests.push(r.url()); seen.reqLog.push({ u: r.url(), t: Date.now() });
    if (/\/result$/.test(r.url()) && r.method() === "POST") seen.submissions.push({ req: JSON.parse(r.postData() || "null") });
  });
  page.on("requestfailed", (r) => seen.failed.push(r.url() + " " + (r.failure() || {}).errorText));
  page.on("response", async (r) => {
    if (/\/result$/.test(r.url()) && r.request().method() === "POST") { try { seen.submissions[seen.submissions.length - 1].res = await r.json(); seen.submissions[seen.submissions.length - 1].status = r.status(); } catch (e) { /* ignore */ } }
  });
  seen.workers = [];
  page.on("worker", (w) => seen.workers.push(w.url()));
  // The page target's own CDP Network domain reports the requests of the page's main thread only, not those of its dedicated
  // workers (Playwright's page.on("request") reports both): a request in seen.requests but not in seen.mainReqs came from a worker.
  seen.mainReqs = [];
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("Network.enable");
  cdp.on("Network.requestWillBeSent", (e) => seen.mainReqs.push(e.request.url));
  // link emulation (it applies to the page's dedicated workers too): keeps a direction of the on-network leg running for seconds
  if (o.throttle) await cdp.send("Network.emulateNetworkConditions", { offline: false, latency: o.throttle.latencyMs || 0,
    downloadThroughput: o.throttle.downKbps * 1000 / 8, uploadThroughput: o.throttle.upKbps * 1000 / 8 });
  if (o.noWorker) await page.addInitScript(() => { delete window.Worker; });      // the fallback path: no dedicated workers at all
  if (o.fakeWorker) await page.addInitScript(fakeWorker, o.fakeWorker);           // a worker that errors / says fatal on cue
  if (o.fakeLocal) await page.addInitScript(fakeLocalWorker, o.fakeLocal);        // the transfer worker misbehaving on cue
  if (o.spyLocal) await page.addInitScript(spyLocalWorker);                       // the real transfer worker, its results copied
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener("securitypolicyviolation", (e) => window.__csp.push(e.violatedDirective + " " + e.blockedURI));
    window.__phases = [];
    window.__phaseAt = [];                 // [performance.now(), text] per phase change (timing of the engine start, see test_full_test_390)
    document.addEventListener("DOMContentLoaded", () => {
      const t = document.getElementById("phaseText");
      new MutationObserver(() => { const v = t.textContent; if (window.__phases[window.__phases.length - 1] !== v) { window.__phases.push(v); window.__phaseAt.push([performance.now(), v]); } }).observe(t, { childList: true, characterData: true, subtree: true });
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
      scriptCount: document.querySelectorAll("script").length, scriptSrcs: [...document.querySelectorAll("script[src]")].map((e) => e.getAttribute("src")), imgs: [...document.querySelectorAll("img")].map((i) => i.getAttribute("src")),
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
  const phaseTimes = await page.evaluate(() => window.__phaseAt);
  await sleep(1800);                                   // let the sweep-in finish
  const first = await snapshot(page); step('first snapshot');
  const fakeWorkerStats = o.fakeWorker ? await page.evaluate(() => window.__fakeWorker) : null;
  const fakeLocalStats = o.fakeLocal ? await page.evaluate(() => window.__fakeLocal || null) : null;
  const localSpy = o.spyLocal ? await page.evaluate(() => window.__localSpy || null) : null;
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
  const res = { cspHeader, pre, first, flipped, phases, phaseTimes, fakeWorker: fakeWorkerStats, fakeLocal: fakeLocalStats, localSpy, firstFocus, started, doneAt, hosts: hostsOf(seen.requests), workers: seen.workers, requests: seen.requests,
    mainReqs: seen.mainReqs, csp: seen.csp, cspEvents: final.csp,
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

// Cancel during the on-network leg (test_page_browser.py::test_cancel_during_the_on_network_leg_*): once the phase o.cancelIn shows
// and its first transfer request (o.cancelPath) went out, wait o.cancelAfterMs, click Cancel (the phase is read in the same task as
// the click), then ask the box twice ("box": its byte meter and in-flight transfers) 1 s and 2.5 s later.
async function cancelRun(browser, o) {
  const { ctx, page, seen } = await open(browser, o);
  await page.goto(BASE + "/", { waitUntil: "load" });
  await startTest(page);
  const want = o.cancelIn || "On-network download", path = o.cancelPath || "/st/down";
  await page.waitForFunction((w) => document.getElementById("phaseText").textContent === w, want, { timeout: 60000 });
  for (let i = 0; i < 200 && !seen.reqLog.some((q) => new URL(q.u).pathname === path); i++) await sleep(25);
  await sleep(o.cancelAfterMs || 600);
  const before = await need("box");
  const tc = Date.now();
  const phaseAtClick = await page.evaluate(() => { const p = document.getElementById("phaseText").textContent; document.getElementById("cancel").click(); return p; });
  await sleep(1000);
  const b1 = await need("box");
  await sleep(1500);
  const b2 = await need("box");
  await page.waitForFunction(() => document.getElementById("phaseText").textContent === "Test stopped", null, { timeout: 10000 }).catch(() => {});
  const snap = await snapshot(page);
  const phases = await page.evaluate(() => window.__phases);
  const res = { cancel: { tc, before, b1, b2, phaseAtClick }, snap, phases, reqLog: seen.reqLog, mainReqs: seen.mainReqs, workers: seen.workers, requests: seen.requests,
    submissions: seen.submissions, errors: seen.errors, csp: seen.csp, dialogs: seen.dialogs, failed: seen.failed };
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
    else if (scenario === "cancel") res = await cancelRun(browser, o);
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
