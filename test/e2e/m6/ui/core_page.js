// A phone on the harness LAN runs the speedtest page (Playwright + Chromium, pre-installed globally; never `playwright install`).
// Usage: node core_page.js <config.json>      (the python driver starts it inside a client network namespace)
// The browser reaches the box and the fake Cloudflare through the LAN itself: its own resolver (DHCP), routed, no NAT, no
// host-resolver rules. The fake Cloudflare's certificate (throwaway CA) is trusted by public-key pin only.
// Output: one "@@RESULT {json}" line.
"use strict";
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const text = (page, sel) => page.evaluate((s) => { const e = document.querySelector(s); return e ? e.textContent : null; }, sel);
const shot = async (page, name, full) => { if (cfg.out && name) await page.screenshot({ path: path.join(cfg.out, name + ".png"), fullPage: !!full }); };

async function snapshot(page) {
  return page.evaluate(() => {
    const t = (id) => { const e = document.getElementById(id); return e ? e.textContent : null; };
    const legs = {};
    document.querySelectorAll("#path .leg").forEach((li) => {
      const n = li.querySelector(".name").firstChild.textContent;
      legs[n] = { val: li.querySelector(".val").firstChild.nodeValue, small: li.querySelector(".val small").textContent, cls: li.className };
    });
    const inputs = [...document.querySelectorAll("input,textarea,select")].map((e) => ({
      tag: e.tagName, type: e.type || null, name: e.name || null, id: e.id || null, autocomplete: e.getAttribute("autocomplete"),
      placeholder: e.getAttribute("placeholder"), aria: e.getAttribute("aria-label"), hidden: !!e.closest("[hidden]"),
    }));
    const boxes = {};
    for (const sel of [".top", "#stage", ".legs", "#path", "#results", ".res-top", ".score", "#parts", "#speeds", "#wf", "#checks", ".actions", ".foot", ".wrap"]) {
      const e = document.querySelector(sel);
      if (e) { const b = e.getBoundingClientRect(); boxes[sel] = { x: b.x + scrollX, y: b.y + scrollY, w: b.width, h: b.height }; }
    }
    return {
      boxes, docHeight: document.documentElement.scrollHeight, anims: document.getAnimations().length,
      scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth, innerWidth: window.innerWidth,
      score: t("scoreN"), verdict: t("verdict"), why: t("why"), parts: [...document.querySelectorAll("#parts .part")].map((e) => e.textContent),
      speeds: [...document.querySelectorAll("#speeds .sp")].map((e) => ({ k: e.querySelector(".k").textContent, v: e.querySelector(".v").textContent,
        note: (e.querySelector(".note") || { textContent: "" }).textContent })),
      wf: [...document.querySelectorAll("#wfKey span")].map((e) => e.textContent), wfNote: t("wfNote"), colo: t("colo"),
      checks: [...document.querySelectorAll("#checks li")].map((e) => e.textContent), flags: t("flagNote"),
      notice: document.getElementById("notice").hidden ? null : t("notice"),
      where: document.getElementById("whereLine").hidden ? null : t("whereLine"), chip: document.getElementById("zoneChip").hidden ? null : t("zoneChipText"),
      share: t("shareLink"), note: document.getElementById("noteView").hidden ? null : t("noteView"), title: t("title"), phase: t("phaseText"),
      legs, resultsHidden: document.getElementById("results").hidden,
      csp: window.__csp.slice(), secure: window.isSecureContext, subtle: typeof (window.crypto && window.crypto.subtle),
      wakeLock: typeof navigator.wakeLock, clipboard: typeof navigator.clipboard, inputs,
      bodyText: document.body.innerText.slice(0, 6000),
    };
  });
}

async function main() {
  fs.mkdirSync(cfg.out || ".", { recursive: true });
  const args = ["--no-proxy-server"];
  if (cfg.spki && cfg.spki.length) args.push("--ignore-certificate-errors-spki-list=" + cfg.spki.join(","));
  const browser = await chromium.launch({ args });
  const vp = cfg.viewport || { width: 390, height: 844 };
  const ctx = await browser.newContext({ viewport: vp, deviceScaleFactor: 2, colorScheme: cfg.colorScheme || "light", isMobile: true, hasTouch: true,
    reducedMotion: cfg.reducedMotion || "no-preference" });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("Network.enable");
  const wire = new Map();                 // requestId -> {url, encoded}: what really crossed the wire (compressed size)
  cdp.on("Network.requestWillBeSent", (e) => wire.set(e.requestId, { url: e.request.url, encoded: 0, type: e.type }));
  cdp.on("Network.loadingFinished", (e) => { const w = wire.get(e.requestId); if (w) w.encoded = e.encodedDataLength; });
  if (cfg.cpuThrottle) await cdp.send("Emulation.setCPUThrottlingRate", { rate: cfg.cpuThrottle });
  if (cfg.throttle) await cdp.send("Network.emulateNetworkConditions", { offline: false, latency: cfg.throttle.latencyMs || 0,
    downloadThroughput: cfg.throttle.downKbps * 1000 / 8, uploadThroughput: cfg.throttle.upKbps * 1000 / 8 });
  const seen = { dialogs: [], csp: [], errors: [], requests: [], submissions: [], failed: [], responses: [] };
  page.on("dialog", async (d) => { seen.dialogs.push(d.message()); await d.dismiss(); });
  page.on("console", (m) => { const t = m.text(); if (/Content Security Policy|Refused to/i.test(t)) seen.csp.push(t); });
  page.on("pageerror", (e) => seen.errors.push(String(e)));
  page.on("request", (r) => {
    seen.requests.push(r.url());
    if (/\/result$/.test(r.url()) && r.method() === "POST") seen.submissions.push({ req: JSON.parse(r.postData() || "null") });
  });
  page.on("requestfailed", (r) => seen.failed.push(r.url() + " " + (r.failure() || {}).errorText));
  page.on("response", async (r) => {
    if (/\/result$/.test(r.url()) && r.request().method() === "POST") {
      try { const s = seen.submissions[seen.submissions.length - 1]; s.res = await r.json(); s.status = r.status(); } catch (e) { /* ignore */ }
    }
    if (/\/internet-slot/.test(r.url())) { try { seen.responses.push({ url: r.url(), status: r.status(), body: await r.json() }); } catch (e) { /* ignore */ } }
  });
  await page.addInitScript(() => {
    window.__csp = [];
    window.__frames = [];
    window.__animMax = 0;
    window.__phases = [];
    setInterval(() => {
      window.__animMax = Math.max(window.__animMax, document.getAnimations().length);
      const e = document.getElementById("phaseText");
      if (e) window.__phases.push([performance.now(), e.textContent]);
    }, 200);
    (function tick(t) { window.__frames.push(t); requestAnimationFrame(tick); })(performance.now());
    document.addEventListener("securitypolicyviolation", (e) => window.__csp.push(e.violatedDirective + " " + e.blockedURI));
    if (window.__noClipboard) { try { Object.defineProperty(navigator, "clipboard", { value: undefined }); } catch (e) { /* ignore */ } }
  });
  const resp = await page.goto(cfg.url, { waitUntil: "load" });
  const cspHeader = resp.headers()["content-security-policy"];
  const status = resp.status();
  const pre = await snapshot(page);
  await shot(page, cfg.shotPre);
  const res = { status, cspHeader, pre, hosts: {}, scenario: cfg.name || "run" };

  if (cfg.loadOnly) {
    res.final = pre; res.requests = seen.requests; res.errors = seen.errors; res.csp = seen.csp;
    await browser.close(); console.log("@@RESULT " + JSON.stringify(res)); return;
  }
  await page.waitForFunction(() => !document.getElementById("go").disabled, null, { timeout: 15000 });
  res.loadWire = [...wire.values()].map((w) => ({ url: w.url, bytes: w.encoded, type: w.type }));
  if (cfg.tracePath) await browser.startTracing(page, { path: cfg.tracePath, categories: ["devtools.timeline", "disabled-by-default-devtools.timeline.frame", "toplevel", "blink.user_timing"] });
  if (cfg.profilePath) { await cdp.send("Profiler.enable"); await cdp.send("Profiler.setSamplingInterval", { interval: 1000 }); await cdp.send("Profiler.start"); }
  const t0 = Date.now();
  const f0 = await page.evaluate(() => performance.now());
  await page.click("#go");
  const consent = await page.waitForSelector("#consent:not([hidden])", { timeout: 5000 }).then(() => true, () => false);
  if (consent) { res.consentText = await text(page, "#cText"); await page.click("#cAnon"); }
  await page.waitForSelector("#results:not([hidden])", { timeout: cfg.timeoutMs || 90000 });
  res.doneAt = Date.now() - t0;
  res.frameTimes = await page.evaluate((from) => window.__frames.filter((t) => t >= from), f0);
  if (cfg.tracePath) await browser.stopTracing();
  if (cfg.profilePath) { const pr = await cdp.send("Profiler.stop"); fs.writeFileSync(cfg.profilePath, JSON.stringify(pr.profile)); }
  res.phases = await page.evaluate((from) => window.__phases.filter((p) => p[0] >= from), f0);
  res.animMax = await page.evaluate(() => window.__animMax);
  await page.waitForFunction(() => document.getElementById("scoreN").textContent !== "0", null, { timeout: 15000 }).catch(() => {});
  await sleep(cfg.settleMs || 1800);
  res.first = await snapshot(page);
  await shot(page, cfg.shotResults);
  if (cfg.waitChecksMs) {
    await page.waitForFunction(() => document.querySelectorAll("#checks li .wait").length === 0 && document.getElementById("checks").children.length > 0,
      null, { timeout: cfg.waitChecksMs }).catch(() => {});
    await sleep(500);
    res.checked = await snapshot(page);
    await shot(page, cfg.shotFinal, true);
  }
  if (cfg.report) {
    await page.click("#reportBtn"); await page.fill("#rText", cfg.report); await page.click("#report button[type=submit]");
    await page.waitForFunction(() => /Saved/.test(document.getElementById("rDone").textContent), null, { timeout: 8000 }).catch(() => {});
    res.rDone = await text(page, "#rDone");
    res.afterReport = await snapshot(page);
  }
  if (cfg.copy) {
    await page.click("#copy"); await sleep(300);
    res.copyStat = await text(page, "#copyStat");
    res.selection = await page.evaluate(() => String(window.getSelection()));
  }
  res.final = await snapshot(page);
  res.requests = seen.requests; res.csp = seen.csp; res.errors = seen.errors; res.dialogs = seen.dialogs;
  res.submissions = seen.submissions; res.failed = seen.failed; res.slots = seen.responses;
  const hosts = {};
  for (const u of seen.requests) { if (/^(data|blob|about):/.test(u)) continue; const h = new URL(u).host; hosts[h] = (hosts[h] || 0) + 1; }
  res.hosts = hosts;
  await browser.close();
  console.log("@@RESULT " + JSON.stringify(res));
}
main().catch((e) => { console.log("@@ERROR " + String(e && e.stack || e)); process.exit(1); });
