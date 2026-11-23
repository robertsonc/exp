// Run one real exp speed test from this client: headless Chromium opens the page, presses GO, accepts the anonymous
// consent, waits for the results and prints a one-line JSON summary. Used by traffic-loop.sh and scripts/traffic.sh.
//
//   node /opt/lab/speedtest-run.js [--url http://speed.cr-lab.test/] [--zone hall-a] [--report "text"] [--timeout 180]
"use strict";
const { chromium } = require("/opt/lab/node_modules/playwright");

function arg(name, dflt) {
  const i = process.argv.indexOf("--" + name);
  return i > 0 && i + 1 < process.argv.length ? process.argv[i + 1] : dflt;
}

(async () => {
  const base = arg("url", process.env.ST_URL || "http://speed.cr-lab.test/");
  const zone = arg("zone", "");
  const report = arg("report", "");
  const timeoutS = Number(arg("timeout", "180"));
  const url = zone ? `${base}${base.includes("?") ? "&" : "?"}z=${encodeURIComponent(zone)}` : base;
  const started = Date.now();
  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  try {
    const page = await (await browser.newContext({ viewport: { width: 390, height: 844 } })).newPage();
    await page.goto(url, { waitUntil: "load", timeout: 30000 });
    await page.waitForFunction(() => !document.getElementById("go").disabled, null, { timeout: 30000 });
    await page.click("#go");
    if (await page.waitForSelector("#consent:not([hidden])", { timeout: 5000 }).then(() => true, () => false)) {
      await page.click("#cAnon");
    }
    await page.waitForSelector("#results:not([hidden])", { timeout: timeoutS * 1000 });
    const t = (id) => page.evaluate((i) => { const e = document.getElementById(i); return e ? e.textContent.trim() : null; }, id);
    const speeds = await page.evaluate(() => [...document.querySelectorAll("#speeds > *")].map((c) => c.textContent.replace(/\s+/g, " ").trim()));
    if (report) {
      await page.click("#reportBtn").catch(() => {});
      await page.fill("#rText", report).catch(() => {});
      await page.click("#report button[type=submit]").catch(() => {});
      await page.waitForFunction(() => document.getElementById("rDone").textContent.trim() !== "", null, { timeout: 10000 }).catch(() => {});
    }
    console.log(JSON.stringify({ ok: true, url, seconds: Math.round((Date.now() - started) / 1000), score: await t("scoreN"),
      verdict: await t("verdict"), speeds }));
  } catch (e) {
    console.log(JSON.stringify({ ok: false, url, error: String(e && e.message || e).slice(0, 300) }));
    process.exitCode = 1;
  } finally {
    await browser.close();
  }
})();
