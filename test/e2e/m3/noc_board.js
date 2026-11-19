// Playwright (Chromium) NOC flow: open the NOC link https://<dashboard>/noc#t=<token> (token from the environment, never
// argv), let the page exchange the fragment for a read-only session, then print what the kiosk board shows as JSON.
//   EXP_E2E_NOC_TOKEN=... node noc_board.js <base-url> <screenshot.png>
const path = require("path");
let chromium;
try { ({ chromium } = require("playwright")); }
catch (_e) { ({ chromium } = require(require.resolve("playwright", { paths: [path.join(__dirname, "..", "m1"), __dirname] }))); }

(async () => {
  const [base, shot] = process.argv.slice(2);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  await page.goto(base + "/noc#t=" + process.env.EXP_E2E_NOC_TOKEN, { waitUntil: "load", timeout: 30000 });
  await page.waitForURL(/kiosk=1/, { timeout: 20000 });
  await page.waitForLoadState("networkidle", { timeout: 30000 });
  await page.waitForTimeout(3000);
  await page.screenshot({ path: shot, fullPage: true });
  const text = await page.evaluate(() => document.body.innerText);
  const url = page.url();
  const who = await (await ctx.request.get(base + "/auth/session")).status();
  await browser.close();
  console.log(JSON.stringify({ url, text, errors, whoami: who }));
})().catch((e) => { console.log(JSON.stringify({ error: String(e) })); process.exit(1); });
