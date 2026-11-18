// Playwright (Chromium) check of the Pulse board: sign in with a local user, open the page, screenshot it, print
// what it shows as JSON. Credentials come from the environment (never argv). Used by the M1 suite (A1.1, A1.3).
//   EXP_E2E_USER / EXP_E2E_PASSWORD  node board.js <base-url> <path-with-query> <screenshot.png> [width] [height]
const { chromium } = require("playwright");

(async () => {
  const [base, path, shot, w, h] = process.argv.slice(2);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({
    ignoreHTTPSErrors: true,      // the dashboard's certificate is self-signed (pinned by the Python side)
    viewport: { width: Number(w || 1280), height: Number(h || 900) },
  });
  const login = await ctx.request.post(base + "/auth/login", {
    data: { username: process.env.EXP_E2E_USER, password: process.env.EXP_E2E_PASSWORD },
  });
  if (login.status() >= 400) { console.log(JSON.stringify({ error: "login " + login.status() })); process.exit(2); }
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  await page.goto(base + path, { waitUntil: "networkidle", timeout: 30000 });
  await page.waitForTimeout(2500);        // first SSE/state paint
  await page.screenshot({ path: shot, fullPage: true });
  const text = await page.evaluate(() => document.body.innerText);
  const title = await page.title();
  await browser.close();
  console.log(JSON.stringify({ title, text, errors }));
})().catch((e) => { console.log(JSON.stringify({ error: String(e) })); process.exit(1); });
