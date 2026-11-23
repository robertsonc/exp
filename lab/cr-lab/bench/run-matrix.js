// Sweep the browser bench in headless Chromium: streams x host names x direction. Prints one JSON line per run.
//   node bench/run-matrix.js [--base http://127.0.0.1:8081] [--secs 8] [--streams 1,2,4,6,8,12,16] [--hosts 1,2,4]
// --no-proxy-server: Chromium on Linux otherwise follows http_proxy from the environment.
// Host names m1.bench .. m4.bench are mapped to the base's IP inside Chromium (no DNS needed).
"use strict";
const { chromium } = require(process.env.PLAYWRIGHT_PATH || "playwright");
const arg = (n, d) => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : d; };
(async () => {
  const base = new URL(arg("base", "http://127.0.0.1:8081"));
  const secs = Number(arg("secs", "8"));
  const streamsList = arg("streams", "1,2,4,6,8,12,16").split(",").map(Number);
  const hostsList = arg("hosts", "1,2,4").split(",").map(Number);
  const dirs = arg("dirs", "down,up").split(",");
  const browser = await chromium.launch({ args: ["--no-sandbox", "--no-proxy-server", `--host-resolver-rules=MAP *.bench ${base.hostname}`] });
  try {
    for (const dir of dirs) for (const h of hostsList) for (const s of streamsList) {
      if (s < h) continue;
      const hosts = Array.from({ length: h }, (_, i) => `m${i + 1}.bench`).join(",");
      const page = await browser.newPage();
      await page.goto(`http://m1.bench:${base.port}/?auto=1&dir=${dir}&streams=${s}&hosts=${hosts}&secs=${secs}`);
      await page.waitForFunction(() => window.benchResult, null, { timeout: (secs + 30) * 1000 });
      console.log(JSON.stringify(await page.evaluate(() => window.benchResult)));
      await page.close();
    }
  } finally { await browser.close(); }
})();
