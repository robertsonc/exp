// A6.10: render the reference prototype (docs/spec/prototypes/speed-check.html, its own demo data) at 390 px and compare it with the real
// page's results screenshot (taken by core_page.js on the harness). Offline: file:// + the product's own woff2 fonts (so text metrics are
// comparable), Google Fonts requests aborted. Output: "@@RESULT {json}" with the geometry of both pages and the pixel comparison.
// Usage: node proto_diff.js <config.json>   config: {proto, assets, realShot, realBoxes, protoShot}
"use strict";
const fs = require("fs");
const { chromium } = require("playwright");
const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const SEL = [".top", "#stage", ".legs", "#path", "#results", ".res-top", ".score", "#parts", "#speeds", "#wf", "#checks", ".wrap"];

async function main() {
  const browser = await chromium.launch({ args: ["--no-proxy-server"] });
  // isMobile off: the prototype has no viewport meta (a mobile emulation would lay it out at 980 px); a 390-px desktop viewport = the same 390-px layout
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, colorScheme: "light", hasTouch: true });
  const page = await ctx.newPage();
  await page.route(/^https?:/, (r) => r.abort());
  await page.goto("file://" + cfg.proto, { waitUntil: "load" });
  const fonts = ["archivo", "inter", "jetbrains-mono"].map((f) => `@font-face{font-family:"${{ archivo: "Archivo", inter: "Inter", "jetbrains-mono": "JetBrains Mono" }[f]}";src:url("file://${cfg.assets}/${f}.woff2") format("woff2");font-weight:100 900;font-stretch:62% 125%;}`).join("");
  await page.addStyleTag({ content: fonts });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForFunction(() => !document.getElementById("go").disabled, null, { timeout: 15000 });
  await page.click("#go");
  if (await page.waitForSelector("#consent:not([hidden])", { timeout: 4000 }).then(() => true, () => false)) await page.click("#cAnon");
  await page.waitForSelector("#results:not([hidden])", { timeout: 90000 });
  await sleep(2500);
  const boxes = await page.evaluate((sels) => {
    const out = {};
    for (const s of sels) { const e = document.querySelector(s); if (e) { const b = e.getBoundingClientRect(); out[s] = { x: b.x + scrollX, y: b.y + scrollY, w: b.width, h: b.height }; } }
    return out;
  }, SEL);
  const docHeight = await page.evaluate(() => document.documentElement.scrollHeight);
  const scrollW = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
  await page.screenshot({ path: cfg.protoShot, fullPage: true });

  // pixel comparison in a blank page: both PNGs on canvases, luminance averaged over 16 x 16 device-pixel cells, per SECTION (each section
  // is cropped at its own top in both pages, so a taller card above does not shift everything below it): the section's cropped common height
  const cmp = await ctx.newPage();
  const b64 = (p) => "data:image/png;base64," + fs.readFileSync(p).toString("base64");
  const sections = Object.keys(boxes).filter((k) => cfg.realBoxes[k] && ![".wrap", "#results", "#path"].includes(k))
    .map((k) => ({ sel: k, r: cfg.realBoxes[k], p: boxes[k] }));
  const res = await cmp.evaluate(async ([a, b, cell, secs]) => {
    const load = (src) => new Promise((ok, bad) => { const i = new Image(); i.onload = () => ok(i); i.onerror = bad; i.src = src; });
    const [ia, ib] = await Promise.all([load(a), load(b)]);
    const grab = (img, y, h) => { const c = document.createElement("canvas"); c.width = img.width; c.height = Math.max(1, h); const x = c.getContext("2d");
      x.drawImage(img, 0, y, img.width, h, 0, 0, img.width, h); const d = x.getImageData(0, 0, c.width, c.height).data; const g = new Float32Array(c.width * c.height);
      for (let i = 0; i < g.length; i++) g[i] = 0.2126 * d[4 * i] + 0.7152 * d[4 * i + 1] + 0.0722 * d[4 * i + 2]; return { g, w: c.width, h: c.height }; };
    const out = {};
    for (const s of secs) {
      const h = Math.floor(Math.min(s.r.h, s.p.h) * 2 / cell) * cell, ya = Math.round(s.r.y * 2), yb = Math.round(s.p.y * 2);
      if (h < cell) continue;
      const A = grab(ia, ya, h), B = grab(ib, yb, h);
      let sum = 0, n = 0, big = 0;
      for (let y = 0; y + cell <= h; y += cell) for (let x = 0; x + cell <= A.w; x += cell) {
        let sa = 0, sb = 0;
        for (let yy = 0; yy < cell; yy++) for (let xx = 0; xx < cell; xx++) { const i = (y + yy) * A.w + x + xx; sa += A.g[i]; sb += B.g[i]; }
        const d = Math.abs(sa - sb) / (cell * cell); sum += d; n++; if (d > 40) big++;
      }
      out[s.sel] = { meanAbsDiff: sum / n / 255, bigCellsFrac: big / n, cells: n };
    }
    return { real: [ia.width, ia.height], proto: [ib.width, ib.height], sections: out };
  }, [b64(cfg.realShot), b64(cfg.protoShot), 16, sections]);
  await browser.close();
  console.log("@@RESULT " + JSON.stringify({ boxes, docHeight, scrollW, cmp: res }));
}
main().catch((e) => { console.log("@@ERROR " + String(e && e.stack || e)); process.exit(1); });
