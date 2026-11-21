// Unit cases for the on-network leg's speed estimator (CR-m6-speedtest-server item 27), run by test_local_leg_estimator.py.
// Usage: node local_leg_units.js <path of local-leg.js>   (the built asset, or src/local-leg.js; classic script, no exports)
// Prints one "@@RESULT {json}" line: {cases: [{name, ok, got, want}]}; never exits non-zero for a failed case (pytest judges).
//
// Two kinds of case:
//  - "pure": ExpLocalLeg.estimate / pushPoint on synthetic cumulative series (per stream [[ms, bytes], ...], 250-ms bins,
//    rampAt, endAt), rates exact by construction;
//  - "sim": the whole ExpLocalLeg.transfer() on a virtual clock (performance.now, timers) with a fake box (fetch for
//    /st/down and /st/ping, XMLHttpRequest for /st/up) behind a fluid link model: the link's rate is shared equally by the
//    requests in flight (optionally capped per request), each request starts after the link latency, upload progress
//    events come every 100-300 ms per request (seeded), as Chromium reports them. Same file, same code path as the page.
"use strict";
const fs = require("fs");
const vm = require("vm");

const file = process.argv[2];
const SRC = fs.readFileSync(file, "utf8");

// ------------------------------------------------------------------------------------------------ helpers
function mulberry32(a) { return function () { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const BPMS = (mbps) => mbps * 1e6 / 8 / 1000;            // Mb/s -> bytes per ms
const near = (got, want, tol) => typeof got === "number" && isFinite(got) && Math.abs(got - want) <= tol * want;

// A context with the file loaded; `env` supplies the globals the transfer needs (the pure cases need none).
function load(env) {
  const ctx = vm.createContext(Object.assign({ console }, env || {}));
  vm.runInContext(SRC, ctx, { filename: file });
  return ctx.ExpLocalLeg;
}

// Cumulative bytes of piecewise-constant rate phases [[from, to, mbps], ...] at time t.
function cum(phases, t) { let b = 0; for (const [a, z, r] of phases) b += Math.max(0, Math.min(t, z) - a) * BPMS(r); return b; }

// One synthetic stream: reported at `times` (sorted) with the exact cumulative bytes then; created at `t0` with 0 bytes.
function stream(phases, times, stop, t0) {
  const pts = [[t0 || 0, 0]];
  for (const t of times) pts.push([t, cum(phases, t)]);
  const first = pts.find((p) => p[1] > 0);
  return { start: first ? first[0] : null, stop, pts };
}
const every = (a, z, step) => { const o = []; for (let t = a; t <= z + 1e-9; t += step) o.push(+t.toFixed(3)); return o; };
const binsTo = (end) => every(250, end, 250).map((t) => ({ t, dt: 250 }));
// report times every 100-300 ms (seeded), plus `extra` exact moments (request completions)
function lumps(a, z, seed, extra) { const r = mulberry32(seed), o = []; for (let t = a + 100 + 200 * r(); t < z; t += 100 + 200 * r()) o.push(t); return o.concat(extra || [], [z]).sort((x, y) => x - y); }

// ------------------------------------------------------------------------------------------------ pure cases
const pure = {
  // the spec's path: 6 s at a steady 400 Mb/s (4 x 100), ramp over at 1 s -> p90 of the post-ramp samples, unchanged rule
  p90_steady_400(L) {
    const ss = [0, 1, 2, 3].map((i) => stream([[2 + i, 6100, 100]], every(3 + i, 6100, 2), 6100));
    const e = L.estimate({ streams: ss, bins: binsTo(6000), rampAt: 1000, endAt: 6000 });
    return { ok: e.method === "p90" && near(e.mbps, 400, 0.01) && e.samples === 21 && e.cv < 0.01, got: e, want: "p90 ~400, 21 samples" };
  },
  // the budget ends the direction at 0.3 s on a 2 Gb/s link: 10-ms ramp-up head per stream, then a drain tail at a lower rate
  // (the first stream stopped at 300 ms, the last at 480 ms). Not the drain bin (HEAD: ~450), not bytes / one bin.
  budget_ends_at_300ms_2gbps(L) {
    const tails = [[300, 300, 0], [300, 330, 300], [300, 360, 300], [300, 480, 300]];
    const ss = [0, 1, 2, 3].map((i) => stream([[1 + i * 0.5, 11, 250], [11, 300, 500], tails[i].slice(0, 2).concat(tails[i][2])],
      every(2 + i * 0.5, tails[i][1], 0.5), tails[i][1]));
    const e = L.estimate({ streams: ss, bins: binsTo(500), rampAt: null, endAt: 500 });
    return { ok: e.method === "steady" && near(e.mbps, 2000, 0.03), got: e, want: "steady ~2000 (+-3 %)" };
  },
  // the reported artifact: ~18 MB in ~80 ms at 2 Gb/s, all of it inside ONE 250-ms bin (HEAD: 18 MB / 0.25 s = 576 Mb/s)
  budget_inside_one_bin_18mb(L) {
    const ends = [76, 77, 79, 82];
    const ss = [0, 1, 2, 3].map((i) => stream([[0.5 + i * 0.2, 4, 250], [4, ends[i], 500]], every(1 + i * 0.2, ends[i], 0.5), ends[i]));
    const e = L.estimate({ streams: ss, bins: binsTo(250), rampAt: null, endAt: 250 });
    const bytes = ss.reduce((s, x) => s + x.pts[x.pts.length - 1][1], 0);
    return { ok: e.method === "lower_bound" && e.mbps <= 2000 * 1.01 && e.mbps >= 2000 * 0.8 && Math.abs(e.mbps - bytes * 8 / 250 / 1000) > 500 && e.cv === 0,
      got: Object.assign({ budget_per_bin: bytes * 8 / 250 / 1000 }, e), want: "lower_bound in [1600, 2020], far from bytes / 250 ms" };
  },
  // the e2e upload: 800 Mb/s steady, the ramp ends (a >= 1 s request completes) at 2150 ms and the budget runs out at 2200 ms;
  // one stream drains at 20 Mb/s for 3.8 s more. HEAD's post-ramp samples are that tail (~20 Mb/s); the steady rate is 800.
  budget_right_after_ramp_long_drain(L) {
    const ends = [2200, 2210, 2220, 6000];
    const ss = [0, 1, 2, 3].map((i) => stream([[2 + i, Math.min(ends[i], 2220), 200]].concat(i === 3 ? [[2220, 6000, 20]] : []),
      every(3 + i, ends[i], 2), ends[i]));
    const e = L.estimate({ streams: ss, bins: binsTo(6250), rampAt: 2150, endAt: 6250 });
    return { ok: e.method === "steady" && near(e.mbps, 800, 0.02) && e.samples >= 3, got: e, want: "steady ~800 (+-2 %), cv over >= 3 sub-windows" };
  },
  // upload progress in lumps (each request reports every 100-300 ms and at its end): 4 x 50 Mb/s, 1.5-MB requests back to back
  // with a 3-ms gap, the budget ends the direction at 1.0-1.18 s -> the average, not a lump
  bursty_upload_budget_window(L) {
    const stops = [1000, 1050, 1100, 1180];
    const ss = [0, 1, 2, 3].map((i) => {
      const ph = [], ends = [];
      for (let t = 3 + i; t < stops[i]; t += 243) { const z = Math.min(t + 240, stops[i]); ph.push([t, z, 50]); ends.push(z); }
      return stream(ph, lumps(3 + i, stops[i], 11 + i, ends), stops[i]);
    });
    const e = L.estimate({ streams: ss, bins: binsTo(1250), rampAt: null, endAt: 1250 });
    return { ok: e.method === "steady" && near(e.mbps, 200 * 240 / 243, 0.03), got: e, want: "steady ~197.5 (+-3 %)" };
  },
  // the spec's path on a lumpy upload: 4 x 5 Mb/s for 6 s, ramp over at 1 s: every sample is computed from the per-stream
  // series (interpolated), so the p90 is the link's 20 Mb/s, not the top of the lumps (HEAD's counter: ~+30 %)
  bursty_upload_p90(L) {
    const ss = [0, 1, 2, 3].map((i) => stream([[3 + i, 6200, 5]], lumps(3 + i, 6200, 101 + i), 6200));
    const e = L.estimate({ streams: ss, bins: binsTo(6000), rampAt: 1000, endAt: 6000 });
    return { ok: e.method === "p90" && near(e.mbps, 20, 0.05) && e.cv < 0.1, got: e, want: "p90 ~20 (+-5 %)" };
  },
  // a fifth stream that started 100 ms before the first budget stop does not shrink the window to 100 ms
  late_stream_does_not_collapse_the_window(L) {
    const ss = [0, 1, 2, 3].map((i) => stream([[2, 1000, 100]], every(3, 1000, 2), 1000 + i * 10));
    ss.push(stream([[900, 1000, 100]], every(901, 1000, 2), 1005));
    const e = L.estimate({ streams: ss, bins: binsTo(1250), rampAt: null, endAt: 1250 });
    return { ok: e.method === "steady" && near(e.mbps, 410, 0.02), got: e, want: "steady over [~3, 1000] ~410" };
  },
  // no bytes at all, and a stream that never moved any: 0 Mb/s, no exception
  no_bytes(L) {
    const e = L.estimate({ streams: [{ start: null, stop: 5, pts: [[0, 0]] }], bins: [], rampAt: null, endAt: 250 });
    const e2 = L.estimate({});
    return { ok: e.mbps === 0 && e.method === "lower_bound" && e2.mbps === 0, got: [e, e2], want: "0" };
  },
  // the series stays bounded (<= SERIES_CAP = 1024 points), keeps its first and newest point, and what it keeps is exact
  series_is_bounded_and_exact(L) {
    const p = [[0, 0]];
    let ok = true;
    for (let i = 1; i <= 100000; i++) { L.pushPoint(p, i * 0.3, i * 1000); if (p.length > 1024) ok = false; }
    const exact = p.every((x, i) => i === 0 || Math.abs(x[1] - x[0] / 0.3 * 1000) < 1e-6);
    const mono = p.every((x, i) => i === 0 || (x[0] >= p[i - 1][0] && x[1] >= p[i - 1][1]));
    return { ok: ok && exact && mono && p[0][0] === 0 && p[p.length - 1][1] === 100000 * 1000 && p.length >= 256, got: { n: p.length, last: p[p.length - 1] },
      want: "<= 1024 points, exact, newest kept" };
  },
};

// ------------------------------------------------------------------------------------------------ the simulated box + link
function sim(o) {
  const clock = { t: 0, q: [], seq: 0 };
  const at = (t, fn, h) => { h = h || { dead: false }; clock.q.push({ t, s: clock.seq++, fn, h }); return h; };
  const setTimeout_ = (fn, ms) => at(clock.t + Math.max(0, +ms || 0), fn);
  const clear = (h) => { if (h) h.dead = true; };
  const setInterval_ = (fn, ms) => { const h = { dead: false }; const fire = () => { fn(); if (!h.dead) at(clock.t + ms, fire, h); }; at(clock.t + ms, fire, h); return h; };
  const abortErr = () => { const e = new Error("aborted"); e.name = "AbortError"; return e; };
  const rnd = mulberry32(o.seed || 7);
  const xs = [];                                          // requests moving bytes over the link
  const tick = o.tickMs || 1;
  const link = { h: null };
  link.h = setInterval_(() => {
    const act = xs.filter((x) => x.live && clock.t >= x.from);
    if (!act.length) return;
    let share = BPMS(o.mbps) * tick / act.length;
    if (o.perReqMbps) share = Math.min(share, BPMS(o.perReqMbps) * tick);
    act.forEach((x) => x.take(share));
  }, tick);
  function onAbort(sig, fn) { if (sig) { if (sig.aborted) fn(); else sig.addEventListener("abort", fn, { once: true }); } }
  function fetch_(url, init) {
    const u = String(url), sig = init && init.signal;
    return new Promise((resolve, reject) => {
      if (sig && sig.aborted) { reject(abortErr()); return; }
      if (u.startsWith("/st/ping")) {
        const h = setTimeout_(() => resolve({ status: 204, ok: true, text: () => Promise.resolve("") }), o.pingMs || 2);
        onAbort(sig, () => { h.dead = true; reject(abortErr()); });
        return;
      }
      const n = parseInt(u.split("bytes=")[1], 10);
      const x = { left: n, from: clock.t + o.latencyMs, live: true, carry: 0, chunks: [], waiter: null, err: null };
      const settle = () => {
        if (!x.waiter) return;
        const w = x.waiter;
        if (x.err) { x.waiter = null; w.rej(x.err); } else if (x.chunks.length) { x.waiter = null; w.res({ done: false, value: x.chunks.shift() }); } else if (!x.left) { x.waiter = null; w.res({ done: true }); }
      };
      x.take = (amt) => { x.carry += amt; const k = Math.floor(Math.min(x.carry, x.left)); if (k <= 0) return; x.carry -= k; x.left -= k; x.chunks.push({ length: k }); if (!x.left) x.live = false; settle(); };
      const reader = { read: () => new Promise((res, rej) => { x.waiter = { res, rej }; settle(); }) };
      xs.push(x);
      onAbort(sig, () => { x.live = false; x.err = abortErr(); settle(); });
      setTimeout_(() => { if (x.err) reject(x.err); else resolve({ status: 200, ok: true, body: { getReader: () => reader } }); }, o.latencyMs);
    });
  }
  function XHR() { this.upload = {}; this.status = 0; this.responseText = ""; this.timeout = 0; }
  XHR.prototype.open = function () {};
  XHR.prototype.setRequestHeader = function () {};
  XHR.prototype.send = function (blob) {
    const me = this, size = blob.size, gap = () => 100 + 200 * rnd();
    const x = { left: size, sent: 0, from: clock.t + o.latencyMs / 2, live: true, carry: 0 };
    x.next = x.from + gap();
    x.take = (amt) => {
      x.carry += amt; const k = Math.floor(Math.min(x.carry, x.left)); if (k <= 0) return;
      x.carry -= k; x.left -= k; x.sent += k;
      if (x.left && clock.t >= x.next) { x.next = clock.t + gap(); if (me.upload.onprogress) me.upload.onprogress({ loaded: x.sent, total: size }); }
      if (!x.left) {
        x.live = false;
        if (me.upload.onprogress) me.upload.onprogress({ loaded: size, total: size });
        setTimeout_(() => { if (me.aborted) return; me.status = 204; if (me.onload) me.onload(); }, o.latencyMs / 2);
      }
    };
    me.x = x; xs.push(x);
  };
  XHR.prototype.abort = function () { if (this.aborted) return; this.aborted = true; if (this.x) this.x.live = false; if (this.onabort) this.onabort(); };
  function Blob_(parts) { this.size = parts.reduce((s, p) => s + (p.byteLength != null ? p.byteLength : p.length || 0), 0); }
  const env = { performance: { now: () => clock.t }, Date: { now: () => clock.t }, setTimeout: setTimeout_, clearTimeout: clear, setInterval: setInterval_,
    clearInterval: clear, fetch: fetch_, XMLHttpRequest: XHR, Blob: Blob_, AbortController, crypto: globalThis.crypto };
  async function run(dir, budget) {
    const L = load(env);
    let done = false, val, err;
    L.transfer(dir, budget, { token: "t", limits: { streams_start: 4, streams_max: 8, ramp_max_bytes: 25e6 }, signal: null, onSample: null })
      .then((v) => { done = true; val = v; }, (e) => { done = true; err = e; });
    for (let n = 0; ; n++) {
      await new Promise((r) => setImmediate(r));                // every promise chain settles before the clock moves
      if (done) break;
      let bi = -1;
      clock.q = clock.q.filter((e) => !e.h.dead);
      for (let i = 0; i < clock.q.length; i++) { const e = clock.q[i]; if (bi < 0 || e.t < clock.q[bi].t || (e.t === clock.q[bi].t && e.s < clock.q[bi].s)) bi = i; }
      if (bi < 0) throw new Error("stalled at " + clock.t);
      const e = clock.q.splice(bi, 1)[0];
      clock.t = Math.max(clock.t, e.t);
      if (clock.t > 30000) throw new Error("runaway");
      e.fn();
    }
    link.h.dead = true;
    if (err) throw err;
    return Object.assign({ ms: Math.round(clock.t) }, val);
  }
  return { run };
}

const sims = {
  // 40 Mb/s, enough budget: the direction ends on the spec's rule, p90 of the post-ramp samples
  async sim_slow_down_p90() {
    const r = await sim({ mbps: 40, latencyMs: 5 }).run("down", 60e6);
    return { ok: near(r.mbps, 40, 0.05) && r.bytes < 60e6 * 0.9 && (r.method === undefined || r.method === "p90"), got: r, want: "~40 (+-5 %), p90" };
  },
  // 20 Mb/s upload with lumpy progress events, enough budget: p90 path, the link's rate (HEAD: the top of the lumps)
  async sim_slow_up_p90_lumpy() {
    const r = await sim({ mbps: 20, latencyMs: 5, seed: 3 }).run("up", 40e6);
    return { ok: near(r.mbps, 20, 0.05) && (r.method === undefined || r.method === "p90"), got: r, want: "~20 (+-5 %), p90" };
  },
  // 2 Gb/s, each request at most 700 Mb/s, budget 75 MB: spent in ~0.3 s, before any request took 1 s (HEAD: the drain bin)
  async sim_fast_down_budget_window() {
    const r = await sim({ mbps: 2000, perReqMbps: 700, latencyMs: 0.5 }).run("down", 75e6);
    return { ok: near(r.mbps, 2000, 0.05) && r.bytes >= 75e6 - 300000 && (r.method === undefined || r.method === "steady"), got: r, want: "~2000 (+-5 %), steady" };
  },
  // 2 Gb/s with the page tests' 18 MB download budget: all of it in < 0.1 s, inside one 250-ms sample (HEAD: 576 Mb/s)
  async sim_fast_down_budget_one_bin() {
    const r = await sim({ mbps: 2000, perReqMbps: 700, latencyMs: 0.5 }).run("down", 18e6);
    return { ok: r.mbps <= 2000 * 1.02 && r.mbps >= 2000 * 0.75 && Math.abs(r.mbps - 576) > 300, got: r, want: "lower bound in [1500, 2040], not 576" };
  },
  // 200 Mb/s upload, lumpy progress, the page tests' 12 MB upload budget: spent in ~0.5 s -> the window's average (HEAD: ~276)
  async sim_fast_up_budget_lumpy() {
    const r = await sim({ mbps: 200, latencyMs: 2, seed: 5 }).run("up", 12e6);
    return { ok: near(r.mbps, 200, 0.05) && (r.method === undefined || r.method === "steady"), got: r, want: "~200 (+-5 %), steady" };
  },
  // 600 Mb/s upload, 12 MB: spent in ~0.17 s, inside one sample (HEAD: 12 MB / 0.25 s = 384 Mb/s, the e2e figure)
  async sim_fast_up_budget_one_bin() {
    const r = await sim({ mbps: 600, latencyMs: 1, seed: 5 }).run("up", 12e6);
    return { ok: r.mbps <= 600 * 1.02 && r.mbps >= 600 * 0.75 && Math.abs(r.mbps - 384) > 60, got: r, want: "lower bound in [450, 612], not 384" };
  },
};

(async () => {
  const cases = [];
  let L = null, loadErr = null;
  try { L = load({}); } catch (e) { loadErr = String(e && e.stack || e); }
  for (const [name, fn] of Object.entries(pure)) {
    try {
      if (!L || typeof L.estimate !== "function" || typeof L.pushPoint !== "function") throw new Error("ExpLocalLeg.estimate / pushPoint missing " + (loadErr || ""));
      cases.push(Object.assign({ name }, fn(L)));
    } catch (e) { cases.push({ name, ok: false, got: String(e && e.message || e), want: "no exception" }); }
  }
  for (const [name, fn] of Object.entries(sims)) {
    const t = Date.now();
    try { cases.push(Object.assign({ name, realMs: 0 }, await fn(), { realMs: Date.now() - t })); } catch (e) { cases.push({ name, ok: false, got: String(e && e.stack || e), want: "no exception" }); }
  }
  console.log("@@RESULT " + JSON.stringify({ cases }));
})();
