/* exp speed check: the on-network transfer, ONE implementation for both hosts (CR-m6-speedtest-server item 26, follow-up
 * 2026-11-20 "on-network transfer in a worker"). page/build.py writes this file + src/local-bridge.js as assets/local-leg.js:
 *  - in a dedicated worker (the normal case) the bridge runs ExpLocalLeg.transfer for the page and posts coalesced progress;
 *  - on the main thread (the fallback when no worker can run) the page loads the same file as a classic script and calls
 *    ExpLocalLeg.transfer itself; the bridge does nothing there.
 * It needs only fetch, XMLHttpRequest, AbortController, Blob, crypto.getRandomValues, performance and timers: no document,
 * no localStorage, no window. Everything it is given (leg token, limits) and everything it returns is plain data.
 */
var ExpLocalLeg = (function () {
  'use strict';

  var MAX_STREAMS_H1 = 5;                                     // 6 connections per host over HTTP/1.1, one is kept for pings
  // the estimator (CR-m6-speedtest-server item 27): 250-ms samples, >= 8 of them for the spec's p90, else a steady window of
  // >= 200 ms; each stream keeps at most SERIES_CAP points of its cumulative byte series (<= 5 x 1024 points per direction)
  var BIN_MS = 250, MIN_P90_SAMPLES = 8, MIN_WINDOW_MS = 200, SERIES_CAP = 1024;

  function now() { return (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now(); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function median(a) { if (!a.length) return null; var b = a.slice().sort(function (x, y) { return x - y; }); var m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; }
  function percentile(a, p) { if (!a.length) return null; var b = a.slice().sort(function (x, y) { return x - y; }); return b[Math.min(b.length - 1, Math.max(0, Math.ceil(p * b.length) - 1))]; }
  function mean(a) { return a.length ? a.reduce(function (s, x) { return s + x; }, 0) / a.length : null; }
  function cv(a) { if (a.length < 2) return 0; var m = mean(a); if (!m) return 0; var v = mean(a.map(function (x) { return (x - m) * (x - m); })); return Math.sqrt(v) / m; }
  function randomBytes(n) {
    var b = new Uint8Array(n);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(b); else for (var i = 0; i < n; i++) b[i] = Math.floor(Math.random() * 256);
    return b;
  }

  var chunkBuf = null;
  function uploadBlob(size) {
    if (!chunkBuf) { chunkBuf = new Uint8Array(262144); for (var o = 0; o < chunkBuf.length; o += 65536) chunkBuf.set(randomBytes(65536), o); }
    var parts = [], left = size;
    while (left >= chunkBuf.length) { parts.push(chunkBuf); left -= chunkBuf.length; }
    if (left > 0) parts.push(chunkBuf.subarray(0, left));
    return new Blob(parts);
  }

  /** One ping of the loaded-latency series: GET /st/ping (204), 5 s timeout, aborted with `signal`. -> ms */
  function pingOnce(token, n, signal) {
    var t = now(), ac = new AbortController(), timer = setTimeout(function () { ac.abort(); }, 5000);
    if (signal) { if (signal.aborted) ac.abort(); else signal.addEventListener('abort', function () { ac.abort(); }, { once: true }); }
    return fetch('/st/ping?n=' + n, { method: 'GET', headers: { 'X-Exp-Leg-Token': token }, cache: 'no-store', credentials: 'omit', signal: ac.signal, mode: 'same-origin' }).then(function (r) {
      return r.text().then(function () {
        clearTimeout(timer);
        if (r.status !== 204) { var e = new Error('ping ' + r.status); e.status = r.status; throw e; }
        return now() - t;
      });
    }, function (e) { clearTimeout(timer); throw e; });
  }

  /** Appends [t, bytes] to a stream's cumulative series in place: a point less than 1 ms after the one before the last replaces
   * the last (the newest bytes are always kept); past SERIES_CAP points every other one is dropped (first and last kept), so a
   * series stays bounded and every point kept is still exact, only further apart. */
  function pushPoint(p, t, bytes) {
    var k = p.length;
    if (k >= 2 && t - p[k - 2][0] < 1) p[k - 1] = [t, bytes]; else p.push([t, bytes]);
    if (p.length > SERIES_CAP) { var kept = p.filter(function (x, i) { return i % 2 === 0 || i === p.length - 1; }); p.length = 0; Array.prototype.push.apply(p, kept); }
    return p;
  }

  /** Cumulative bytes of one stream at time t: linear between its recorded points, 0 before the first, the last value after
   * the last. pts: [[ms, bytes], ...], both non-decreasing. */
  function bytesAt(pts, t) {
    var n = pts ? pts.length : 0;
    if (!n || t < pts[0][0]) return 0;
    if (t >= pts[n - 1][0]) return pts[n - 1][1];
    var lo = 0, hi = n - 1;
    while (hi - lo > 1) { var mid = (lo + hi) >> 1; if (pts[mid][0] <= t) lo = mid; else hi = mid; }
    var a = pts[lo], b = pts[hi], span = b[0] - a[0];
    return span > 0 ? a[1] + (b[1] - a[1]) * (t - a[0]) / span : b[1];
  }

  /**
   * The speed of one direction from what transferLeg recorded: a PURE function (CR-m6-speedtest-server item 27).
   * in: { streams: [{ start: ms of its first byte (null: it moved none), stop: ms it stopped, pts: [[ms, cumulative bytes], ...] }],
   *       bins: [{ t: end of the 250-ms sample, dt: its length }], rampAt: ms the ramp ended (null: it never did),
   *       endAt: ms the direction ended } -- every time in ms since the direction started.
   * -> { mbps, cv, samples, method: 'p90' | 'steady' | 'lower_bound', note: null | 'short_steady' | 'no_steady' | 'no_bytes' }
   * The steady window runs from the moment the last stream that ran started moving bytes (a stream whose first byte came less
   * than 200 ms before the window's end is not waited for) to the moment the FIRST stream stopped (budget spent or refused,
   * failures) or the direction ended, whichever is first: no ramp-up head of a stream, no drain tail.
   *  - 'p90' (the spec): >= 8 complete 250-ms samples after the ramp (rampAt, else 1.5 s) inside the window: their p90 and cv;
   *  - 'steady' (the budget ended the direction first): bytes moved inside the window / its duration, when it lasts >= 200 ms;
   *    cv over its whole 250-ms sub-windows when there are >= 3, else 0 (note 'short_steady');
   *  - 'lower_bound': bytes / time from the first byte to the last of the whole direction (cv 0, note 'no_steady').
   * Bytes at a time are interpolated per stream and summed: upload progress arrives per request in ~100-ms lumps, and a counter
   * of lumps misplaces bytes between samples (on a 20 Mb/s emulated upload its p90 read 25.7 Mb/s).
   */
  function estimate(inp) {
    inp = inp || {};
    var ss = (inp.streams || []).filter(function (s) { return s && s.start != null && s.pts && s.pts.length; });
    if (!ss.length) return { mbps: 0, cv: 0, samples: 0, method: 'lower_bound', note: 'no_bytes' };
    function B(t) { var sum = 0; for (var i = 0; i < ss.length; i++) sum += bytesAt(ss[i].pts, t); return sum; }
    function rate(a, b) { return (B(b) - B(a)) * 8 / (b - a) / 1000; }               // bytes per ms -> Mb/s
    var end = inp.endAt != null ? inp.endAt : Infinity, starts = ss.map(function (s) { return s.start; }).sort(function (x, y) { return x - y; });
    ss.forEach(function (s) { if (s.stop != null && s.stop < end) end = s.stop; });
    if (end === Infinity) end = Math.max.apply(null, ss.map(function (s) { return s.pts[s.pts.length - 1][0]; }));
    var start = starts[starts.length - 1];
    for (var i = starts.length - 1; i >= 0; i--) { if (starts[i] <= end - MIN_WINDOW_MS) { start = starts[i]; break; } }
    var from = inp.rampAt != null ? inp.rampAt : 1500;
    var post = (inp.bins || []).filter(function (b) { return b.t >= from && b.dt > 0 && b.t - b.dt >= start && b.t <= end; })
      .map(function (b) { return rate(b.t - b.dt, b.t); });
    if (post.length >= MIN_P90_SAMPLES) return { mbps: percentile(post, 0.9), cv: cv(post), samples: post.length, method: 'p90', note: null };
    var dur = end - start;
    if (dur >= MIN_WINDOW_MS) {
      var k = Math.floor(dur / BIN_MS), subs = [];
      for (var j = 0; k >= 3 && j < k; j++) subs.push(rate(start + j * dur / k, start + (j + 1) * dur / k));
      return { mbps: rate(start, end), cv: subs.length ? cv(subs) : 0, samples: subs.length, method: 'steady', note: subs.length ? null : 'short_steady' };
    }
    var first = starts[0], last = Math.max.apply(null, ss.map(function (s) { return s.pts[s.pts.length - 1][0]; }));
    if (!(last - first >= 1)) first = Math.min.apply(null, ss.map(function (s) { return s.pts[0][0]; }));   // one lump: from the first request
    return { mbps: last > first ? rate(first, last) : 0, cv: 0, samples: 0, method: 'lower_bound', note: 'no_steady' };
  }

  /**
   * One direction of the on-network leg: parallel streams (start 4, grow while throughput keeps rising, capped for
   * HTTP/1.1), request sizes ramping 100 kB -> ramp_max, ending when a request takes >= 1 s (ramp over) and enough samples
   * were gathered, after 8 s, or when the direction's byte budget is spent. Each stream records its cumulative bytes at every
   * progress callback (download chunks, upload progress events; at most SERIES_CAP points: pushPoint) and when it started
   * moving bytes and stopped; estimate() turns that into the figure: p90 of 250-ms aggregate samples after the ramp (the spec),
   * or, when the budget ended the direction before 8 such samples, bytes / duration of the steady window (item 27).
   * Loaded latency is pinged on its own connection while this runs.
   *
   * ctx: { token: leg token (X-Exp-Leg-Token), limits: { streams_start, streams_max, ramp_max_bytes },
   *        signal: AbortSignal of the test's Cancel (aborts every request of this direction at once),
   *        onSample(mbps, bytes, ms): called once per 250-ms sample (the gauge) }
   * -> { mbps, cv, failures, bytes, loaded_ms, samples, method }
   */
  async function transferLeg(dir, budget, ctx) {
    var lim = ctx.limits || {}, startN = Math.max(1, lim.streams_start || 4), maxN = Math.min(lim.streams_max || 8, MAX_STREAMS_H1);
    var minB = 100000, maxB = Math.max(minB, Math.min(25000000, lim.ramp_max_bytes || 25000000));
    var T = { dir: dir, bytes: 0, used: 0, inflight: 0, size: minB, streams: 0, stop: false, rampAt: null, endAt: null, bins: [], ss: [], failures: 0,
      t0: now(), last: 0, lastT: 0 };
    var ctrls = [], pings = [], pingStop = false, token = ctx.token, cancel = ctx.signal || null, pingAc = new AbortController();
    function cancelled() { return !!(cancel && cancel.aborted); }
    // Cancel: every in-flight request of this direction is aborted now (no grace: nothing is submitted after a cancel)
    function abortAll() { ctrls.forEach(function (c) { try { c.abort(); } catch (e) { /* ignore */ } }); try { pingAc.abort(); } catch (e) { /* ignore */ } }
    if (cancel) { if (cancel.aborted) abortAll(); else cancel.addEventListener('abort', abortAll, { once: true }); }
    function remaining() { return budget - T.used - T.inflight; }
    function nextSize() { var share = Math.floor(remaining() / Math.max(1, T.streams)); return Math.min(T.size, share); }
    // per stream: { start: ms of its first byte, stop, why: 'budget' | 'end' | 'failures', bytes, pts: its cumulative bytes from
    // [created, 0] on, one point per progress callback (pushPoint bounds it) }
    function newStream() { var s = { start: null, stop: null, why: null, bytes: 0, pts: [[now() - T.t0, 0]] }; T.ss.push(s); return s; }
    function add(s, n) {
      if (!(n > 0)) return;
      var t = now() - T.t0;
      T.bytes += n; s.bytes += n;
      if (s.start == null) s.start = t;
      pushPoint(s.pts, t, s.bytes);
    }
    function done(size, dur, moved) {
      T.used += moved; T.inflight -= size;
      if (moved >= size) {
        if (dur >= 1000 && T.rampAt == null) T.rampAt = now() - T.t0;
        else if (dur < 1000 && T.size < maxB) T.size = Math.min(maxB, T.size * 4);
      } else if (!T.stop) T.failures++;
    }
    async function downReq(s, size, ctrl) {
      var r = await fetch('/st/down?bytes=' + size, { headers: { 'X-Exp-Leg-Token': token }, cache: 'no-store', credentials: 'omit', signal: ctrl.signal });
      if (r.status === 413) { var j = null; try { j = await r.json(); } catch (e) { /* ignore */ } return { moved: 0, refused: j && j.error && j.error.details && j.error.details.remaining }; }
      if (!r.ok || !r.body) throw new Error('down ' + r.status);
      var rd = r.body.getReader(), got = 0;
      for (;;) { var c = await rd.read(); if (c.done) break; got += c.value.length; add(s, c.value.length); }
      return { moved: got };
    }
    function upReq(s, size, ctrl) {
      return new Promise(function (resolve, reject) {
        var x = new XMLHttpRequest(), prev = 0;
        x.open('POST', '/st/up'); x.timeout = 30000;
        x.setRequestHeader('X-Exp-Leg-Token', token);
        x.upload.onprogress = function (e) { add(s, e.loaded - prev); prev = Math.max(prev, e.loaded); };
        x.onload = function () {
          if (x.status === 204) { add(s, size - prev); resolve({ moved: size }); }
          else if (x.status === 413) { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* ignore */ } resolve({ moved: prev, refused: j && j.error && j.error.details && j.error.details.remaining }); }
          else reject(new Error('up ' + x.status));
        };
        x.onerror = function () { reject(new Error('up network')); }; x.ontimeout = x.onerror; x.onabort = function () { resolve({ moved: prev, aborted: true }); };
        ctrl.signal.addEventListener('abort', function () { x.abort(); }, { once: true });
        x.send(uploadBlob(size));
      });
    }
    async function stream() {
      var s = newStream(), why = 'end';
      T.streams++;
      while (!T.stop && !cancelled()) {
        var size = nextSize();
        if (size < 50000) { why = 'budget'; break; }
        var ctrl = new AbortController(); ctrls.push(ctrl); T.inflight += size;
        var t = now(), res;
        try { res = await (dir === 'down' ? downReq(s, size, ctrl) : upReq(s, size, ctrl)); }
        catch (e) { T.inflight -= size; if (!T.stop) T.failures++; if (T.failures > 5) { why = 'failures'; break; } await sleep(100); continue; }
        done(size, now() - t, res.moved);
        if (res.refused != null && res.refused < 50000) { why = 'budget'; break; }
        if (res.refused != null) T.size = Math.max(minB, Math.floor(res.refused / 2));
      }
      s.stop = now() - T.t0; s.why = why;
      T.streams--;
    }
    async function pinger() {
      var i = 0;
      while (!pingStop && !cancelled()) { try { pings.push([now(), await pingOnce(token, 900 + (i++), pingAc.signal)]); } catch (e) { /* token ended or aborted */ } await sleep(220); }
    }
    var workers = [];
    for (var i = 0; i < startN && i < maxN; i++) workers.push(stream());
    var pingP = pinger();
    var prevRate = 0, lastGrow = 0;
    T.last = T.bytes; T.lastT = now();
    await new Promise(function (resolve) {
      var timer = setInterval(function () {
        var tn = now(), dt = tn - T.lastT, rate = (T.bytes - T.last) * 8 / (dt / 1000) / 1e6;
        T.last = T.bytes; T.lastT = tn;
        var el0 = tn - T.t0;
        T.bins.push({ t: el0, dt: dt, mbps: rate });
        if (ctx.onSample) { try { ctx.onSample(rate, T.bytes, el0); } catch (e) { /* the display never stops the measurement */ } }
        // grow the stream count while the aggregate rate is still rising and the ramp is not over
        if (T.streams < maxN && T.rampAt == null && el0 - lastGrow > 500 && rate > prevRate * 1.1 && T.bins.length > 2) { workers.push(stream()); lastGrow = el0; }
        prevRate = rate;
        var after = T.bins.filter(function (b) { return b.t >= (T.rampAt != null ? T.rampAt : 1500); }).length;
        if (cancelled() || el0 >= 8000 || T.streams === 0 || (T.rampAt != null && after >= 8)) { clearInterval(timer); resolve(); }
      }, 250);
    });
    T.endAt = now() - T.t0; T.stop = true; pingStop = true;
    // let small in-flight requests finish so the box's byte counters and ours agree; abort the rest
    var grace = now() + 1500;
    while (T.streams > 0 && now() < grace && !cancelled()) await sleep(50);
    ctrls.forEach(function (c) { try { c.abort(); } catch (e) { /* ignore */ } });
    await Promise.all(workers.map(function (w) { return w.catch(function () {}); })); await pingP;
    var est = estimate({ streams: T.ss, bins: T.bins, rampAt: T.rampAt, endAt: T.endAt });
    var lat = pings.filter(function (p) { return p[0] - T.t0 >= 500 || pings.length < 4; }).map(function (p) { return p[1]; });
    return { mbps: est.mbps, cv: est.cv, failures: T.failures, bytes: T.bytes, loaded_ms: median(lat), samples: est.samples, method: est.method };
  }

  // estimate and pushPoint are pure: exported for the unit tests (speedtest/tests/test_local_leg_estimator.py), unused by the page
  return { transfer: transferLeg, estimate: estimate, pushPoint: pushPoint };
})();
