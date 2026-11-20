var ExpLocalLeg = (function () {
  'use strict';
  var MAX_STREAMS_H1 = 5;                                     // 6 connections per host over HTTP/1.1, one is kept for pings
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
  /**
   * One direction of the on-network leg: parallel streams (start 4, grow while throughput keeps rising, capped for
   * HTTP/1.1), request sizes ramping 100 kB -> ramp_max, ending when a request takes >= 1 s (ramp over) and enough samples
   * were gathered, after 8 s, or when the direction's byte budget is spent. Speed = p90 of 250-ms aggregate samples taken
   * after the ramp. Loaded latency is pinged on its own connection while this runs.
   *
   * ctx: { token: leg token (X-Exp-Leg-Token), limits: { streams_start, streams_max, ramp_max_bytes },
   *        signal: AbortSignal of the test's Cancel (aborts every request of this direction at once),
   *        onSample(mbps, bytes, ms): called once per 250-ms sample (the gauge) }
   * -> { mbps, cv, failures, bytes, loaded_ms, samples }
   */
  async function transferLeg(dir, budget, ctx) {
    var lim = ctx.limits || {}, startN = Math.max(1, lim.streams_start || 4), maxN = Math.min(lim.streams_max || 8, MAX_STREAMS_H1);
    var minB = 100000, maxB = Math.max(minB, Math.min(25000000, lim.ramp_max_bytes || 25000000));
    var T = { dir: dir, bytes: 0, used: 0, inflight: 0, size: minB, streams: 0, stop: false, rampAt: null, bins: [], failures: 0, t0: now(), last: 0, lastT: 0 };
    var ctrls = [], pings = [], pingStop = false, token = ctx.token, cancel = ctx.signal || null, pingAc = new AbortController();
    function cancelled() { return !!(cancel && cancel.aborted); }
    function abortAll() { ctrls.forEach(function (c) { try { c.abort(); } catch (e) { /* ignore */ } }); try { pingAc.abort(); } catch (e) { /* ignore */ } }
    if (cancel) { if (cancel.aborted) abortAll(); else cancel.addEventListener('abort', abortAll, { once: true }); }
    function remaining() { return budget - T.used - T.inflight; }
    function nextSize() { var share = Math.floor(remaining() / Math.max(1, T.streams)); return Math.min(T.size, share); }
    function add(n) { T.bytes += n; }
    function done(size, dur, moved) {
      T.used += moved; T.inflight -= size;
      if (moved >= size) {
        if (dur >= 1000 && T.rampAt == null) T.rampAt = now() - T.t0;
        else if (dur < 1000 && T.size < maxB) T.size = Math.min(maxB, T.size * 4);
      } else if (!T.stop) T.failures++;
    }
    async function downReq(size, ctrl) {
      var r = await fetch('/st/down?bytes=' + size, { headers: { 'X-Exp-Leg-Token': token }, cache: 'no-store', credentials: 'omit', signal: ctrl.signal });
      if (r.status === 413) { var j = null; try { j = await r.json(); } catch (e) { /* ignore */ } return { moved: 0, refused: j && j.error && j.error.details && j.error.details.remaining }; }
      if (!r.ok || !r.body) throw new Error('down ' + r.status);
      var rd = r.body.getReader(), got = 0;
      for (;;) { var c = await rd.read(); if (c.done) break; got += c.value.length; add(c.value.length); }
      return { moved: got };
    }
    function upReq(size, ctrl) {
      return new Promise(function (resolve, reject) {
        var x = new XMLHttpRequest(), prev = 0;
        x.open('POST', '/st/up'); x.timeout = 30000;
        x.setRequestHeader('X-Exp-Leg-Token', token);
        x.upload.onprogress = function (e) { add(e.loaded - prev); prev = e.loaded; };
        x.onload = function () {
          if (x.status === 204) { add(size - prev); resolve({ moved: size }); }
          else if (x.status === 413) { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* ignore */ } resolve({ moved: prev, refused: j && j.error && j.error.details && j.error.details.remaining }); }
          else reject(new Error('up ' + x.status));
        };
        x.onerror = function () { reject(new Error('up network')); }; x.ontimeout = x.onerror; x.onabort = function () { resolve({ moved: prev, aborted: true }); };
        ctrl.signal.addEventListener('abort', function () { x.abort(); }, { once: true });
        x.send(uploadBlob(size));
      });
    }
    async function stream() {
      T.streams++;
      while (!T.stop && !cancelled()) {
        var size = nextSize();
        if (size < 50000) break;
        var ctrl = new AbortController(); ctrls.push(ctrl); T.inflight += size;
        var t = now(), res;
        try { res = await (dir === 'down' ? downReq(size, ctrl) : upReq(size, ctrl)); }
        catch (e) { T.inflight -= size; if (!T.stop) T.failures++; if (T.failures > 5) break; await sleep(100); continue; }
        done(size, now() - t, res.moved);
        if (res.refused != null && res.refused < 50000) break;
        if (res.refused != null) T.size = Math.max(minB, Math.floor(res.refused / 2));
      }
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
        T.bins.push({ t: el0, mbps: rate });
        if (ctx.onSample) { try { ctx.onSample(rate, T.bytes, el0); } catch (e) { /* the display never stops the measurement */ } }
        if (T.streams < maxN && T.rampAt == null && el0 - lastGrow > 500 && rate > prevRate * 1.1 && T.bins.length > 2) { workers.push(stream()); lastGrow = el0; }
        prevRate = rate;
        var after = T.bins.filter(function (b) { return b.t >= (T.rampAt != null ? T.rampAt : 1500); }).length;
        if (cancelled() || el0 >= 8000 || T.streams === 0 || (T.rampAt != null && after >= 8)) { clearInterval(timer); resolve(); }
      }, 250);
    });
    T.stop = true; pingStop = true;
    var grace = now() + 1500;
    while (T.streams > 0 && now() < grace && !cancelled()) await sleep(50);
    ctrls.forEach(function (c) { try { c.abort(); } catch (e) { /* ignore */ } });
    await Promise.all(workers.map(function (w) { return w.catch(function () {}); })); await pingP;
    var from = T.rampAt != null ? T.rampAt : 1500;
    var post = T.bins.filter(function (b) { return b.t >= from; }).map(function (b) { return b.mbps; });
    if (post.length < 3) post = T.bins.slice(Math.floor(T.bins.length / 2)).map(function (b) { return b.mbps; });
    var secs = Math.max(0.25, (now() - T.t0) / 1000);
    var speed = post.length ? percentile(post, 0.9) : T.bytes * 8 / secs / 1e6;
    var lat = pings.filter(function (p) { return p[0] - T.t0 >= 500 || pings.length < 4; }).map(function (p) { return p[1]; });
    return { mbps: speed, cv: cv(post), failures: T.failures, bytes: T.bytes, loaded_ms: median(lat), samples: post.length };
  }
  return { transfer: transferLeg };
})();
(function () {
  'use strict';
  var IN_WORKER = typeof WorkerGlobalScope !== 'undefined' && typeof self !== 'undefined' && self instanceof WorkerGlobalScope;
  if (!IN_WORKER) return;
  var job = null;
  function post(m) { try { self.postMessage(m); } catch (e) { /* ignore */ } }
  function msgOf(e) { return String(e && e.message || e).slice(0, 200); }
  function num(v) { return typeof v === 'number' && isFinite(v) ? v : undefined; }
  function fin(v) { return typeof v === 'number' && isFinite(v) ? v : null; }
  self.onmessage = function (ev) {
    var m = ev.data;
    if (!m || typeof m !== 'object') return;
    if (m.cmd === 'cancel') { if (job) job.ac.abort(); return; }
    if (m.cmd !== 'transfer') return;
    var id = typeof m.id === 'number' && isFinite(m.id) ? m.id : 0;
    var lim = m.limits && typeof m.limits === 'object' ? m.limits : {};
    if (job || (m.dir !== 'down' && m.dir !== 'up') || typeof m.token !== 'string' || !/^[A-Za-z0-9_.~-]{1,200}$/.test(m.token) ||
        num(m.budget) === undefined) { post({ t: 'fatal', id: id, msg: job ? 'busy' : 'bad command' }); return; }
    var ac = new AbortController(), me = { id: id, ac: ac, hb: null };
    job = me;
    me.hb = setInterval(function () { post({ t: 'alive', id: id }); }, 1000);
    var ctx = { token: m.token, limits: { streams_start: num(lim.streams_start), streams_max: num(lim.streams_max), ramp_max_bytes: num(lim.ramp_max_bytes) },
      signal: ac.signal, onSample: function (mbps, bytes, at) { post({ t: 'progress', id: id, mbps: fin(mbps), bytes: fin(bytes), at: fin(at) }); } };
    var run;
    try { run = ExpLocalLeg.transfer(m.dir, m.budget, ctx); } catch (e) { run = Promise.reject(e); }
    run.then(function (res) {
      clearInterval(me.hb); job = null; res = res || {};
      post({ t: 'done', id: id, res: { mbps: fin(res.mbps), cv: fin(res.cv), failures: fin(res.failures), bytes: fin(res.bytes), loaded_ms: fin(res.loaded_ms), samples: fin(res.samples) } });
    }, function (e) { clearInterval(me.hb); job = null; post({ t: 'fatal', id: id, msg: msgOf(e) }); });
  };
  post({ t: 'ready' });
})();
