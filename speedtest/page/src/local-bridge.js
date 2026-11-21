/* exp speed check: the worker side of assets/local-leg.js (src/local-leg.js + this bridge; CR-m6-speedtest-server item 26,
 * follow-up 2026-11-20). Inside a DedicatedWorkerGlobalScope it runs ExpLocalLeg.transfer for the page:
 *   page -> worker  {cmd: "transfer", id, dir: "down"|"up", budget, token, limits: {streams_start, streams_max, ramp_max_bytes}}
 *                   {cmd: "cancel"}                 aborts every request of the running transfer (the page terminates us too)
 *   worker -> page  {t: "ready"}                    once, when this file has loaded
 *                   {t: "progress", id, mbps, bytes, at}   one per 250-ms sample of the transfer (no per-chunk messages)
 *                   {t: "alive", id}                once a second while a transfer runs (its end can be quiet for seconds)
 *                   {t: "done", id, res}            the direction's figures (ExpLocalLeg.transfer's result; `method`, which
 *                                                  estimator gave mbps, is 'p90' | 'steady' | 'lower_bound' or null: page-only)
 *                   {t: "fatal", id, msg}           the transfer could not run: the page stops using this worker
 * On the main thread (the fallback: the same file as a classic <script src>) it does nothing. */
(function () {
  'use strict';
  var IN_WORKER = typeof WorkerGlobalScope !== 'undefined' && typeof self !== 'undefined' && self instanceof WorkerGlobalScope;
  if (!IN_WORKER) return;
  var job = null;
  function post(m) { try { self.postMessage(m); } catch (e) { /* ignore */ } }
  function msgOf(e) { return String(e && e.message || e).slice(0, 200); }
  function num(v) { return typeof v === 'number' && isFinite(v) ? v : undefined; }
  function fin(v) { return typeof v === 'number' && isFinite(v) ? v : null; }
  function method(v) { return v === 'p90' || v === 'steady' || v === 'lower_bound' ? v : null; }
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
      post({ t: 'done', id: id, res: { mbps: fin(res.mbps), cv: fin(res.cv), failures: fin(res.failures), bytes: fin(res.bytes), loaded_ms: fin(res.loaded_ms), samples: fin(res.samples),
        method: method(res.method) } });
    }, function (e) { clearInterval(me.hb); job = null; post({ t: 'fatal', id: id, msg: msgOf(e) }); });
  };
  post({ t: 'ready' });
})();
