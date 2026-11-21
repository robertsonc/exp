(function () {
  "use strict";
  if (!EXP_IN_WORKER) { self.CFSpeedTest = CFSpeedTest; return; }
  var engine = null;
  function num(v) { return typeof v === "number" && isFinite(v) ? v : null; }
  function pts(a) {
    return (Array.isArray(a) ? a : []).slice(0, 5000).map(function (p) {
      if (typeof p === "number") return p;
      return { bps: num(p && p.bps), bytes: num(p && p.bytes), duration: num(p && p.duration), transferSize: num(p && p.transferSize), ping: num(p && p.ping) };
    });
  }
  function snap(R) {
    return { down: num(R.getDownloadBandwidth()), up: num(R.getUploadBandwidth()), idle: num(R.getUnloadedLatency()), jitter: num(R.getUnloadedJitter()),
      ldown: num(R.getDownLoadedLatency()), lup: num(R.getUpLoadedLatency()), dp: pts(R.getDownloadBandwidthPoints()), upp: pts(R.getUploadBandwidthPoints()),
      lp: pts(R.getUnloadedLatencyPoints()) };
  }
  function post(m) { self.postMessage(m); }
  function msgOf(e) { return String(e && e.message || e).slice(0, 200); }
  function guarded(fn) { try { fn(); } catch (e) { post({ t: "error", msg: msgOf(e) }); } }
  self.onmessage = function (ev) {
    var m = ev.data;
    if (!m || typeof m !== "object") return;
    if (m.cmd === "start" && !engine) {
      try { engine = new CFSpeedTest(m.config); } catch (e) { post({ t: "fatal", msg: msgOf(e) }); return; }
      engine.onPhaseChange = function (p) { guarded(function () { post({ t: "phase", type: p && p.measurement && p.measurement.type || null }); }); };
      engine.onResultsChange = function (p) { guarded(function () { post({ t: "results", type: p && p.type || null, snap: snap(engine.results) }); }); };
      engine.onError = function (msg) { post({ t: "error", msg: String(msg && msg.message || msg).slice(0, 200) }); };
      engine.onFinish = function () { guarded(function () { post({ t: "finish", snap: snap(engine.results) }); }); };
      engine.onRunningChange = function (running) { post({ t: "running", running: !!running, finished: !!engine.isFinished }); };
      post({ t: "started" });
      // play() throwing before the engine runs means it never will: "fatal" (the page falls back, or ends the leg after a snapshot)
      try { engine.play(); } catch (e) { post({ t: engine.isRunning ? "error" : "fatal", msg: msgOf(e) }); }
    } else if (m.cmd === "pause" && engine) {
      guarded(function () { engine.pause(); post({ t: "finish", snap: snap(engine.results), paused: true }); });
    }
  };
})();
