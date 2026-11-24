// Multigig browser bench: drives worker.js and reports Gb/s. URL params run it directly (used by run-matrix.js):
//   /?dir=down&streams=8&hosts=m1.bench,m2.bench&secs=10&chunk=25&auto=1
"use strict";
(function () {
  var out = document.getElementById("out"), form = document.getElementById("f");
  function params(src) {
    var hosts = String(src.get("hosts") || "").split(",").map(function (h) { return h.trim(); }).filter(Boolean);
    return {
      dir: src.get("dir") === "up" ? "up" : "down",
      streams: Math.max(1, Math.min(32, Number(src.get("streams")) || 6)),
      hosts: hosts.length ? hosts : [location.host],
      secs: Math.max(3, Math.min(30, Number(src.get("secs")) || 10)),
      chunkMB: Math.max(1, Math.min(100, Number(src.get("chunk")) || 25)),
      port: location.port, proto: location.protocol,
    };
  }
  function run(p) {
    window.benchResult = null;
    out.textContent = "running " + JSON.stringify(p);
    var w = new Worker("/page/worker.js");
    w.onmessage = function (e) {
      if (e.data.type === "tick") { out.textContent = p.dir + " " + e.data.gbps.toFixed(2) + " Gb/s (" + e.data.t.toFixed(1) + " s)"; return; }
      window.benchResult = e.data;
      out.textContent = JSON.stringify(e.data, null, 1);
      w.terminate();
    };
    w.postMessage(p);
  }
  form.addEventListener("submit", function (ev) { ev.preventDefault(); run(params(new FormData(form))); });
  var q = new URLSearchParams(location.search);
  if (q.get("auto") === "1") run(params(q));
})();
