// Runs the transfers off the main thread. Each stream loops fetches on one host name until the deadline.
// Download counts bytes as the body arrives; upload counts a chunk when its response returns (fetch has no upload
// progress), so upload uses smaller chunks to keep the counting granular.
"use strict";
self.onmessage = async function (e) {
  var p = e.data, t0 = performance.now(), end = t0 + p.secs * 1000, bins = [], BIN = 250, errors = 0, reqs = 0;
  var chunk = p.dir === "up" ? Math.min(p.chunkMB, 8) * 1e6 : p.chunkMB * 1e6;
  var file = p.chunkMB >= 100 ? "100m" : "25m";
  // Upload body: a Blob of repeated 256 KiB random parts, the same shape as the exp page (local-leg.js uploadBlob).
  // In Chromium an ArrayBuffer/Uint8Array body uploads ~25x slower than a Blob (measured 0.2 vs 5.5 Gb/s on loopback).
  var body = null;
  if (p.dir === "up") {
    var part = new Uint8Array(262144);
    for (var o = 0; o < part.length; o += 65536) crypto.getRandomValues(part.subarray(o, o + 65536));
    var parts = []; for (var left = chunk; left > 0; left -= part.length) parts.push(left >= part.length ? part : part.subarray(0, left));
    body = new Blob(parts);
  }
  function add(n) { var i = Math.floor((performance.now() - t0) / BIN); bins[i] = (bins[i] || 0) + n; }
  function base(i) { return p.proto + "//" + p.hosts[i % p.hosts.length].replace(/:\d+$/, "") + (p.port ? ":" + p.port : ""); }
  async function stream(i) {
    while (performance.now() < end) {
      var u = base(i) + (p.dir === "up" ? "/up" : "/down/" + file) + "?r=" + Math.random();
      try {
        reqs++;
        if (p.dir === "up") {
          var r = await fetch(u, { method: "POST", body: body, headers: { "Content-Type": "text/plain" }, cache: "no-store" });
          if (r.ok) add(chunk); else errors++;
        } else {
          var res = await fetch(u, { cache: "no-store" }), rd = res.body.getReader();
          for (;;) { var x = await rd.read(); if (x.done) break; add(x.value.byteLength); if (performance.now() >= end) { rd.cancel(); break; } }
        }
      } catch (err) { errors++; }
    }
  }
  var timer = setInterval(function () {
    var i = Math.floor((performance.now() - t0) / BIN) - 1;
    if (i >= 0) self.postMessage({ type: "tick", t: (performance.now() - t0) / 1000, gbps: (bins[i] || 0) * 8 / (BIN / 1000) / 1e9 });
  }, 500);
  var all = []; for (var i = 0; i < p.streams; i++) all.push(stream(i));
  await Promise.all(all);
  clearInterval(timer);
  var n = Math.floor(p.secs * 1000 / BIN), per = [];
  for (var k = 0; k < n; k++) per.push((bins[k] || 0) * 8 / (BIN / 1000) / 1e9);
  var steady = per.slice(Math.floor(n * 0.3)), sorted = steady.slice().sort(function (a, b) { return a - b; });
  var total = per.reduce(function (a, b) { return a + b; }, 0) * BIN / 1000;
  self.postMessage({ type: "done", dir: p.dir, streams: p.streams, hosts: p.hosts.length, secs: p.secs,
    gbps_mean_steady: +(steady.reduce(function (a, b) { return a + b; }, 0) / Math.max(1, steady.length)).toFixed(3),
    gbps_p90_steady: +(sorted[Math.floor(sorted.length * 0.9)] || 0).toFixed(3),
    gb_moved: +(total / 8).toFixed(2), requests: reqs, errors: errors });
};
