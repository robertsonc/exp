/* exp speed check: the page engine (WP-10, 12-speedtest-analytics.md section 4).
 *
 * Everything the user or the server can influence reaches the DOM through textContent / setAttribute of validated values;
 * there is no innerHTML. Requests go to this box, to the DNS-leg names it handed out and, for the internet leg only, to
 * speed.cloudflare.com. The page works over plain HTTP: crypto.subtle, the clipboard API and the wake lock are feature
 * detected (the view-proof HMAC is implemented below because subtle crypto does not exist outside secure contexts).
 *
 * Wire format to the box: shared/openapi/speedtest.yaml; page -> box result: shared/schemas/speedtest.submission.schema.json
 * (exp.speedtest.submission/1). Fragment-key view proof: CR-m6-contracts + CR-m6-speedtest-server item 1.
 * Internet leg: the vendored @cloudflare/speedtest 1.16.0 (MIT) as CFSpeedTest, configured with logAimApiUrl = null so no
 * result is ever posted to Cloudflare; the serving colo comes from the /cdn-cgi/trace BODY; the requester egress headers
 * that Cloudflare's __down returns (cf-meta-ip, city, ...) are never read.
 */
(function () {
  'use strict';

  // ------------------------------------------------------------------------------------------------ constants
  var SENTINEL_ID = 'st_00000000000000000000000000';       // CR-m6-speedtest-server item 1: fixed id for the proof HMAC
  var CF_BASE = 'https://speed.cloudflare.com';
  var SCALE = [0, 5, 10, 25, 50, 100, 250, 500, 1000];       // piecewise-log gauge scale, 270 degrees
  var ARC = 565.5, CX = 150, CY = 150, R = 120, SCORE_ARC = 326.7;
  var API = '/st/api/v1';
  var MAX_STREAMS_H1 = 5;                                     // 6 connections per host over HTTP/1.1, one is kept for pings
  var NS = document.querySelector('svg').namespaceURI; // SVG namespace taken from the page's own inline <svg> (no URL literal in the page)
  var $ = function (id) { return document.getElementById(id); };

  var ICONS = {
    wifi: 'M2 9a15 15 0 0 1 20 0 M5 12.5a10 10 0 0 1 14 0 M8.5 16a5 5 0 0 1 7 0 M12 19.5h0',
    dns: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0 -18 0 M3 12h18 M12 3a14 14 0 0 1 0 18 M12 3a14 14 0 0 0 0 18',
    router: 'M3 15a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z M7 16.5h0 M11 16.5h0 M12 13V8 M8.5 6.5a5 5 0 0 1 7 0',
    edge: 'M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z M8 12h8 M13 9l3 3-3 3',
    isp: 'M4 12h4l2-6 4 12 2-6h4',
    cloud: 'M7 18h10a4 4 0 0 0 .5-8 6 6 0 0 0-11.5 1.5A3.5 3.5 0 0 0 7 18z',
    check: 'M5 12l5 5 9-10', dash: 'M6 12h12', bang: 'M12 7v6 M12 17h0', cross: 'M7 7l10 10 M17 7L7 17', spin: 'M12 3a9 9 0 1 0 9 9'
  };
  var LEGS = [
    { id: 'lan', icon: 'wifi', name: 'Wi-Fi and venue network', tag: 'on-network', what: 'Your device across Wi-Fi and the venue to the test box' },
    { id: 'dns', icon: 'dns', name: 'Name lookup (DNS)', tag: 'your resolver', what: 'A one-time name, so nothing is cached' },
    { id: 'gw', icon: 'router', name: 'Venue gateway', tag: 'net', what: 'First router on your network' },
    { id: 'edge', icon: 'edge', name: 'Venue edge', tag: 'net', what: 'Where the venue meets the internet' },
    { id: 'edge1', icon: 'isp', name: 'One hop past the edge', tag: 'net', what: 'The internet provider’s first router' },
    { id: 'cf', icon: 'cloud', name: 'Cloudflare', tag: 'you → internet', what: 'Public test servers, nearest location' }
  ];
  var CHECK_LABELS = { wifi: 'Wi-Fi signal', wired: 'Wired connection', wan: 'Venue internet', security: 'Security policy', baseline: 'Hall sensor',
    dns: 'Name lookups', identity: 'Your device', flows: 'Your traffic' };
  var DEFAULT_CHECKS = ['wifi', 'wan', 'security', 'baseline'];
  var INTERNET_REASON = {
    admin_pause: 'The network team has paused the internet part of the test.',
    wan_utilization: 'Paused for now: the venue internet link is busy.',
    disabled: 'The internet part of the test is not available at this event.',
    capacity: 'Waiting for a free slot so the venue internet link is not overloaded.'
  };

  // ------------------------------------------------------------------------------------------------ small helpers
  function reduced() { try { return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches); } catch (e) { return false; } }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function now() { return (window.performance && performance.now) ? performance.now() : Date.now(); }
  function median(a) { if (!a.length) return null; var b = a.slice().sort(function (x, y) { return x - y; }); var m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; }
  function percentile(a, p) { if (!a.length) return null; var b = a.slice().sort(function (x, y) { return x - y; }); return b[Math.min(b.length - 1, Math.max(0, Math.ceil(p * b.length) - 1))]; }
  function mean(a) { return a.length ? a.reduce(function (s, x) { return s + x; }, 0) / a.length : null; }
  function cv(a) { if (a.length < 2) return 0; var m = mean(a); if (!m) return 0; var v = mean(a.map(function (x) { return (x - m) * (x - m); })); return Math.sqrt(v) / m; }
  function jitterOf(a) { if (a.length < 2) return 0; var d = []; for (var i = 1; i < a.length; i++) d.push(Math.abs(a[i] - a[i - 1])); return mean(d); }
  function clampNum(v, max) { return (typeof v === 'number' && isFinite(v)) ? Math.max(0, Math.min(max, v)) : null; }
  function r1(v) { return v == null ? null : Math.round(v * 10) / 10; }
  function r2(v) { return v == null ? null : Math.round(v * 100) / 100; }
  function fmtMs(v) { return v == null ? '—' : (v < 10 ? v.toFixed(1) : String(Math.round(v))); }
  function fmtMbps(v) { return v >= 100 ? String(Math.round(v)) : v.toFixed(1); }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function svgEl(name, attrs) { var e = document.createElementNS(NS, name); for (var k in attrs) e.setAttribute(k, attrs[k]); return e; }
  function icon(name, cls) {
    var s = svgEl('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true' }); if (cls) s.setAttribute('class', cls);
    ICONS[name].split(' M').forEach(function (d, i) { s.appendChild(svgEl('path', { d: i ? 'M' + d : d })); });
    return s;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function safeStorage(op, k, v) { try { return op === 'get' ? window.localStorage.getItem(k) : window.localStorage.setItem(k, v); } catch (e) { return null; } }
  function cleanText(s, max) { return String(s).replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').slice(0, max); }
  function grade(v, ok, warn) { return v == null ? null : (v <= ok ? 'ok' : (v <= warn ? 'warn' : 'crit')); }

  // ------------------------------------------------------------------------------------------------ SHA-256 / HMAC
  // Pure JS: window.crypto.subtle only exists in secure contexts and this page is plain HTTP by default (D15).
  var K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  function sha256(msg) {
    var h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    var n = msg.length, total = ((n + 9 + 63) >> 6) << 6, buf = new Uint8Array(total);
    buf.set(msg); buf[n] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(n / 0x20000000), false); dv.setUint32(total - 4, (n << 3) >>> 0, false);
    var w = new Uint32Array(64);
    for (var off = 0; off < total; off += 64) {
      var i, s0, s1;
      for (i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (i = 16; i < 64; i++) {
        s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
        s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K256[i] + w[i]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    var out = new Uint8Array(32), ov = new DataView(out.buffer);
    for (var j = 0; j < 8; j++) ov.setUint32(j * 4, h[j], false);
    return out;
  }
  function hmac256(key, msg) {
    if (key.length > 64) key = sha256(key);
    var ipad = new Uint8Array(64 + msg.length), opad = new Uint8Array(64 + 32), i;
    for (i = 0; i < 64; i++) { var kb = i < key.length ? key[i] : 0; ipad[i] = kb ^ 0x36; opad[i] = kb ^ 0x5c; }
    ipad.set(msg, 64); opad.set(sha256(ipad), 64);
    return sha256(opad);
  }
  function utf8(s) { return new TextEncoder().encode(s); }
  function hex(b) { var s = ''; for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16); return s; }
  function b64url(b) { var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function unb64url(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; var r = atob(s), o = new Uint8Array(r.length); for (var i = 0; i < r.length; i++) o[i] = r.charCodeAt(i); return o; }
  function randomBytes(n) {
    var b = new Uint8Array(n);
    if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(b); else for (var i = 0; i < n; i++) b[i] = Math.floor(Math.random() * 256);
    return b;
  }
  /** proof = "expv_" + b64url(HMAC-SHA256(k, "exp.st.view/1:" + SENTINEL)); verifier = sha256_hex(proof) (01-contracts 14.2). */
  function viewProof(k) { return 'expv_' + b64url(hmac256(unb64url(k), utf8('exp.st.view/1:' + SENTINEL_ID))); }
  function viewVerifier(proof) { return hex(sha256(utf8(proof))); }

  // ------------------------------------------------------------------------------------------------ http
  function http(method, url, opt) {
    opt = opt || {};
    var ac = new AbortController(), timer = setTimeout(function () { ac.abort(); }, opt.timeout || 15000);
    if (opt.signal) { if (opt.signal.aborted) ac.abort(); else opt.signal.addEventListener('abort', function () { ac.abort(); }, { once: true }); }
    var init = { method: method, headers: opt.headers || {}, cache: 'no-store', credentials: 'omit', signal: ac.signal, mode: opt.mode || 'same-origin' };
    if (opt.json !== undefined) { init.body = JSON.stringify(opt.json); init.headers = Object.assign({ 'Content-Type': 'application/json' }, init.headers); }
    return fetch(url, init).then(function (r) {
      var ra = parseInt(r.headers.get('Retry-After') || '', 10);
      return (opt.raw ? r.text() : r.text().then(function (t) { try { return t ? JSON.parse(t) : null; } catch (e) { return null; } })).then(function (body) {
        clearTimeout(timer);
        return { status: r.status, ok: r.ok, body: body, retryAfter: isNaN(ra) ? null : ra };
      });
    }, function (e) { clearTimeout(timer); throw e; });
  }
  async function retrying(fn, tries) {
    var delay = 400, last;
    for (var i = 0; i < tries; i++) {
      try { var r = await fn(); if (r.status < 500 && r.status !== 429) return r; last = r; } catch (e) { last = { status: 0, body: null, err: e }; }
      if (i + 1 < tries) { await sleep(delay); delay *= 2; }
    }
    return last;
  }
  function errCode(r) { return r && r.body && r.body.error && r.body.error.code || null; }

  // ------------------------------------------------------------------------------------------------ state
  var S = {
    cfg: null, key: null, proof: null, sess: null, running: false, cancelled: false, ac: null, path: null, pathTimer: null,
    pollTimer: null, viewMode: false, result: null, view: null, measured: null, t0: 0, zoneHint: null, animated: false,
    report: '', zoneFix: '', note: '', wake: null, cf: null, slot: false, shareId: null
  };
  var legEls = {};
  var G = { shown: 0, target: 0, loop: false, mode: 'speed', samples: [] };

  // ------------------------------------------------------------------------------------------------ gauge
  function buildTicks() {
    var g = $('ticks');
    SCALE.forEach(function (v, i) {
      var a = (135 + 270 * i / (SCALE.length - 1)) * Math.PI / 180;
      g.appendChild(svgEl('line', { x1: (CX + (R - 18) * Math.cos(a)).toFixed(2), y1: (CY + (R - 18) * Math.sin(a)).toFixed(2), x2: (CX + (R - 24) * Math.cos(a)).toFixed(2), y2: (CY + (R - 24) * Math.sin(a)).toFixed(2) }));
      var t = svgEl('text', { x: (CX + (R - 38) * Math.cos(a)).toFixed(2), y: (CY + (R - 38) * Math.sin(a) + 4).toFixed(2), 'text-anchor': 'middle' });
      t.textContent = String(v); g.appendChild(t);
    });
  }
  function frac(v) {
    for (var i = 1; i < SCALE.length; i++) if (v <= SCALE[i]) return (i - 1 + (v - SCALE[i - 1]) / (SCALE[i] - SCALE[i - 1])) / (SCALE.length - 1);
    return 1;
  }
  function draw() {
    G.shown += (G.target - G.shown) * (reduced() ? 1 : 0.14);
    if (Math.abs(G.target - G.shown) < 0.05) G.shown = G.target;
    var f = frac(G.shown);
    $('prog').setAttribute('stroke-dashoffset', (ARC * (1 - f)).toFixed(1));
    var a = (135 + 270 * f) * Math.PI / 180;
    $('tip').setAttribute('cx', (CX + R * Math.cos(a)).toFixed(1)); $('tip').setAttribute('cy', (CY + R * Math.sin(a)).toFixed(1));
    if (G.mode === 'speed') $('num').textContent = fmtMbps(G.shown);
    if (G.loop) requestAnimationFrame(draw);
  }
  function loopOn() { if (!G.loop) { G.loop = true; requestAnimationFrame(draw); } }
  function loopOff() { G.loop = false; }
  function gaugeMode(m) {
    var c = m === 'up' ? 'var(--up)' : 'var(--down)';
    $('stage').classList.toggle('mode-up', m === 'up'); $('stage').style.setProperty('--accent', c);
    document.querySelectorAll('.stop-f').forEach(function (s) { s.style.setProperty('stop-color', c); });
  }
  function setSpeedMode(on) {
    G.mode = on ? 'speed' : 'text';
    $('spinner').hidden = on; $('tip').setAttribute('opacity', on ? '1' : '0');
    if (on) { $('unit').textContent = 'Mb/s'; } else { G.shown = G.target = 0; $('prog').setAttribute('stroke-dashoffset', String(ARC)); }
  }
  function showMs(v) { G.mode = 'text'; $('num').textContent = v == null ? '…' : fmtMs(v); $('unit').textContent = 'ms'; }
  function trace() {
    var n = G.samples.length;
    if (!n) { $('traceLine').setAttribute('d', ''); $('traceArea').setAttribute('d', ''); return; }
    var max = Math.max.apply(null, G.samples) * 1.15 || 1, d = '';
    for (var i = 0; i < n; i++) { d += (i ? ' L' : 'M') + ((i / Math.max(n - 1, 1)) * 300).toFixed(1) + ' ' + (62 - G.samples[i] / max * 58).toFixed(1); }
    $('traceLine').setAttribute('d', d); $('traceArea').setAttribute('d', d + ' L300 64 L0 64 Z');
  }
  function feedGauge(mbps) {
    G.target = Math.max(0, mbps); G.samples.push(G.target); if (G.samples.length > 120) G.samples.shift(); trace();
    $('lgR').textContent = Math.round(G.target) + ' Mb/s';
  }
  function phase(text, sub) { $('phaseText').textContent = text; $('sub').textContent = sub || ''; $('announce').textContent = text; }
  function notice(text, bad) { var n = $('notice'); n.hidden = !text; n.textContent = text || ''; n.classList.toggle('bad', !!bad); }

  // ------------------------------------------------------------------------------------------------ path of legs
  function buildLegs() {
    var ol = $('path');
    LEGS.forEach(function (l) {
      var li = el('li', 'leg');
      var node = el('span', 'node'); node.appendChild(icon(l.icon)); li.appendChild(node); li.appendChild(el('span', 'rail'));
      var mid = el('div'), nm = el('div', 'name', l.name); nm.appendChild(el('em', '', l.tag)); mid.appendChild(nm);
      var what = el('div', 'what', l.what); mid.appendChild(what); li.appendChild(mid);
      var val = el('div', 'val pending'); var main = document.createTextNode('—'); val.appendChild(main);
      var small = el('small', '', 'not yet'); val.appendChild(small); li.appendChild(val);
      ol.appendChild(li);
      legEls[l.id] = { li: li, val: val, main: main, small: small, what: what, defWhat: l.what };
    });
  }
  function legReset() {
    Object.keys(legEls).forEach(function (k) {
      var L = legEls[k];
      L.li.classList.remove('done', 'active', 'st-warn', 'st-crit'); L.val.classList.add('pending'); L.main.nodeValue = '—'; L.small.textContent = 'not yet';
      L.what.textContent = L.defWhat;
    });
  }
  function legActive(id) { Object.keys(legEls).forEach(function (k) { legEls[k].li.classList.toggle('active', k === id); }); }
  function legSet(id, main, small, state) {
    var L = legEls[id]; L.val.classList.remove('pending'); L.main.nodeValue = main; L.small.textContent = small;
    L.li.classList.remove('st-warn', 'st-crit');
    if (state) { L.li.classList.add('done'); if (state === 'warn') L.li.classList.add('st-warn'); if (state === 'crit') L.li.classList.add('st-crit'); }
  }

  /** Box-timed legs (gateway / edge / edge+1): idle (and loaded) RTT from the core box. */
  function applyPath(p) {
    if (!p || !p.path) return;
    [['gw', 'gateway_ms', 5, 20], ['edge', 'edge_ms', 10, 40], ['edge1', 'edge1_ms', 40, 120]].forEach(function (x) {
      var h = p.path[x[1]]; if (!h || h.idle == null) return;
      var small = 'from box' + (h.loaded != null ? ' · loaded ' + fmtMs(h.loaded) + ' ms' : ' · idle');
      legSet(x[0], fmtMs(h.idle) + ' ms', small, grade(h.loaded != null ? h.loaded : h.idle, x[2], x[3]));
    });
  }
  function startPathPoll() {
    stopPathPoll();
    var sid = S.sess.session_id;
    var tick = function () {
      http('GET', API + '/sessions/' + sid + '/path', { headers: { 'X-Exp-View-Proof': S.proof }, timeout: 4000 }).then(function (r) {
        if (r.ok && r.body && S.sess && S.sess.session_id === sid) { S.path = r.body; applyPath(r.body); }
      }, function () {});
    };
    tick(); S.pathTimer = setInterval(tick, 500);
  }
  function stopPathPoll() { if (S.pathTimer) { clearInterval(S.pathTimer); S.pathTimer = null; } }

  // ------------------------------------------------------------------------------------------------ config + branding
  function luminance(hexColor) {
    var c = [1, 3, 5].map(function (i) { var v = parseInt(hexColor.substr(i, 2), 16) / 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); });
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
  }
  function applyBranding(cfg) {
    document.title = cfg.title || 'Speed check'; $('title').textContent = cfg.title || 'Speed check';
    var copy = cfg.copy || {};
    if (typeof copy.subtitle === 'string') $('subtitle').textContent = copy.subtitle;
    if (typeof copy.start_button === 'string') $('goSub').textContent = copy.start_button;
    if (typeof copy.footer === 'string') $('footer').textContent = copy.footer;
    var p = cfg.colors && cfg.colors.primary;
    if (typeof p === 'string' && /^#[0-9a-fA-F]{6}$/.test(p)) {
      var root = document.documentElement.style, l = luminance(p);
      root.setProperty('--brand', p); root.setProperty('--on-brand', l > 0.3 ? '#0B0D12' : '#FFFFFF');
    }
    if (typeof cfg.logo === 'string' && /^\/st\/assets\/[a-z0-9._-]{1,64}$/.test(cfg.logo)) {
      var img = el('img'); img.alt = ''; img.src = cfg.logo; img.addEventListener('error', function () { img.remove(); $('mark').firstChild && ($('mark').firstChild.style.display = ''); });
      var m = $('mark'); if (m.firstChild) m.firstChild.style.display = 'none'; m.appendChild(img);
    }
    $('cText').textContent = (cfg.consent && cfg.consent.text) || '';
  }
  async function loadConfig() {
    var r = await retrying(function () { return http('GET', API + '/config'); }, 3);
    if (!r || !r.ok || !r.body) throw new Error('config');
    S.cfg = r.body; applyBranding(r.body); $('go').disabled = false;
    return r.body;
  }
  function zoneHintFromUrl() {
    try { var z = new URLSearchParams(location.search).get('z'); return z && /^[a-z0-9][a-z0-9-]{0,63}$/.test(z) ? z : null; } catch (e) { return null; }
  }
  function zoneChip(name) {
    var c = $('zoneChip'); if (!name) { c.hidden = true; return; }
    $('zoneChipText').textContent = name; c.hidden = false;
  }
  async function loadWhere() {
    var path = API + '/where' + (S.zoneHint ? '?z=' + encodeURIComponent(S.zoneHint) : '');
    try {
      var r = await http('GET', path, { timeout: 5000 });
      if (r.ok && r.body && r.body.zone_name && r.body.source !== 'unresolved') zoneChip(r.body.zone_name);
    } catch (e) { /* best effort */ }
  }

  // ------------------------------------------------------------------------------------------------ session
  function checkCancel() { if (S.cancelled) { var e = new Error('cancelled'); e.cancelled = true; throw e; } }
  async function createSession() {
    var k = b64url(randomBytes(32));
    S.key = k; S.proof = viewProof(k);
    var body = { consent: { text_version: S.cfg.consent.version }, view_verifier: viewVerifier(S.proof) };
    if (S.zoneHint) body.zone_hint = S.zoneHint;
    var r = await http('POST', API + '/sessions', { json: body, timeout: 10000 });
    if (r.status === 201 && r.body) return r.body;
    var code = errCode(r), err = new Error(code || 'session');
    err.status = r.status; err.retryAfter = r.retryAfter; err.code = code;
    throw err;
  }
  function sessionErrorText(e) {
    if (e.status === 429) return 'The test box is busy or you ran several tests in a row. Try again' + (e.retryAfter ? ' in about ' + e.retryAfter + ' seconds.' : ' in a minute.');
    if (e.code === 'consent_version_stale') return 'The consent text changed. Reload the page and start again.';
    if (e.status === 0 || e.name === 'TypeError' || e.name === 'AbortError') return 'Could not reach the test box. Check that you are on the event network.';
    return 'The test could not start (' + (e.code || e.status || 'error') + '). Try again in a moment.';
  }
  function legHeaders() { return { 'X-Exp-Leg-Token': S.sess.leg_token }; }

  // ------------------------------------------------------------------------------------------------ on-network latency
  async function pingOnce(n) {
    var t = now();
    var r = await http('GET', '/st/ping?n=' + n, { headers: legHeaders(), timeout: 5000, signal: S.ac && S.ac.signal, raw: true });
    if (r.status !== 204) { var e = new Error('ping ' + r.status); e.status = r.status; throw e; }
    return now() - t;
  }
  async function pingSeries(count, onSample) {
    var out = [];
    await pingOnce(0);                                   // warm-up: the connection is open and warm for the 20 measured pings
    for (var i = 1; i <= count; i++) {
      checkCancel(); var v = await pingOnce(i); out.push(v); if (onSample) onSample(v, out);
    }
    return out;
  }

  // ------------------------------------------------------------------------------------------------ DNS leg
  async function dnsOne(name, nonce) {
    var url = location.protocol + '//' + nonce + '.' + name + (location.port ? ':' + location.port : '') + '/st/px?n=' + nonce + '&t=' + Math.floor(Math.random() * 1e9);
    var ac = new AbortController(), timer = setTimeout(function () { ac.abort(); }, 2500);
    try {
      var r = await fetch(url, { mode: 'cors', cache: 'no-store', credentials: 'omit', signal: ac.signal });
      if (r.status !== 204 && r.status !== 200) return null;
    } catch (e) { return null; } finally { clearTimeout(timer); }
    for (var i = 0; i < 12; i++) {
      var ents = performance.getEntriesByName(url);
      if (ents.length) {
        var e0 = ents[ents.length - 1];
        if (typeof e0.domainLookupStart === 'number' && typeof e0.domainLookupEnd === 'number' && e0.domainLookupEnd >= e0.domainLookupStart && (e0.domainLookupEnd > 0 || e0.fetchStart > 0)) {
          return e0.domainLookupEnd - e0.domainLookupStart;
        }
        return null;
      }
      await sleep(25);
    }
    return null;
  }
  /** 2 fresh nonces (cold) + the first repeated (warm), Resource Timing domainLookupEnd - domainLookupStart. */
  async function dnsLeg(sess) {
    var zone = sess.dns_zone, n = sess.dns_nonces || [];
    if (!zone || n.length < 2) return null;
    var c1 = await dnsOne(zone, n[0]);
    if (c1 == null) return { cold_ms: null, warm_ms: null };
    var c2 = await dnsOne(zone, n[1]);
    var warm = await dnsOne(zone, n[0]);
    var colds = [c1]; if (c2 != null) colds.push(c2);
    return { cold_ms: mean(colds), warm_ms: warm };
  }

  // ------------------------------------------------------------------------------------------------ on-network transfer
  var chunkBuf = null;
  function uploadBlob(size) {
    if (!chunkBuf) { chunkBuf = new Uint8Array(262144); for (var o = 0; o < chunkBuf.length; o += 65536) chunkBuf.set(randomBytes(65536), o); }
    var parts = [], left = size;
    while (left >= chunkBuf.length) { parts.push(chunkBuf); left -= chunkBuf.length; }
    if (left > 0) parts.push(chunkBuf.subarray(0, left));
    return new Blob(parts);
  }

  /**
   * One direction of the on-network leg: parallel streams (start 4, grow while throughput keeps rising, capped for
   * HTTP/1.1), request sizes ramping 100 kB -> ramp_max, ending when a request takes >= 1 s (ramp over) and enough samples
   * were gathered, after 8 s, or when the direction's byte budget is spent. Speed = p90 of 250-ms aggregate samples taken
   * after the ramp. Loaded latency is pinged on its own connection while this runs.
   */
  async function transferLeg(dir, budget) {
    var lim = S.sess.limits, startN = Math.max(1, lim.streams_start || 4), maxN = Math.min(lim.streams_max || 8, MAX_STREAMS_H1);
    var minB = 100000, maxB = Math.max(minB, Math.min(25000000, lim.ramp_max_bytes || 25000000));
    var T = { dir: dir, bytes: 0, used: 0, inflight: 0, size: minB, streams: 0, stop: false, rampAt: null, bins: [], failures: 0, t0: now(), last: 0, lastT: 0 };
    var ctrls = [], pings = [], pingStop = false;
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
      var r = await fetch('/st/down?bytes=' + size, { headers: legHeaders(), cache: 'no-store', credentials: 'omit', signal: ctrl.signal });
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
        x.setRequestHeader('X-Exp-Leg-Token', S.sess.leg_token);
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
      while (!T.stop && !S.cancelled) {
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
      while (!pingStop && !S.cancelled) { try { pings.push([now(), await pingOnce(900 + (i++))]); } catch (e) { /* token ended or aborted */ } await sleep(220); }
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
        T.bins.push({ t: el0, mbps: rate }); feedGauge(rate);
        // grow the stream count while the aggregate rate is still rising and the ramp is not over
        if (T.streams < maxN && T.rampAt == null && el0 - lastGrow > 500 && rate > prevRate * 1.1 && T.bins.length > 2) { workers.push(stream()); lastGrow = el0; }
        prevRate = rate;
        var after = T.bins.filter(function (b) { return b.t >= (T.rampAt != null ? T.rampAt : 1500); }).length;
        if (S.cancelled || el0 >= 8000 || T.streams === 0 || (T.rampAt != null && after >= 8)) { clearInterval(timer); resolve(); }
      }, 250);
    });
    T.stop = true; pingStop = true;
    // let small in-flight requests finish so the box's byte counters and ours agree; abort the rest
    var grace = now() + 1500;
    while (T.streams > 0 && now() < grace) await sleep(50);
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

  async function localLeg(sess) {
    var out = { status: 'ok' }, lim = sess.limits;
    // idle latency
    legActive('lan'); phase('Timing your Wi-Fi'); setSpeedMode(false); showMs(null);
    var idle = await pingSeries(Math.max(5, Math.min(20, lim.ping_count || 20)), function (v) { showMs(v); });
    out.idle_ms = median(idle); out.jitter_ms = jitterOf(idle);
    legSet('lan', fmtMs(out.idle_ms) + ' ms', 'idle', grade(out.idle_ms, 30, 100));
    // DNS
    legActive('dns'); phase('Timing name lookups'); showMs(null);
    var dns = null;
    try { dns = await dnsLeg(sess); } catch (e) { dns = null; }
    out.dns = dns;
    if (dns && dns.cold_ms != null) legSet('dns', fmtMs(dns.cold_ms) + ' ms', 'cached ' + fmtMs(dns.warm_ms) + ' ms', grade(dns.cold_ms, 80, 250));
    else legSet('dns', '—', 'measured by the hall sensor', null);
    // the box-timed path legs fill in from the poll; give the first snapshot a moment
    var started = now();
    ['gw', 'edge', 'edge1'].forEach(function (id) { legEls[id].what.textContent = legEls[id].defWhat; });
    legActive('gw'); phase('Timing the venue path'); showMs(null);
    while (now() - started < (reduced() ? 600 : 1500) && !(S.path && S.path.path && S.path.path.edge1_ms && S.path.path.edge1_ms.idle != null)) { checkCancel(); await sleep(100); }
    legActive(null);
    // throughput: down then up
    var budget = Math.max(200000, lim.bytes_local || 50000000), downB = Math.floor(budget * 0.6);
    setSpeedMode(true); loopOn(); legActive('lan');
    gaugeMode('down'); phase('On-network download', 'From the venue test box'); $('lgL').textContent = 'Download · live'; G.samples = []; G.target = 0;
    var d = await transferLeg('down', downB);
    checkCancel();
    out.down_mbps = d.mbps; out.loaded_down_ms = d.loaded_ms; out.bytes = d.bytes; var failures = d.failures, cvs = [d.cv];
    G.target = d.mbps; feedGauge(d.mbps);
    await sleep(reduced() ? 0 : 250);
    gaugeMode('up'); phase('On-network upload', 'To the venue test box'); $('lgL').textContent = 'Upload · live'; G.samples = []; G.target = 0;
    var u = await transferLeg('up', Math.max(200000, budget - d.bytes));
    checkCancel();
    out.up_mbps = u.mbps; out.loaded_up_ms = u.loaded_ms; out.bytes += u.bytes; failures += u.failures; cvs.push(u.cv);
    G.target = u.mbps; feedGauge(u.mbps);
    out.cv = Math.max(cvs[0] || 0, cvs[1] || 0); out.failures = failures;
    var worst = Math.max(out.loaded_down_ms || 0, out.loaded_up_ms || 0);
    legSet('lan', fmtMs(out.idle_ms) + ' ms', 'loaded ' + (worst ? fmtMs(worst) + ' ms' : 'n/a'), grade(worst || out.idle_ms, 100, 300));
    if (!(out.down_mbps > 0) && !(out.up_mbps > 0)) out.status = 'unavailable';
    return out;
  }

  // ------------------------------------------------------------------------------------------------ internet leg
  function internetPlan(budget) {
    var downTiers = [[1e5, 1, true], [1e5, 9], [1e6, 8], [1e7, 6], [25e6, 4]], upTiers = [[1e5, 8], [1e6, 6], [1e7, 4], [25e6, 3]];
    var meas = [{ type: 'latency', numPackets: 20 }];
    function fill(type, tiers, limit) {
      var cum = 0;
      for (var i = 0; i < tiers.length; i++) {
        var t = tiers[i], count = Math.min(t[1], Math.floor((limit - cum) / t[0]));
        if (count < 1) break;
        var m = { type: type, bytes: t[0], count: count }; if (t[2]) m.bypassMinDuration = true;
        meas.push(m); cum += t[0] * count;
        if (count < t[1]) break;
      }
    }
    fill('download', downTiers, Math.floor(budget * 0.55)); fill('upload', upTiers, Math.floor(budget * 0.4));
    return meas;
  }
  /** The colo is in the /cdn-cgi/trace BODY (not in __down headers, 12 section 4.2 / test/fixtures/cloudflare/README.md). */
  async function cloudflareTrace() {
    var ac = new AbortController(), timer = setTimeout(function () { ac.abort(); }, 4000);
    try {
      var r = await fetch(CF_BASE + '/cdn-cgi/trace', { mode: 'cors', cache: 'no-store', credentials: 'omit', signal: ac.signal });
      if (!r.ok) return null;
      var m = /^colo=([A-Za-z0-9]{1,8})$/m.exec((await r.text()).slice(0, 4096));
      return { colo: m ? m[1].toUpperCase() : '' };
    } catch (e) { return null; } finally { clearTimeout(timer); }
  }
  async function slotCall(action) {
    var r = await http('POST', API + '/sessions/' + S.sess.session_id + '/internet-slot', { json: { action: action }, headers: { 'X-Exp-View-Proof': S.proof }, timeout: 6000 });
    if (!r.ok || !r.body) { var e = new Error('slot'); e.status = r.status; throw e; }
    return r.body;
  }
  function reasonText(why) { return INTERNET_REASON[why] || 'The internet part of the test is not available right now.'; }
  async function internetLeg(sess) {
    var cfg = S.cfg;
    if (!cfg.internet_leg || !cfg.internet_leg.enabled || sess.internet_leg === 'unavailable') {
      legSet('cf', 'n/a', 'not enabled here', null); return { status: 'unavailable', note: reasonText('disabled') };
    }
    legActive('cf'); setSpeedMode(false); showMs(null);
    // 1. a slot, so a crowd of tests cannot flatten the venue WAN (12 section 4.4)
    var slot = await slotCall('acquire'), waitUntil = now() + 45000;
    while (slot.state === 'queued' && now() < waitUntil) {
      var txt = 'Waiting for a free internet slot' + (slot.queue_position ? ' — you are #' + slot.queue_position : '');
      phase(txt, 'Your on-network results are ready'); legSet('cf', '…', 'queued' + (slot.queue_position ? ' #' + slot.queue_position : ''), null); legEls.cf.li.classList.remove('done');
      await sleep(Math.max(500, (slot.retry_after_s || 2) * 1000)); checkCancel();
      slot = await slotCall('acquire');
    }
    if (slot.state === 'paused') { legSet('cf', 'paused', slot.reason === 'wan_utilization' ? 'venue link busy' : 'paused by the network team', null); return { status: 'paused', note: reasonText(slot.reason) }; }
    if (slot.state === 'unavailable') { legSet('cf', 'n/a', 'not enabled here', null); return { status: 'unavailable', note: reasonText(slot.reason || 'disabled') }; }
    if (slot.state !== 'granted') { legSet('cf', 'queued', 'no free slot', null); return { status: 'queued', note: reasonText('capacity') }; }
    S.slot = true;
    try {
      phase('Timing Cloudflare'); showMs(null);
      var trace = await cloudflareTrace();
      if (!trace) { legSet('cf', 'n/a', 'could not reach Cloudflare', 'crit'); return { status: 'unavailable', note: 'Cloudflare could not be reached from this network, so the internet speed was not measured.' }; }
      return await runCloudflare(trace.colo);
    } finally {
      if (S.slot) { S.slot = false; slotCall('release').catch(function () {}); }
    }
  }
  function runCloudflare(colo) {
    return new Promise(function (resolve) {
      var Engine = window.CFSpeedTest, sess = S.sess, errors = 0, firstErr = null, finished = false, curType = null, engine;
      var cfg = {
        autoStart: false, logAimApiUrl: null, logMeasurementApiUrl: null, includeCredentials: false,       // results stay on-prem
        measurements: internetPlan(sess.limits.bytes_internet || 200000000), abortTestDuration: 30000, bandwidthFinishRequestDuration: 1000
      };
      try { engine = new Engine(cfg); } catch (e) { legSet('cf', 'n/a', 'could not start', 'crit'); resolve({ status: 'unavailable', note: 'The internet test could not start.' }); return; }
      S.cf = engine;
      function finish() {
        if (finished) return; finished = true; S.cf = null;
        var R = engine.results, down = R.getDownloadBandwidth(), up = R.getUploadBandwidth();
        if (down == null && up == null) { legSet('cf', 'n/a', 'could not reach Cloudflare', 'crit'); resolve({ status: 'unavailable', note: 'Cloudflare could not be reached from this network, so the internet speed was not measured.', colo: colo }); return; }
        var dp = R.getDownloadBandwidthPoints() || [], upp = R.getUploadBandwidthPoints() || [];
        var bytes = 0, rates = [];
        dp.concat(upp).forEach(function (p) { bytes += (p.transferSize > 0 ? p.transferSize : p.bytes) || 0; rates.push(p.bps || 0); });
        var out = { status: 'ok', colo: colo, down_mbps: down == null ? null : down / 1e6, up_mbps: up == null ? null : up / 1e6,
          idle_ms: R.getUnloadedLatency(), jitter_ms: R.getUnloadedJitter(), loaded_down_ms: R.getDownLoadedLatency(), loaded_up_ms: R.getUpLoadedLatency(),
          cv: cv(rates), failures: errors, bytes: bytes };
        resolve(out);
      }
      engine.onPhaseChange = function (p) {
        var t = p.measurement && p.measurement.type, lbl = { latency: 'Timing Cloudflare ' + colo, download: 'Internet download', upload: 'Internet upload' }[t];
        if (t === curType) return; curType = t; if (!lbl) return;
        if (t === 'latency') { setSpeedMode(false); showMs(null); phase(lbl); }
        else { setSpeedMode(true); loopOn(); gaugeMode(t === 'upload' ? 'up' : 'down'); G.samples = []; G.target = 0; phase(lbl, (t === 'upload' ? 'To Cloudflare ' : 'From Cloudflare ') + colo); $('lgL').textContent = (t === 'upload' ? 'Upload' : 'Download') + ' · live'; }
      };
      engine.onResultsChange = function (p) {
        var R = engine.results;
        if (p.type === 'latency') { var pts = R.getUnloadedLatencyPoints(); if (pts.length) showMs(pts[pts.length - 1]); var idl = R.getUnloadedLatency(); if (idl != null) legSet('cf', fmtMs(idl) + ' ms', 'idle · ' + colo, grade(idl, 40, 120)); }
        else if (p.type === 'download' || p.type === 'upload') {
          var arr = p.type === 'download' ? R.getDownloadBandwidthPoints() : R.getUploadBandwidthPoints();
          if (arr && arr.length) feedGauge(arr[arr.length - 1].bps / 1e6);
        }
      };
      engine.onError = function (msg) { errors++; if (!firstErr) firstErr = msg; };
      engine.onFinish = function () { finish(); };
      engine.onRunningChange = function (running) { if (!running && !finished && engine.isFinished) finish(); };
      if (S.cancelled) { finish(); return; }
      engine.play();
      var guard = setInterval(function () { if (finished) { clearInterval(guard); } else if (S.cancelled) { try { engine.pause(); } catch (e) { /* ignore */ } clearInterval(guard); finish(); } }, 300);
    });
  }

  // ------------------------------------------------------------------------------------------------ run
  function numLeg(o) {
    var out = { status: o.status };
    if (o.status === 'ok') {
      var m = { down_mbps: 100000, up_mbps: 100000, idle_ms: 60000, jitter_ms: 60000, loaded_down_ms: 60000, loaded_up_ms: 60000 };
      Object.keys(m).forEach(function (k) { var v = clampNum(o[k], m[k]); if (v != null) out[k] = r2(v); });
      var worst = Math.max(out.loaded_down_ms || 0, out.loaded_up_ms || 0);
      if (worst > 0) out.rpm = Math.min(1000000, Math.round(60000 / worst));
      var c = clampNum(o.cv, 10); if (c != null) out.cv = r2(c);
      if (typeof o.failures === 'number') out.failures = Math.max(0, Math.min(10000, Math.round(o.failures)));
      if (typeof o.bytes === 'number') out.bytes = Math.max(0, Math.min(1099511627776, Math.round(o.bytes)));
    }
    if (o.colo && /^[A-Za-z0-9]{1,8}$/.test(o.colo)) out.colo = o.colo;
    return out;
  }
  function connectionHint() {
    try { var t = navigator.connection && navigator.connection.type; return ['wifi', 'ethernet', 'cellular', 'other'].indexOf(t) >= 0 ? t : 'unknown'; } catch (e) { return 'unknown'; }
  }
  function buildSubmission(local, inet, dns) {
    var sub = { schema: 'exp.speedtest.submission/1', legs: { local: numLeg(local) }, client: { connection_hint: connectionHint() },
      duration_ms: Math.max(0, Math.min(60000, Math.round(now() - S.t0))) };
    if (inet) sub.legs.internet = numLeg(inet);
    var dl = { source: 'browser' };
    if (dns && dns.cold_ms != null) dl.cold_ms = r1(clampNum(dns.cold_ms, 60000));
    if (dns && dns.warm_ms != null) dl.warm_ms = r1(clampNum(dns.warm_ms, 60000));
    sub.legs.dns = dl;
    if (S.zoneHint) sub.zone_hint = S.zoneHint;
    return sub;
  }
  async function submitResult(sub) {
    var sid = S.sess.session_id, hdr = { 'X-Exp-View-Proof': S.proof };
    for (var i = 0; i < 3; i++) {
      var r;
      try { r = await http('POST', API + '/sessions/' + sid + '/result', { json: sub, headers: hdr, timeout: 12000 }); }
      catch (e) { await sleep(800 * (i + 1)); continue; }
      if (r.status === 202 && r.body) return r.body;
      if (r.status === 409 && errCode(r) === 'already_submitted') return null;
      if (r.status === 503 && r.retryAfter && i < 2) { await sleep(Math.min(5000, r.retryAfter * 1000)); continue; }
      if (r.status >= 500 || r.status === 0) { await sleep(800 * (i + 1)); continue; }
      var err = new Error(errCode(r) || 'submit'); err.status = r.status; throw err;
    }
    throw new Error('submit');
  }
  function resetRun() {
    legReset(); G.shown = G.target = 0; G.samples = []; trace(); G.mode = 'text';
    $('results').hidden = true; S.animated = false; S.view = null; S.result = null; S.path = null; S.report = ''; S.zoneFix = ''; S.note = '';
    $('scoreArc').setAttribute('stroke-dashoffset', String(SCORE_ARC)); $('scoreN').textContent = '0';
    $('report').hidden = true; $('zonefix').hidden = true; $('rText').value = ''; $('zText').value = ''; $('rDone').textContent = ''; $('zDone').textContent = ''; $('copyStat').textContent = '';
    $('reportBtn').setAttribute('aria-expanded', 'false'); $('fixZone').setAttribute('aria-expanded', 'false');
    notice('');
  }
  async function acquireWake() {
    try { if (window.isSecureContext && navigator.wakeLock) S.wake = await navigator.wakeLock.request('screen'); } catch (e) { S.wake = null; }
  }
  function releaseWake() { try { if (S.wake) S.wake.release(); } catch (e) { /* ignore */ } S.wake = null; }
  function idleUi() {
    S.running = false; loopOff(); releaseWake(); stopPathPoll(); legActive(null);
    $('stage').classList.remove('running'); $('cancel').hidden = true; $('spinner').hidden = true;
    setTimeout(function () { if (!S.running) { $('go').hidden = false; $('live').hidden = true; } }, reduced() ? 0 : 900);
  }
  async function runTest() {
    if (S.running) return;
    S.running = true; S.cancelled = false; S.ac = new AbortController(); S.t0 = now(); S.measured = null;
    resetRun();
    $('go').hidden = true; $('live').hidden = false; $('cancel').hidden = false; $('stage').classList.add('running'); phase('Starting…');
    $('lgL').textContent = 'Live throughput'; $('lgR').textContent = '';
    G.mode = 'text'; showMs(null); $('spinner').hidden = false;
    acquireWake();
    try {
      try { S.sess = await createSession(); }
      catch (e) { notice(sessionErrorText(e), true); phase('Test not started'); idleUi(); return; }
      startPathPoll();
      var local = await localLeg(S.sess);
      checkCancel();
      var inet = await internetLeg(S.sess);
      checkCancel();
      // one last box path snapshot so the loaded figures are in
      try { var pr = await http('GET', API + '/sessions/' + S.sess.session_id + '/path', { headers: { 'X-Exp-View-Proof': S.proof }, timeout: 3000 }); if (pr.ok && pr.body) { S.path = pr.body; applyPath(pr.body); } } catch (e) { /* ignore */ }
      stopPathPoll();
      var cfLoaded = inet && inet.status === 'ok' ? Math.max(inet.loaded_down_ms || 0, inet.loaded_up_ms || 0) : 0;
      if (inet && inet.status === 'ok') legSet('cf', fmtMs(inet.idle_ms) + ' ms', 'loaded ' + (cfLoaded ? fmtMs(cfLoaded) + ' ms' : 'n/a') + ' · ' + (inet.colo || ''), grade(cfLoaded || inet.idle_ms, 100, 300));
      S.measured = { local: local, inet: inet, dns: local.dns };
      phase('Sending your result…'); setSpeedMode(false); showMs(null);
      var acc = await submitResult(buildSubmission(local, S.cfg.internet_leg.enabled ? inet : null, local.dns));
      phase('Done');
      S.result = acc;
      idleUi();
      showResultsFromRun(acc);
      pollView();
    } catch (e) {
      if (e && e.cancelled) { phase('Test stopped', 'Nothing was sent.'); notice('Test stopped. Nothing was sent.'); }
      else { phase('Test stopped'); notice('Something went wrong while testing (' + (e && e.message || 'error') + '). Try again.', true); }
      releaseSlotQuiet(); idleUi();
    }
  }
  function releaseSlotQuiet() { if (S.slot && S.sess) { S.slot = false; slotCall('release').catch(function () {}); } }
  function cancelTest() {
    S.cancelled = true; try { if (S.ac) S.ac.abort(); } catch (e) { /* ignore */ } try { if (S.cf) S.cf.pause(); } catch (e) { /* ignore */ }
  }

  // ------------------------------------------------------------------------------------------------ results
  function bestLeg(legs) {
    var i = legs && legs.internet, l = legs && legs.local;
    return (i && i.status === 'ok' && (i.down_mbps != null || i.up_mbps != null)) ? i : l;
  }
  function verdictFor(score, leg, tg) {
    if (score == null) return 'We could not measure a speed this time.';
    var t = score.total, base = t >= 80 ? 'Great for video calls and streaming.' : t >= 60 ? 'Good for everyday use; some things may feel slow.' : t >= 40 ? 'Usable, but video calls may struggle.' : 'Your connection is struggling right now.';
    if (t >= 60 && leg && leg.up_mbps != null && leg.up_mbps < tg.up_mbps) base += ' Big uploads are slower right now.';
    return base;
  }
  function goodFor(leg, tg) {
    if (!leg) return [];
    var d = leg.down_mbps, u = leg.up_mbps, lat = Math.max(leg.loaded_down_ms || 0, leg.loaded_up_ms || 0) || leg.idle_ms || 0;
    function lvl(good, mid) { return good ? 'ok' : (mid ? 'mid' : 'bad'); }
    return [['Video calls', lvl(d >= 5 && u >= 3 && lat <= 150, d >= 2 && u >= 1 && lat <= 300)], ['HD streaming', lvl(d >= 10, d >= 5)],
      ['Web and email', lvl(d >= 2 && (leg.idle_ms || 0) < 200, d >= 0.5)], ['Large uploads', lvl(u >= Math.max(10, tg.up_mbps), u >= 3)]];
  }
  function renderSpeeds(r, animate) {
    var legs = r.legs || {}, loc = legs.local || {}, inet = legs.internet || {};
    var tiles = [['Local down', loc, 'down_mbps', 'down'], ['Local up', loc, 'up_mbps', 'up'], ['Internet down', inet, 'down_mbps', 'down'], ['Internet up', inet, 'up_mbps', 'up']];
    var maxv = Math.max.apply(null, tiles.map(function (t) { return t[1][t[2]] || 0; }).concat([1]));
    var sp = $('speeds'); clear(sp);
    tiles.forEach(function (t) {
      var c = el('div', 'sp'), v = t[1][t[2]];
      c.appendChild(el('span', 'k', t[0]));
      var val = el('span', 'v', v == null ? '—' : fmtMbps(v)); if (v != null) val.appendChild(el('small', '', 'Mb/s')); c.appendChild(val);
      var bar = el('div', 'bar'), i = el('i', t[3]); bar.appendChild(i); c.appendChild(bar);
      if (v == null && t[1].status && t[1].status !== 'ok') c.appendChild(el('span', 'note', { paused: 'Paused by the network', queued: 'No free slot', unavailable: 'Not available', skipped: 'Skipped' }[t[1].status] || ''));
      sp.appendChild(c);
      var f = v ? Math.max(0.03, v / maxv) : 0;
      if (animate && !reduced()) { requestAnimationFrame(function () { requestAnimationFrame(function () { i.style.transform = 'scaleX(' + f.toFixed(3) + ')'; }); }); } else i.style.transform = 'scaleX(' + f.toFixed(3) + ')';
    });
  }
  function renderWaterfall(r, fine, animate) {
    var legs = r.legs || {}, loc = legs.local || {}, inet = legs.internet || {}, p = legs.path || (S.path && S.path.path) || null;
    var wf = $('wf'), key = $('wfKey'), note = $('wfNote'); clear(wf); clear(key);
    $('colo').textContent = inet.server && /^cloudflare:[A-Z0-9]{1,8}$/.test(inet.server) ? inet.server.slice(11) : (S.measured && S.measured.inet && S.measured.inet.colo || '');
    var lan = loc.idle_ms, cf = inet.status === 'ok' ? inet.idle_ms : null, segs = [];
    if (lan != null && cf != null) {
      var gw = p && p.gateway_ms && p.gateway_ms.idle, ed = p && p.edge_ms && p.edge_ms.idle, e1 = p && p.edge1_ms && p.edge1_ms.idle;
      if (fine && gw != null && ed != null && e1 != null) {
        segs = [['Wi-Fi and venue network', lan], ['core to gateway', gw], ['gateway to edge', Math.max(0.2, ed - gw)], ['edge to ISP first hop', Math.max(0.2, e1 - ed)],
          ['internet to Cloudflare', Math.max(0.5, cf - lan - e1)]];
      } else segs = [['On the venue network', lan], ['Beyond the venue, to Cloudflare', Math.max(0.5, cf - lan)]];
      note.textContent = fine ? 'An estimate: your own measurements plus the venue’s timings from the test box, which are shared by everyone and not specific to you.' : 'An estimate. It fills in with more detail when the network team’s measurements for your device arrive.';
    } else { note.textContent = 'Not available: it needs both the on-network and the internet legs.'; }
    segs.forEach(function (s, i) {
      var span = el('span', 'c' + i, s[1] >= 4 ? s[1].toFixed(0) : ''); wf.appendChild(span);
      var grow = function () { span.style.flexGrow = String(s[1]); };
      if (animate && !reduced()) requestAnimationFrame(function () { requestAnimationFrame(grow); }); else grow();
      var k = el('span'), sw = el('i', 'sw c' + i); k.appendChild(sw); k.appendChild(document.createTextNode(s[0] + ' ')); k.appendChild(el('b', '', s[1].toFixed(1) + ' ms')); key.appendChild(k);
    });
    wf.setAttribute('aria-label', segs.length ? 'Estimated time to Cloudflare by segment: ' + segs.map(function (s) { return s[0] + ' ' + s[1].toFixed(1) + ' ms'; }).join(', ') : 'Not available');
  }
  function renderChecks(view) {
    var ul = $('checks'); clear(ul);
    var ev = view && view.evidence ? view.evidence.state : 'pending', got = (view && view.checks) || [], seen = {};
    function row(kind, state, text) {
      var li = el('li'), ic = el('span', 'ic ' + (state === 'checking' ? 'wait' : state === 'ok' ? 'ok' : state === 'attention' ? 'attention' : 'na'));
      ic.appendChild(icon(state === 'checking' ? 'spin' : state === 'ok' ? 'check' : state === 'attention' ? 'bang' : 'dash')); li.appendChild(ic);
      var body = el('div'); body.appendChild(el('b', '', CHECK_LABELS[kind] || 'Check'));
      body.appendChild(document.createTextNode(' ')); body.appendChild(el('span', 'm', '— ' + (state === 'checking' ? 'checking…' : (text || { ok: 'nothing unusual', attention: 'worth a look', unavailable: 'not available here' }[state] || ''))));
      li.appendChild(body); ul.appendChild(li);
    }
    got.forEach(function (c) { if (c && CHECK_LABELS[c.kind] && !seen[c.kind]) { seen[c.kind] = 1; row(c.kind, c.state, c.text); } });
    if (ev === 'pending' || ev === 'correlating') DEFAULT_CHECKS.forEach(function (k) { if (!seen[k]) row(k, 'checking'); });
    else if (!got.length) row('baseline', 'unavailable', 'Detailed measurements are not available at this event; you only get the test above.');
  }
  function renderWhere(view) {
    var box = $('whereLine'); if (!view) { box.hidden = true; return; }
    var named = view.zone_name && view.zone_source !== 'unresolved';
    box.hidden = false; clear(box);
    var sp = el('span'); if (named) { sp.appendChild(document.createTextNode('You were in ')); sp.appendChild(el('b', '', view.zone_name)); } else sp.textContent = 'We could not tell where you were.';
    box.appendChild(sp);
    var b = el('button', 'linkbtn', named ? 'Not right?' : 'Tell us'); b.type = 'button'; b.id = 'fixZone'; b.setAttribute('aria-expanded', String(!$('zonefix').hidden)); b.setAttribute('aria-controls', 'zonefix');
    b.addEventListener('click', toggleZoneFix); box.appendChild(b);
    if (named) zoneChip(view.zone_name);
  }
  function renderNote(view) {
    var n = $('noteView'), c = view && typeof view.comment === 'string' && view.comment ? view.comment : (S.viewMode ? '' : S.note);
    n.hidden = !c; n.textContent = c ? 'Your note: ' + c : '';
  }
  function renderFlags(flags) {
    var notes = [], f = flags || [];
    if (f.indexOf('internet_paused') >= 0) notes.push('The internet part of the test was paused by the network team.');
    if (f.indexOf('internet_queued') >= 0) notes.push('The internet part of the test had to wait for a free slot and was skipped.');
    if (f.indexOf('internet_unavailable') >= 0) notes.push('The internet part of the test was not available.');
    if (f.indexOf('dns_fallback') >= 0) notes.push('Name-lookup timing is measured by the hall sensor, not by your device.');
    if (f.indexOf('nat_suspected') >= 0) notes.push('We could not be sure which device this was, so the network team will not match it to your Wi-Fi.');
    if (f.indexOf('bytes_capped') >= 0) notes.push('The test stopped early to protect the venue network.');
    $('flagNote').textContent = notes.join(' ');
  }
  /** Renders a result. `view` is a session view (or null while it is not known yet). Safe to call again with fresher data. */
  function showResults(r, view, diag, opt) {
    opt = opt || {};
    var first = !S.animated, animate = first && !opt.still, tg = S.cfg ? S.cfg.targets : { down_mbps: 25, up_mbps: 10 };
    $('results').hidden = false;
    var score = r.score;
    if (first) {
      S.animated = true;
      var go = function () { $('scoreArc').setAttribute('stroke-dashoffset', (SCORE_ARC * (1 - (score ? score.total : 0) / 100)).toFixed(1)); };
      if (animate && !reduced()) {
        requestAnimationFrame(function () { requestAnimationFrame(go); });
        var n = 0, tot = score ? score.total : 0, tick = setInterval(function () { n = Math.min(tot, n + 3); $('scoreN').textContent = String(n); if (n >= tot) clearInterval(tick); }, 30);
      } else { go(); $('scoreN').textContent = score ? String(score.total) : '—'; }
      if (!score) $('scoreN').textContent = '—';
    }
    var parts = $('parts'); clear(parts);
    if (score) [['Speed', score.speed], ['Responsiveness', score.responsiveness], ['Stability', score.stability]].forEach(function (x) { parts.appendChild(el('span', 'part', x[0] + ' ' + x[1])); });
    var leg = bestLeg(r.legs);
    $('verdict').textContent = verdictFor(score, leg, tg);
    $('why').textContent = diag && diag.user_text ? diag.user_text : (opt.viewOnly ? '' : 'The network team is looking at the venue side of your test.');
    renderFlags(r.flags);
    renderSpeeds(r, first && animate);
    var fine = !!(view && view.evidence && view.evidence.state !== 'pending');
    renderWaterfall(r, fine, first && animate);
    var gf = $('goodFor'); clear(gf);
    goodFor(leg, tg).forEach(function (x) { var d = el('div', 'gf'); d.appendChild(icon(x[1] === 'ok' ? 'check' : x[1] === 'mid' ? 'dash' : 'cross', x[1])); d.appendChild(document.createTextNode(x[0])); gf.appendChild(d); });
    renderChecks(view); renderWhere(view); renderNote(view);
    var dnsLeg = r.legs && r.legs.dns;
    if (dnsLeg && dnsLeg.source === 'probe') legSet('dns', dnsLeg.cold_ms != null ? fmtMs(dnsLeg.cold_ms) + ' ms' : '—', 'measured by the hall sensor', null);
    if (first && !S.viewMode && window.innerWidth < 900) setTimeout(function () { $('results').scrollIntoView({ behavior: reduced() ? 'auto' : 'smooth', block: 'start' }); }, reduced() ? 0 : 400);
    $('announce').textContent = 'Test complete.' + (score ? ' Score ' + score.total + ' out of 100.' : '');
  }
  function resultFromRun(acc) {
    var m = S.measured, legs = { local: numLeg(m.local) };
    if (m.inet) legs.internet = numLeg(m.inet);
    var dl = m.dns && m.dns.cold_ms != null ? { cold_ms: m.dns.cold_ms, warm_ms: m.dns.warm_ms, source: 'browser' } : { cold_ms: null, warm_ms: null, source: 'probe' };
    legs.dns = dl; if (S.path && S.path.path) legs.path = S.path.path;
    if (m.inet && m.inet.colo) { legs.internet.server = 'cloudflare:' + m.inet.colo; }
    return { legs: legs, score: acc ? acc.score : null, flags: acc ? acc.flags : [] };
  }
  function showResultsFromRun(acc) {
    var shareId = S.sess.session_id;
    S.shareId = shareId;
    var r = acc ? resultFromRun(acc) : resultFromRun(null);
    S.result = r;
    var link = location.origin + '/st/r/' + shareId + '#k=' + S.key;
    $('shareLink').textContent = link;
    var minimalView = { evidence: { state: 'pending', kinds_done: [] }, checks: [], zone_name: null, zone_source: 'unresolved' };
    showResults(r, minimalView, acc && acc.diagnosis, {});
    $('whereLine').hidden = true;
    var inet = S.measured.inet;
    if (inet && inet.status !== 'ok' && inet.note) notice(inet.note);
  }
  async function pollView() {
    var sid = S.sess.session_id, t0 = now(), delay = 1500;
    if (S.pollTimer) clearTimeout(S.pollTimer);
    var step = async function () {
      if (!S.sess || S.sess.session_id !== sid || S.running) return;
      try {
        var r = await http('GET', API + '/sessions/' + sid, { headers: { 'X-Exp-View-Proof': S.proof }, timeout: 6000 });
        if (r.ok && r.body) {
          S.view = r.body;
          var res = r.body.result || S.result;
          showResults(res, r.body, r.body.diagnosis, {});
          if (r.body.evidence && (r.body.evidence.state === 'final' || r.body.evidence.state === 'unavailable')) return;
        }
      } catch (e) { /* keep polling */ }
      if (now() - t0 > 6 * 60 * 1000) return;
      delay = Math.min(5000, delay + 500); S.pollTimer = setTimeout(step, delay);
    };
    S.pollTimer = setTimeout(step, 800);
  }
  // ------------------------------------------------------------------------------------------------ report / correct / share
  async function postComment() {
    var parts = [];
    if (S.zoneFix) parts.push('[where I was] ' + S.zoneFix);
    if (S.report) parts.push(S.report);
    var text = cleanText(parts.join('\n'), 500);
    if (!text || !S.sess) return false;
    var r = await http('POST', API + '/sessions/' + S.sess.session_id + '/comment', { json: { comment: text }, headers: { 'X-Exp-View-Proof': S.proof }, timeout: 8000, raw: true });
    if (r.status === 204) { S.note = text; renderNote({ comment: text }); return true; }
    return false;
  }
  function toggleZoneFix() {
    var f = $('zonefix'); f.hidden = !f.hidden; $('fixZone') && $('fixZone').setAttribute('aria-expanded', String(!f.hidden)); if (!f.hidden) $('zText').focus();
  }
  function selectLink() {
    try { var r = document.createRange(); r.selectNodeContents($('shareLink')); var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); return true; } catch (e) { return false; }
  }
  async function copyLink() {
    var text = $('shareLink').textContent, stat = $('copyStat');
    if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
      try { await navigator.clipboard.writeText(text); stat.textContent = 'Link copied.'; return; } catch (e) { /* fall through to select-the-code */ }
    }
    selectLink();
    var ok = false; try { ok = document.execCommand && document.execCommand('copy'); } catch (e) { ok = false; }
    stat.textContent = ok ? 'Link copied.' : 'Link selected: press and hold, then choose Copy.';
  }

  // ------------------------------------------------------------------------------------------------ shared result view
  async function loadShared(id, k) {
    S.viewMode = true; document.body.classList.add('shared-only');
    $('again').textContent = 'Run your own test'; $('shareBox').hidden = true; $('reportBtn').hidden = true; $('fixZone').hidden = true;
    try { S.key = k; S.proof = viewProof(k); } catch (e) { sharedError(); return; }
    S.sess = { session_id: id }; S.shareId = id;
    var r = await retrying(function () { return http('GET', API + '/sessions/' + id, { headers: { 'X-Exp-View-Proof': S.proof } }); }, 3);
    if (!r || !r.ok || !r.body) { sharedError(); return; }
    S.view = r.body; S.measured = { inet: null };
    var res = r.body.result || { legs: {}, score: null, flags: [] };
    showResults(res, r.body, r.body.diagnosis, { still: true, viewOnly: true });
    $('whereLine').querySelectorAll('button').forEach(function (b) { b.hidden = true; });
    var again = function () {
      if (!S.sess || S.sess.session_id !== id) return;
      http('GET', API + '/sessions/' + id, { headers: { 'X-Exp-View-Proof': S.proof } }).then(function (q) {
        if (q.ok && q.body) { S.view = q.body; showResults(q.body.result || res, q.body, q.body.diagnosis, { still: true, viewOnly: true }); $('whereLine').querySelectorAll('button').forEach(function (b) { b.hidden = true; });
          if (q.body.evidence && (q.body.evidence.state === 'final' || q.body.evidence.state === 'unavailable')) return; }
        S.pollTimer = setTimeout(again, 5000);
      }, function () { S.pollTimer = setTimeout(again, 8000); });
    };
    if (!r.body.evidence || (r.body.evidence.state !== 'final' && r.body.evidence.state !== 'unavailable')) S.pollTimer = setTimeout(again, 4000);
  }
  function sharedError() {
    $('results').hidden = true; var st = $('stage'); document.body.classList.remove('shared-only');
    ['.gauge', '.trace', '.legend', '.phase'].forEach(function (q) { st.querySelector(q).hidden = true; }); document.querySelector('.legs').hidden = true;
    notice('This link is not valid or the test is no longer stored. Ask the person who shared it for a new one, or run your own test.', true);
    var b = el('button', 'btn primary', 'Run your own test'); b.type = 'button'; b.addEventListener('click', function () { location.assign('/'); });
    st.querySelector('.ctrl').appendChild(b);
  }

  // ------------------------------------------------------------------------------------------------ wiring
  function onGo() {
    if (S.running) return;
    var v = String(S.cfg && S.cfg.consent && S.cfg.consent.version);
    if (safeStorage('get', 'exp-st-consent') === v) { runTest(); return; }
    $('consent').hidden = false; $('cAnon').focus();
  }
  function init() {
    buildTicks(); buildLegs(); S.zoneHint = zoneHintFromUrl();
    $('go').addEventListener('click', onGo);
    $('cAnon').addEventListener('click', function () { $('consent').hidden = true; safeStorage('set', 'exp-st-consent', String(S.cfg.consent.version)); runTest(); });
    $('cCancel').addEventListener('click', function () { $('consent').hidden = true; $('go').focus(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !$('consent').hidden) { $('consent').hidden = true; $('go').focus(); } });
    $('cancel').addEventListener('click', cancelTest);
    $('again').addEventListener('click', function () { if (S.viewMode) { location.assign('/'); return; } window.scrollTo({ top: 0, behavior: reduced() ? 'auto' : 'smooth' }); runTest(); });
    $('reportBtn').addEventListener('click', function () { var r = $('report'); r.hidden = !r.hidden; $('reportBtn').setAttribute('aria-expanded', String(!r.hidden)); if (!r.hidden) $('rText').focus(); });
    $('report').addEventListener('submit', async function (e) {
      e.preventDefault(); var t = cleanText($('rText').value, 500).trim();
      if (!t) { $('rDone').textContent = 'Add a few words first.'; return; }
      S.report = t;
      try { $('rDone').textContent = (await postComment()) ? 'Saved with your test.' : 'Could not save it. Try again.'; } catch (err) { $('rDone').textContent = 'Could not save it. Try again.'; }
    });
    $('zonefix').addEventListener('submit', async function (e) {
      e.preventDefault(); var t = cleanText($('zText').value, 120).trim();
      if (!t) { $('zDone').textContent = 'Say where you were first.'; return; }
      S.zoneFix = t;
      try { $('zDone').textContent = (await postComment()) ? 'Thanks, the network team will see this.' : 'Could not save it. Try again.'; } catch (err) { $('zDone').textContent = 'Could not save it. Try again.'; }
    });
    $('copy').addEventListener('click', copyLink);
    $('shareLink').addEventListener('focus', selectLink);
    var m = /^\/st\/r\/(st_[0-9A-HJKMNP-TV-Z]{26})\/?$/.exec(location.pathname), km = /^#k=([A-Za-z0-9_-]{43})$/.exec(location.hash);
    loadConfig().then(function () {
      if (m) { if (km) loadShared(m[1], km[1]); else { S.viewMode = true; document.body.classList.add('shared-only'); sharedError(); } }
      else loadWhere();
    }, function () { notice('Could not load the test page settings. Reload to try again.', true); $('go').disabled = true; });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
