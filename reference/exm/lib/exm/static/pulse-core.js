/* EXM Pulse core: the rules behind the board, without the DOM.
 *
 * Loaded by the page and by node in the tests. lib/exm/pulse.py is the same rules
 * in Python for the alerter; test/parity.sh checks the two agree on real results.
 * Events are the compact form served by /api/history and /events (web.compact()).
 */
(function (root) {
  'use strict';
  const LANES = ['Network', 'DHCP', 'DNS', 'Internet', 'Wi-Fi'];
  // Network, DHCP, DNS and Wi-Fi beat every 10 s (heartbeats); the internet line is app checks, ~every 30 s.
  const CADENCE = [10000, 10000, 10000, 40000, 10000];           // expected gap between beats on each line
  const STATE_WINDOW = [30000, 30000, 30000, 120000, 30000];     // how far back the answer looks
  const RECENT = 60000;                                          // a diagnostic result older than this says nothing about now
  const TRACE_HOLD = 30000;                                      // a path is dead only if none of its traces got through in this long
  const ms = (iso) => Date.parse(iso);
  const cls = (o) => (o === 'ok' ? 'ok' : o === 'degraded' ? 'slow' : (o === 'fail' || o === 'portal') ? 'fail' : null);
  const findLast = (a, f) => { for (let i = a.length - 1; i >= 0; i--) if (f(a[i])) return a[i]; return null; };

  // One beat per result; app results from one client run collapse into one beat.
  function beats(pool, lane) {
    const evs = pool.filter((e) => e.l === lane);
    if (lane !== 3) return evs.map((e) => ({ t: ms(e.w), o: cls(e.o), items: [e] })).filter((b) => b.o);
    const out = [], open = {};
    for (const e of evs) {
      const t = ms(e.w);
      if (e.k === 'speedtest') { out.push({ t, items: [e] }); continue; }
      const g = open[e.c];
      if (g && t - g.t < 30000) { g.items.push(e); g.t = t; }
      else { const ng = { t, items: [e] }; open[e.c] = ng; out.push(ng); }
    }
    for (const g of out) {
      const k = g.items.map((e) => cls(e.o)).filter(Boolean);
      const f = k.filter((x) => x === 'fail').length;
      g.o = !k.length ? null : (f * 2 >= k.length ? 'fail' : (f || k.includes('slow')) ? 'slow' : 'ok');
    }
    return out.filter((b) => b.o).sort((a, b) => a.t - b.t);
  }

  // A line is failing when half or more of its recent beats failed, partly working when any failed
  // (or, for the internet and Wi-Fi, a third were slow), and unknown when nothing arrived.
  function stateOf(bs, lane, t, items) {
    const r = bs.filter((b) => b.t <= t && t - b.t <= STATE_WINDOW[lane]);
    if (!r.length) return { s: 'unk', n: 0, f: 0, d: 0 };
    const f = r.filter((b) => b.o === 'fail').length, d = r.filter((b) => b.o === 'slow').length;
    let s = 'ok';
    if (f * 2 >= r.length) s = 'fail';
    else if (f || (lane < 3 ? d : d * 3 >= r.length)) s = 'warn';
    const st = { s, n: r.length, f, d };
    if (items) {           // count individual results, not beats, for the sentence
      const all = r.flatMap((b) => b.items);
      st.items = all.length;
      st.itemFails = all.filter((e) => cls(e.o) === 'fail').length;
      st.itemSlow = all.filter((e) => cls(e.o) === 'slow').length;
    }
    return st;
  }

  // When the current problem began: the earliest bad beat since the last three good ones in a row.
  // For a failure only failed beats count as bad, so a slow one just before it doesn't pull the time back.
  // open: the loaded results ran out before three good ones in a row, so the start is older than we can see.
  function sinceOf(bs, failsOnly) {
    let okRun = 0, earliest = null, found = false;
    for (let i = bs.length - 1; i >= 0; i--) {
      const bad = failsOnly ? bs[i].o === 'fail' : bs[i].o !== 'ok';
      if (!bad) { if (++okRun >= 3) { found = true; break; } }
      else { okRun = 0; earliest = bs[i].t; }
    }
    return { t: earliest, open: earliest !== null && !found };
  }

  // The line's state at each of its beats in [from, t].
  function series(bs, lane, from, t) {
    return bs.filter((b) => b.t >= from && b.t <= t).map((b) => ({ t: b.t, s: stateOf(bs, lane, b.t).s }));
  }

  // The newest failure on a line that has since ended, if it ended within `within` ms of t:
  // {start, end, open}. Null while the line is still failing, or if nothing failed.
  function lastOutage(bs, lane, t, within) {
    const ser = series(bs, lane, t - within, t);
    if (!ser.length || ser[ser.length - 1].s === 'fail') return null;
    let k = -1;
    for (let i = ser.length - 1; i >= 0; i--) if (ser[i].s === 'fail') { k = i; break; }
    if (k < 0) return null;
    const s = sinceOf(bs.filter((b) => b.t <= ser[k].t), true);
    return { start: s.t, end: ser[k + 1].t, open: s.open };
  }

  // How many times a line went into failure in the last `span` ms: three or more is flapping.
  function flaps(bs, lane, t, span) {
    const ser = series(bs, lane, t - span, t);
    let n = 0;
    for (let i = 1; i < ser.length; i++) if (ser[i].s === 'fail' && ser[i - 1].s !== 'fail') n++;
    return n;
  }

  // Where the fault is, from the signals around t. V: results up to t; st: line states at t.
  // Returns null when nothing is wrong, else {seg, ...facts}. The page and the alerter word it.
  //   link      ports have no link: a cable or the switch
  //   switch    wired can't reach the gateway, Wi-Fi can: the switch, its uplink or the VLAN
  //   gateway   neither wired nor Wi-Fi reach the gateway: the gateway or the link to it
  //   lan       wired can't reach the gateway (no Wi-Fi to compare)
  //   edge      past the gateway the ports' path dies, the control path gets out: the WAN edge
  //   isp       both paths die: upstream of the edge
  //   wan       the ports' path dies past the gateway (no control path to compare)
  //   resolver  the DHCP-given resolver is silent, the alternate answers
  //   dns_path  the path is up but no resolver answers
  //   apps      path and DNS fine, apps failing
  //   dhcp      the gateway answers, DHCP offers don't come
  //   ssid      the Wi-Fi laptop can't get on the network it monitors
  //   wifi      the laptop is on it but can't reach the gateway, while wired can
  function whereOf(V, t, st) {
    const bad = (i) => st[i] && (st[i].s === 'fail' || st[i].s === 'warn');
    if (![0, 1, 2, 3, 4].some(bad)) return null;
    const recent = (k) => findLast(V, (e) => e.k === k && t - ms(e.w) <= RECENT);
    const g = recent('gateway'), d = recent('dns_hb'), w = recent('wifi_hb');
    // A traceroute can lose its replies to rate limiting: one that got through recently outweighs one that didn't.
    const path = (k) => {
      const last = recent(k);
      if (!last || last.rc) return last;
      const ok = findLast(V, (e) => e.k === k && e.rc && t - ms(e.w) <= TRACE_HOLD);
      return ok ? Object.assign({}, last, { rc: true, dt: ok.dt }) : last;
    };
    let tr = path('trace');
    const tc = path('trace_ctl');
    // Both resolvers silent corroborate a failed traceroute: then an older success doesn't outweigh it.
    const rawTr = recent('trace');
    if (rawTr && !rawTr.rc && d && d.o === 'fail' && d.ao === false) tr = rawTr;
    const dh = findLast(V, (e) => e.k === 'dhcp_hb' && e.sv);
    const wOn = w && (!w.tg || w.sd === w.tg) && w.sd;
    if (bad(0) && g) {
      const nl = g.nl || [], ug = g.ug || [];
      if (nl.length && nl.length * 2 >= (g.n || 1)) return { seg: 'link', ports: nl, n: g.n };
      if (ug.length) {
        const ip = ug[0][0];
        if (wOn && w.gk) return { seg: 'switch', ip };
        if (wOn && !w.gk) return { seg: 'gateway', ip };
        return { seg: 'lan', ip };
      }
      if (nl.length) return { seg: 'link', ports: nl, n: g.n };
    }
    if ((bad(2) || bad(3)) && !(st[0] && st[0].s === 'fail')) {
      if (tr && !tr.rc) {
        if (tc && tc.rc) return { seg: 'edge', lh: tr.lh, lt: tr.lt, target: tr.g };
        if (tc && !tc.rc) return { seg: 'isp', lh: tr.lh, lt: tr.lt, clh: tc.lh, target: tr.g };
        return { seg: 'wan', lh: tr.lh, lt: tr.lt, target: tr.g };
      }
      if (bad(2) && d && d.o === 'fail') {
        if (d.ao) return { seg: 'resolver', sx: d.sx, ax: d.ax };
        if (tr && tr.rc) return { seg: 'dns_path', sx: d.sx, ax: d.ax };
      }
      if (bad(3) && !bad(2) && tr && tr.rc) return { seg: 'apps', target: tr.g };
    }
    if (bad(1) && !(st[0] && st[0].s === 'fail')) return { seg: 'dhcp', sv: dh ? dh.sv : null };
    if (bad(4) && w && [0, 1, 2, 3].every((i) => !bad(i))) {
      if (!wOn) return { seg: 'ssid', tg: w.tg, sd: w.sd };
      if (!w.gk) return { seg: 'wifi' };
    }
    return null;
  }

  // The path a client's traffic takes, and how each hop looks for a given segment verdict.
  // ok: known good; fail: the break; sus: one of these; unk: past the break, can't tell.
  const PATH = ['Ports', 'Switch', 'Gateway', 'EDGE', 'ISP', 'DNS', 'Apps'];
  const CHIPS = {
    link: 'fuuuuuu', switch: 'ofouuuu', gateway: 'oufuuuu', lan: 'ossuuuu', edge: 'ooofouu',
    isp: 'oooufuu', wan: 'ooossuu', resolver: 'ooooofu', dns_path: 'ooooofu', apps: 'oooooof',
  };
  function chips(seg) {
    const c = CHIPS[seg];
    if (!c) return null;
    const m = { o: 'ok', f: 'fail', s: 'sus', u: 'unk' };
    return PATH.map((name, i) => ({ name, s: m[c[i]] }));
  }

  const api = { LANES, CADENCE, STATE_WINDOW, RECENT, TRACE_HOLD, ms, cls, findLast, beats, stateOf, sinceOf, series, lastOutage, flaps, whereOf, chips };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.PulseCore = api;
})(typeof self !== 'undefined' ? self : this);
