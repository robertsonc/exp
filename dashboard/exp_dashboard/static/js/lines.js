// Site lines board (/site/<id>/lines, CR-site-lines-board). Renders exp.lines/1 from the collector: one line per
// network, one station per check, one train per probe port. Nothing here decides a state, groups a finding or writes a
// headline (decision D3); trains launch only when a real beat arrives (CR-heartbeat-cadence) and the motion between
// beats is interpolation. prefers-reduced-motion stops the trains, never the states.
import { api, qs, ApiError } from "./api.js";
import { h, clear } from "./dom.js";
import { Live } from "./stream.js";
import { fmtHMS, parseTs, toIso, debounce } from "./util.js";

const WINDOW_MS = 15 * 60 * 1000;
const REFRESH_MS = 15000;
const PIN_IDLE_MS = 120000;
const TRAIN_MS = 3400;
const BAD = new Set(["stopped", "confirming", "verifying"]);
const WORD = { stopped: "stopped", confirming: "confirming", verifying: "verifying" };

function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888"; }
function palette() {
  return { ok: css("--exp-ok"), okdim: css("--exp-green-lo"), stopped: css("--exp-fail"), confirming: css("--exp-warn"),
    verifying: css("--exp-accent"), hollow: css("--exp-warn"), untestable: css("--exp-unknown"), unknown: css("--exp-unknown"),
    na: css("--exp-stroke"), line: css("--exp-stroke"), text: css("--exp-text"), dim: css("--exp-text-dim"), bg: css("--exp-bg") };
}
const still = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

export function mountLines(root, opts) {
  const site = opts.site;
  const st = { doc: null, tl: null, at: null, pinnedAt: 0, error: "", trains: [], probes: new Set(), dead: false, seq: 0 };

  const el = {};
  const board = h("section", { class: "lines", "aria-label": "Site lines board", data: { phase: "ok", mode: "live" } });
  el.pinned = h("div", { class: "banner banner-info lines-pinned", role: "status", hidden: true },
    el.pinnedText = h("span"), h("button", { class: "btn", type: "button", text: "Back to live", on: { click: () => goLive() } }));
  el.chip = h("span", { class: "lines-chip", text: "OBSERVED" });
  el.h1 = h("h1", { class: "lines-h1", text: "Loading the board…" });
  el.sub = h("p", { class: "lines-sub" });
  el.map = h("canvas", { class: "lines-map", role: "img", "aria-label": "Line map: one line per network, one station per check" });
  el.side = h("div", { class: "lines-side" });
  el.rib = h("canvas", { class: "lines-ribbon", role: "img", "aria-label": "Last 15 minutes: one ribbon per network. Click a moment to look at it." });
  el.ribNote = h("p", { class: "sub lines-ribnote", text: "A swell is a fault; its thickness is the share of the network's ports affected. Click a moment to look back at it." });
  el.err = h("p", { class: "banner banner-fail", role: "alert", hidden: true });
  board.append(el.pinned, el.err,
    h("header", { class: "lines-head" }, el.chip, el.h1, el.sub),
    h("div", { class: "lines-stage" }, h("div", { class: "lines-mapwrap" }, el.map), h("aside", { class: "lines-sidewrap" }, h("h2", { text: "Service alerts" }), el.side)),
    h("section", { class: "card lines-hist", "aria-label": "Fifteen-minute history" }, h("h2", { text: "Last 15 minutes" }), el.ribNote, el.rib),
    h("details", { class: "lines-about" }, h("summary", { text: "How to read this board" }),
      h("p", { text: "Each network is a line and each check is a station, in order of distance from the client. A train leaves when a probe port's check arrives; it stops at the first station that port fails and stays parked until it passes again. One missed check is a hollow marker; amber is confirming, red is stopped, blue is verifying after a recovery. Stations behind a stop are untestable, not failed: the line beyond is dashed." }),
      h("p", { text: "Service alerts group ports by pattern: every network, several networks, one network (or its wired or wireless side), one port. The internet line is measured by IP, so a DNS or HTTPS-by-name fault can be told apart from a dead path. The reference network has its own path; it is reported beside production, never counted as everyone." })));
  root.append(board);

  // ---------------------------------------------------------------------------------------------- data
  async function load() {
    const seq = ++st.seq;
    try {
      const q = st.at ? qs({ at: toIso(st.at) }) : "";
      const doc = await api("/api/v1/sites/" + encodeURIComponent(site) + "/lines" + q);
      if (st.dead || seq !== st.seq) return;
      st.doc = doc;
      st.error = "";
      st.probes = new Set(doc.networks.flatMap((n) => n.ports.map((p) => p.probe)));
      render();
    } catch (e) {
      if (st.dead) return;
      st.error = e instanceof ApiError ? e.message : "Could not load the board.";
      render();
    }
  }
  async function loadTimeline() {
    try {
      const to = st.at ? st.at + 60000 : Date.now();
      const tl = await api("/api/v1/sites/" + encodeURIComponent(site) + "/lines/timeline" + qs({ from: toIso(to - WINDOW_MS), to: toIso(to), step_s: 10 }));
      if (!st.dead) { st.tl = tl; drawRibbon(); }
    } catch (e) { /* the ribbon is optional; the board stands without it */ }
  }
  const refresh = debounce(() => { if (!st.at) load(); }, 1500);
  const live = opts.static ? null : new Live({ site }, {
    beat(b) { if (st.probes.has(b.probe) && !st.at) { spawn(b.probe); refresh(); } },
    state(s) { if (st.probes.has(s.probe)) refresh(); },
    reconnected() { load(); loadTimeline(); },
  });
  const timer = setInterval(() => { if (!st.at) load(); loadTimeline(); if (st.at && Date.now() - st.pinnedAt > PIN_IDLE_MS) goLive(); }, REFRESH_MS);

  function pin(t) { st.at = t; st.pinnedAt = Date.now(); st.trains = []; load(); loadTimeline(); }
  function goLive() { st.at = null; load(); loadTimeline(); }

  // ---------------------------------------------------------------------------------------------- trains
  // a beat of a probe is one real result for each of its board ports: each launches a train toward its first stop
  function spawn(probe) {
    if (still() || !st.doc) return;
    const now = performance.now();
    st.doc.networks.forEach((n, k) => n.ports.forEach((p, j) => {
      if (p.probe !== probe || p.silent) return;
      const stop = firstStop(p);
      st.trains.push({ k, j, n: n.ports.length, wired: p.media === "wired", stop: stop ? stop.i : -1,
        state: stop ? (stop.state === "hollow" ? "hollow" : stop.state) : (Object.values(p.stations).some((s) => s.state === "verifying") ? "verifying" : "ok"), t0: now });
    }));
  }
  function firstStop(p) {
    const keys = st.doc.stations.map((s) => s.key);
    for (let i = 0; i < keys.length; i++) {
      const s = (p.stations[keys[i]] || {}).state;
      if (s === "stopped" || s === "confirming" || s === "hollow") return { i, state: s };
    }
    return null;
  }

  // ---------------------------------------------------------------------------------------------- render
  function render() {
    el.err.hidden = !st.error;
    el.err.textContent = st.error;
    const d = st.doc;
    board.dataset.mode = st.at ? "history" : "live";
    el.pinned.hidden = !st.at;
    if (st.at) el.pinnedText.textContent = "History, pinned at " + fmtHMS(st.at) + ". Returns to live after two idle minutes.";
    if (!d) return;
    board.dataset.phase = d.headline.phase;
    el.chip.textContent = d.headline.chip;
    el.h1.textContent = d.headline.h;
    el.sub.textContent = (d.headline.sub + " " + d.headline.why).trim();
    renderSide(d);
  }

  function renderSide(d) {
    clear(el.side);
    if (!d.findings.length && !d.coverage.length) {
      el.side.append(h("p", { class: "lines-quiet", text: d.networks.length ? "Good service on every line." : "No probe port is on this board yet." }));
    }
    const labels = Object.fromEntries(d.stations.map((s) => [s.key, s.label]));
    for (const f of d.findings) {
      const worst = f.ports.some((p) => p.state === "stopped") ? "stopped" : f.ports.some((p) => p.state === "confirming") ? "confirming" : "verifying";
      const title = (worst === "stopped" ? "Stopped at " : worst === "confirming" ? "Confirming at " : "Verifying at ") + labels[f.station];
      const scope = f.scope === "ring" ? "every network" : f.networks.map(name).join(", ") + (f.media ? " " + f.media : "") + (f.reference ? " (reference)" : "");
      const card = h("article", { class: "lines-card", data: { state: worst } },
        h("h3", {}, title, h("span", { text: f.affected + " of " + f.total + " ports · " + scope })),
        signature(d, f, worst));
      if (f.evidence) {
        const e = f.evidence;
        card.append(h("p", { class: "lines-ev" }, h("strong", { text: "By IP, " + e.by_ip_ok + " of " + e.n + " reach the internet. " }),
          e.kind === "names" ? (f.station === "dns" ? "Names fail, the path is fine." : "Only HTTPS by name fails.") : e.kind === "path" ? "The path is down too." : "No clean split yet."));
      }
      if (f.scope === "multi" && typeof f.onset_spread_s === "number") {
        card.append(h("p", { class: "lines-ev", text: f.onset_spread_s <= 2 ? "Started together. Look for what they share." : "Started " + f.onset_spread_s + " s apart." }));
      }
      const rows = h("ul", { class: "lines-rows" });
      for (const p of f.ports.slice(0, 12)) rows.append(h("li", {}, h("strong", { text: p.probe + ":" + p.port }), h("span", { text: name(p.network) + " · " + (WORD[p.state] || p.state) })));
      if (f.ports.length > 12) rows.append(h("li", { class: "dim", text: "and " + (f.ports.length - 12) + " more" }));
      card.append(rows);
      if (f.since_s !== null && f.since_s !== undefined) card.append(h("p", { class: "dim", text: "For " + dur(f.since_s) + "." }));
      el.side.append(card);
    }
    if (d.coverage.length) {
      el.side.append(h("article", { class: "lines-card", data: { state: "unknown" } }, h("h3", { text: "Not heard from" }),
        h("p", { text: d.coverage.join(". ") + ". A gap in what we can see; silence is not proof that the network is down." })));
    }
  }
  // the pattern: what this group passes, where it stops, what cannot be tested behind it
  function signature(d, f, worst) {
    const at = d.stations.findIndex((s) => s.key === f.station);
    const row = h("ol", { class: "lines-sig", "aria-label": "Passes up to " + (at ? d.stations[at - 1].label : "nothing") + ", " + worst + " at " + d.stations[at].label });
    d.stations.forEach((s, i) => {
      const behind = i > at && f.ports.length && f.ports.every((p) => portState(d, p, s.key) === "untestable");
      row.append(h("li", { data: { state: i < at ? "ok" : i === at ? worst : behind ? "untestable" : "ok" }, text: s.label }));
    });
    return row;
  }
  function portState(d, ref, key) {
    for (const n of d.networks) for (const p of n.ports) if (p.probe === ref.probe && p.port === ref.port) return (p.stations[key] || {}).state;
    return null;
  }

  // ---------------------------------------------------------------------------------------------- canvas
  let raf = 0;
  function frame() {
    raf = requestAnimationFrame(frame);
    drawMap(performance.now());
  }
  function size(cv) {
    const dpr = devicePixelRatio || 1;
    const w = cv.clientWidth, hh = cv.clientHeight;
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(hh * dpr)) { cv.width = Math.round(w * dpr); cv.height = Math.round(hh * dpr); }
    const g = cv.getContext("2d");
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, hh);
    return { g, w, h: hh };
  }
  function drawMap(now) {
    const d = st.doc;
    if (!d) return;
    const C = palette();
    const { g, w: W, h: H } = size(el.map);
    if (!W) return;
    const narrow = W < 600, left = narrow ? 92 : Math.min(180, W * 0.2), right = W - (narrow ? 14 : 60), top = 54;
    const rows = Math.max(1, d.networks.length), rowH = (H - top - 8) / rows;
    const sx = (i) => left + (i + 1) * (right - left) / (d.stations.length + 1);
    const font = (size, weight, color, align) => { g.font = weight + " " + size + "px " + css("--exp-font-ui"); g.fillStyle = color; g.textAlign = align || "left"; };
    d.stations.forEach((s, i) => { font(narrow ? 11 : 14, 700, C.dim, "center"); g.fillText(s.label, sx(i), 26); });
    d.networks.forEach((n, k) => {
      const y = top + rowH * (k + 0.5);
      font(narrow ? 13 : 17, 700, C.text); g.fillText(n.name, 4, y - 2);
      font(12, 500, n.through < n.ports_total - n.silent ? C.stopped : C.dim);
      g.fillText(n.through + "/" + n.ports_total + " through" + (n.reference && !narrow ? " · reference" : ""), 4, y + 15);
      const ci = n.closed_at ? d.stations.findIndex((s) => s.key === n.closed_at) : -1;
      const xc = ci >= 0 ? sx(ci) : right;
      g.setLineDash([]); g.lineWidth = n.reference ? 2 : 4; g.strokeStyle = C.okdim;
      g.beginPath(); g.moveTo(left, y); g.lineTo(xc, y); g.stroke();
      if (ci >= 0) { g.strokeStyle = C.untestable; g.lineWidth = 2; g.setLineDash([3, 7]); g.beginPath(); g.moveTo(xc, y); g.lineTo(right, y); g.stroke(); g.setLineDash([]); }
      d.stations.forEach((s, i) => {
        const a = n.stations[s.key] || { state: "na", affected: 0, of: 0 };
        if (a.state === "na") return;
        g.beginPath(); g.arc(sx(i), y, 9, 0, 7); g.fillStyle = C.bg; g.fill();
        g.lineWidth = 3; g.strokeStyle = C[a.state] || C.ok; if (a.state === "untestable") g.setLineDash([2, 4]);
        g.stroke(); g.setLineDash([]);
        if (BAD.has(a.state)) {
          g.fillStyle = C[a.state]; g.beginPath(); g.arc(sx(i), y, 4.5, 0, 7); g.fill();
          font(12, 700, C[a.state], "center"); g.fillText(a.affected + "/" + a.of + " " + WORD[a.state], sx(i), y + 30);
        }
      });
      // parked: a port that does not pass stays at the station it stopped at; a hollow marker is one missed check
      n.ports.forEach((p, j) => {
        const yo = y + (j - (n.ports.length - 1) / 2) * 5;
        if (p.silent) { g.strokeStyle = C.untestable; g.lineWidth = 1.5; g.setLineDash([2, 2]); g.beginPath(); g.arc(left - 14, yo, 4.5, 0, 7); g.stroke(); g.setLineDash([]); return; }
        const stop = firstStop(p) || verifyingAt(d, p);
        if (!stop) return;
        mark(g, p.media === "wired", sx(stop.i) - 15, yo, 4.6, C[stop.state] || C.ok, stop.state === "hollow");
      });
    });
    if (still()) { st.trains = []; return; }
    st.trains = st.trains.filter((t) => {
      const u = (now - t.t0) / TRAIN_MS;
      const n = d.networks[t.k];
      if (!n || u > 1.3) return false;
      const y = top + rowH * (t.k + 0.5) + (t.j - (t.n - 1) / 2) * 5;
      const end = t.stop >= 0 ? (sx(t.stop) - 14 - left) / (right - left) : 1;
      const x = left + Math.min(u, end) * (right - left);
      g.globalAlpha = u > end ? Math.max(0, 1 - (u - end) * 4) : 1;
      mark(g, t.wired, x, y, 3.2, C[t.state] || C.ok, t.state === "hollow");
      g.globalAlpha = 1;
      return true;
    });
  }
  function verifyingAt(d, p) {
    const keys = d.stations.map((s) => s.key);
    for (let i = 0; i < keys.length; i++) if ((p.stations[keys[i]] || {}).state === "verifying") return { i, state: "verifying" };
    return null;
  }
  function mark(g, wired, x, y, r, color, hollow) {
    g.beginPath();
    if (wired) g.rect(x - r, y - r, 2 * r, 2 * r); else g.arc(x, y, r, 0, 7);
    if (hollow) { g.strokeStyle = color; g.lineWidth = 1.5; g.stroke(); } else { g.fillStyle = color; g.fill(); }
  }

  function drawRibbon() {
    const tl = st.tl;
    const { g, w: W } = size(el.rib);
    if (!tl || !W) return;
    const C = palette();
    const gut = W < 600 ? 60 : 92, rh = 17, top = 6;
    const t0 = parseTs(tl.from), t1 = parseTs(tl.to), X = (t) => gut + (t - t0) / Math.max(1, t1 - t0) * (W - gut - 2);
    tl.networks.forEach((n, k) => {
      const y = top + k * rh + rh / 2;
      g.font = "600 12px " + css("--exp-font-ui"); g.fillStyle = C.dim; g.textAlign = "left"; g.fillText(name(n.network), 2, y + 4);
      n.points.forEach((p, i) => {
        const x0 = X(parseTs(p.t)), x1 = i + 1 < n.points.length ? X(parseTs(n.points[i + 1].t)) + 0.6 : W;
        const bad = p.state === "stopped" || p.state === "confirming";
        const hh = bad ? 4 + p.share * 10 : 3;
        g.fillStyle = bad ? C[p.state] : p.state === "unknown" ? C.unknown : C.okdim;
        g.fillRect(x0, y - hh / 2, x1 - x0, hh);
      });
    });
    if (st.at) { const x = X(st.at); g.strokeStyle = C.verifying; g.lineWidth = 1.5; g.beginPath(); g.moveTo(x, 0); g.lineTo(x, top + tl.networks.length * rh); g.stroke(); }
    st.ribGeo = { t0, t1, gut, W };
  }
  el.rib.addEventListener("click", (ev) => {
    const geo = st.ribGeo;
    if (!geo) return;
    const r = el.rib.getBoundingClientRect();
    const t = geo.t0 + (ev.clientX - r.left - geo.gut) / Math.max(1, geo.W - geo.gut - 2) * (geo.t1 - geo.t0);
    if (t > geo.t0 && t < geo.t1) pin(Math.round(t));
  });

  const onResize = debounce(() => drawRibbon(), 200);
  addEventListener("resize", onResize);
  raf = requestAnimationFrame(frame);
  load();
  loadTimeline();
  return {
    destroy() {
      st.dead = true;
      cancelAnimationFrame(raf);
      clearInterval(timer);
      removeEventListener("resize", onResize);
      if (live) live.close();
      clear(root);
    },
  };
}

function name(net) { return String(net || "").replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()); }
function dur(s) { return s < 60 ? s + " s" : Math.floor(s / 60) + " min " + (s % 60) + " s"; }
