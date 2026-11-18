// Pulse board (/probe/<id>). UX ported from reference/exm/lib/exm/static/pulse.html (verdict + where chain,
// one lane per line with a beat trace, playhead to look back, "What's failing", Details tables); the rule
// logic of pulse-core.js is NOT ported: every state and headline comes from the collector (decision D3).
import { api, qs, ApiError } from "./api.js";
import { h, clear, icon, normState, STATE_ICON, isSlug } from "./dom.js";
import { Live } from "./stream.js";
import { drawStrip, describe, BEAT_MS } from "./trace.js";
import { fmtHMS, fmtDateTime, parseTs, toIso, dur, lineLabel, lineIcon, debounce, pref, titleCase, LINE_ORDER } from "./util.js";

const WINDOW_MS = 15 * 60 * 1000;
const STALE_S = 30;                // spec 04 section 4: the newest result is older than this -> not current
const CONN_GRACE_MS = 10000;       // stream down for this long -> not current
const REFRESH_MS = 20000;
const REWIND_AHEAD_MS = 150000;

const SEG = { ports: "Ports", switch: "Switch", gateway: "Gateway", edge: "Edge", isp: "ISP", dns: "DNS", apps: "Apps",
  link: "Link", lan: "LAN", wan: "WAN", resolver: "Resolver", dns_path: "DNS path", dhcp: "DHCP", ssid: "SSID", wifi: "Wi-Fi", path: "Path" };
const DETAIL_TITLE = { clients: "Clients", dhcp: "DHCP servers", dns: "Resolvers", apps: "Apps", throughput: "Throughput", servers: "Servers" };

export function mountBoard(root, opts) {
  const probe = opts.probe;
  const kiosk = !!opts.kiosk;
  const staticMode = !!opts.static;
  const st = {
    state: null, beats: {}, markers: [], incidents: [], summary: null,
    offset: 0, newestMs: null, label: "", site: "", collectorId: "", streamUp: staticMode ? true : null, downSince: null,
    at: null, rwin: null, error: "", seq: 0, voice: opts.voice || pref("voice") || "", dead: false, collectorDown: false,
  };
  if (opts.at && !kiosk) {
    const t = parseTs(opts.at);
    if (Number.isFinite(t)) { st.at = t; st.rwin = { start: t + REWIND_AHEAD_MS - WINDOW_MS, end: t + REWIND_AHEAD_MS }; }
  }

  const serverNow = () => Date.now() - st.offset;
  const win = () => (st.at !== null ? st.rwin : { start: serverNow() - WINDOW_MS, end: serverNow() });

  // ---- skeleton
  const el = {};
  const board = h("section", { class: "board", "aria-label": "Probe board", data: { probe, sev: "unknown", stale: "false", mode: "live" } });
  el.stale = h("div", { class: "banner banner-stale", role: "alert", hidden: true },
    h("strong", { class: "banner-title", text: "Nothing on this screen is current" }), h("span", { class: "banner-why" }));
  el.rewind = h("div", { class: "banner banner-rewind", role: "status", hidden: true });
  el.error = h("div", { class: "banner banner-error", role: "alert", hidden: true });
  el.title = h("h2", { class: "probe-title", text: probe });
  el.site = h("span", { class: "probe-site" });
  el.asof = h("span", { class: "asof" });
  el.liveBtn = h("button", { class: "btn btn-primary", type: "button", hidden: true, on: { click: () => goLive() } }, icon("rewind"), "Back to live");
  el.voice = h("button", { class: "btn", type: "button", "aria-pressed": "false", title: "Switch between plain and sysadmin wording",
    on: { click: () => { st.voice = voiceNow() === "plain" ? "sysadmin" : "plain"; pref("voice", st.voice); refresh(); } } });
  el.head = h("div", { class: "board-head" },
    kiosk ? null : h("a", { class: "back", href: "/", "data-spa": "" }, icon("dashboard"), "All probes"),
    h("div", { class: "title-block" }, el.title, el.site),
    h("div", { class: "head-tools" }, el.asof, kiosk ? null : el.voice));
  el.headline = h("h1", { class: "headline", id: "headline", "aria-live": "polite", text: "Connecting to the probe..." });
  el.sub = h("p", { class: "sub", id: "sub" });
  el.chain = h("ol", { class: "chain", "aria-label": "Where on the path" });
  el.explain = h("p", { class: "explain" });
  el.where = h("div", { class: "where", hidden: true }, el.chain, el.explain);
  el.verdict = h("div", { class: "verdict" }, el.headline, el.sub, el.where);
  el.lines = h("div", { class: "lines" });
  el.axis = h("div", { class: "axis" }, h("span", { class: "axis-l" }), h("span", { class: "axis-r" }));
  el.thumb = h("span", { class: "thumb" });
  el.scrubLabel = h("span", { class: "scrub-label" });
  el.scrub = h("div", { class: "scrub", tabindex: kiosk ? null : "0", role: kiosk ? null : "slider", "aria-label": "Moment shown. Arrow keys step, Escape returns to live" },
    h("span", { class: "track" }), el.thumb);
  el.markers = h("div", { class: "markers", "aria-label": "Incidents and events in this window" });
  el.tl = h("div", { class: "timeline" }, h("div", { class: "tl-pad" }), h("div", { class: "tl-body" }, el.axis, el.scrub, el.scrubLabel, el.markers));
  el.openInc = h("section", { class: "panel open-incidents", "aria-labelledby": "oi-h", hidden: true }, h("h2", { id: "oi-h", text: "Open incidents" }), h("ul", { class: "inc-list" }));
  el.failing = h("section", { class: "panel failing", "aria-labelledby": "fail-h", hidden: true }, h("h2", { id: "fail-h", text: "What's failing" }), h("div", { class: "cards" }));
  el.details = h("section", { class: "panel details", "aria-labelledby": "det-h" }, h("h2", { id: "det-h", text: "Details" }), h("div", { class: "cards" }));
  board.append(el.stale, el.rewind, el.error, el.head, el.verdict, el.lines, el.tl);
  root.append(board, el.openInc, el.failing, el.details);

  // ---- helpers
  const voiceNow = () => st.voice || (opts.defaultVoice === "plain" ? "plain" : "sysadmin");
  const live = () => st.at === null;

  function isStale() {
    if (!live()) return null;
    if (!st.state) return null;
    if (st.newestMs === null) return "The probe has not reported any results yet.";
    const age = (serverNow() - st.newestMs) / 1000;
    if (age > STALE_S) return "No result from the probe for " + dur(age) + " (last at " + fmtHMS(st.newestMs) + ").";
    if (st.collectorDown) return "The collector for this probe is unreachable.";
    if (st.streamUp === false && st.downSince !== null && Date.now() - st.downSince > CONN_GRACE_MS) return "The live connection to the dashboard is down; reconnecting.";
    return null;
  }

  // ---- data
  async function refresh() {
    const seq = ++st.seq;
    const win0 = win();
    const at = st.at;
    const rewinding = at !== null;
    const stateQ = { probe, voice: voiceNow(), at: rewinding ? toIso(at) : undefined };
    const calls = [
      api("/api/v1/state" + qs(stateQ)),
      api("/api/v1/beats" + qs({ probe, from: toIso(win0.start), to: toIso(win0.end) })).catch(() => null),
    ];
    if (!rewinding && !kiosk) {
      calls.push(api("/api/v1/summary" + qs({ probe, minutes: 60 })).catch(() => null));
      calls.push(api("/api/v1/incidents" + qs({ probe, open: "true" })).catch(() => null));
    }
    let res;
    try {
      res = await Promise.all(calls);
    } catch (e) {
      if (seq !== st.seq || st.dead) return;
      st.error = e instanceof ApiError ? e.message : "Could not load this probe.";
      render();
      return;
    }
    if (seq !== st.seq || st.dead || (at !== st.at)) return;     // a newer request (or mode change) supersedes this one
    st.error = "";
    const [state, beats, summary, incs] = res;
    st.state = state;
    st.site = String(state.site || "");
    if (!rewinding) {
      const at0 = parseTs(state.at);
      if (Number.isFinite(at0)) st.offset = Date.now() - at0;
      st.newestMs = Number.isFinite(at0) && typeof state.newest_s === "number" ? at0 - state.newest_s * 1000 : null;
      st.summary = summary;
      st.incidents = incs && Array.isArray(incs.items) ? incs.items : [];
    }
    st.beats = {};
    st.markers = [];
    if (beats && beats.lines && typeof beats.lines === "object") {
      for (const k of Object.keys(beats.lines)) if (Array.isArray(beats.lines[k])) st.beats[k] = beats.lines[k].filter((p) => Array.isArray(p) && p.length === 2);
      if (!rewinding) {
        for (const k of Object.keys(st.beats)) for (const p of st.beats[k]) if (st.newestMs === null || p[0] > st.newestMs) st.newestMs = p[0];
      }
    }
    if (beats && Array.isArray(beats.markers)) st.markers = beats.markers.filter((m) => m && Number.isFinite(m.t));
    render();
    loadLabel();
  }

  async function loadLabel() {
    if (st.label || !st.site || !isSlug(st.site)) return;
    try {
      const d = await api("/api/v1/probes" + qs({ site: st.site }));
      const me = (d.items || []).find((p) => p.probe === probe);
      if (me) { st.label = String(me.label || probe); st.collectorId = String(me.collector_id || ""); renderHeader(); }
    } catch (e) {
      st.label = probe;
    }
  }

  // ---- rendering
  function render() {
    renderHeader();
    renderVerdict();
    renderLines();
    renderTimeline();
    renderFailing();
    renderIncidents();
    renderDetails();
    renderBanners();
  }

  function renderHeader() {
    el.title.textContent = st.label || probe;
    el.site.textContent = st.site ? titleCase(st.site) : "";
    el.voice.textContent = "Voice: " + voiceNow();
    el.voice.setAttribute("aria-pressed", voiceNow() === "plain" ? "true" : "false");
    el.liveBtn.hidden = live();
    document.title = (st.label || probe) + " - Pulse";
  }

  function renderVerdict() {
    const v = st.state && st.state.verdict ? st.state.verdict : null;
    const stale = isStale();
    const sev = stale ? "unknown" : normState(v && v.severity);
    board.dataset.sev = sev;
    board.dataset.stale = stale ? "true" : "false";
    board.dataset.mode = live() ? "live" : "rewind";
    if (!v) return;
    if (stale) {
      el.headline.textContent = "Nothing on this screen is current.";
      el.sub.textContent = "Last known: " + String(v.headline || "") + " " + stale;
      el.where.hidden = true;
      return;
    }
    el.headline.textContent = String(v.headline || "");
    el.sub.textContent = String(v.sub || "");
    renderWhere(v.where);
  }

  function renderWhere(w) {
    clear(el.chain);
    if (!w || !Array.isArray(w.chain)) { el.where.hidden = true; return; }
    el.where.hidden = false;
    w.chain.forEach((c, i) => {
      if (!c || typeof c.seg !== "string") return;
      const state = normState(c.state);
      const here = c.seg === w.seg;
      if (i > 0) el.chain.appendChild(h("li", { class: "sep", "aria-hidden": "true", text: ">" }));
      el.chain.appendChild(h("li", { class: "seg st-" + state + (here ? " here" : ""), "aria-current": here ? "true" : null, data: { seg: c.seg, state } },
        icon(STATE_ICON[state]), h("span", { text: SEG[c.seg] || c.seg }), h("span", { class: "sr", text: " " + state })));
    });
    const bits = [];
    if (w.label) bits.push(String(w.label) + (w.ip ? " " + String(w.ip) : "") + ": ");
    el.explain.textContent = bits.join("") + String(w.explain || "");
  }

  function renderLines() {
    clear(el.lines);
    const st0 = st.state;
    if (!st0 || !Array.isArray(st0.lines)) return;
    const stale = isStale();
    const lines = st0.lines.slice().sort((a, b) => LINE_ORDER.indexOf(a.key) - LINE_ORDER.indexOf(b.key));
    for (const ln of lines) {
      if (!ln || typeof ln.key !== "string") continue;
      const state = stale ? "unknown" : normState(ln.state);
      const meta = [];
      if (ln.since) meta.push(h("span", { class: "line-since", text: "since " + fmtHMS(parseTs(ln.since)) }));
      if (typeof ln.flaps === "number" && ln.flaps > 0) meta.push(h("span", { class: "line-flaps", text: ln.flaps + (ln.flaps === 1 ? " flap" : " flaps") }));
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("class", "strip");
      svg.setAttribute("role", "img");
      svg.dataset.line = ln.key;
      const row = h("div", { class: "line st-" + state, data: { line: ln.key, state: normState(ln.state), word: String(ln.word || ""), since: ln.since || "" } },
        h("div", { class: "line-head" },
          h("div", { class: "line-name" }, icon(lineIcon(ln.key)), h("h3", { text: String(ln.label || lineLabel(ln.key)) })),
          h("div", { class: "line-state" }, icon(STATE_ICON[normState(ln.state)]), h("span", { class: "line-word", text: String(ln.word || normState(ln.state)) })),
          meta.length ? h("div", { class: "line-meta" }, meta) : null,
          ln.detail ? h("p", { class: "line-detail", text: String(ln.detail) }) : null),
        h("div", { class: "line-trace" }, svg));
      el.lines.appendChild(row);
      if (!kiosk) attachScrub(svg);
    }
    drawStrips();
  }

  function drawStrips() {
    const w = win();
    const ph = live() ? NaN : st.at;
    for (const svg of el.lines.querySelectorAll("svg.strip")) {
      const k = svg.dataset.line;
      const pts = st.beats[k] || [];
      drawStrip(svg, pts, w, ph);
      svg.setAttribute("aria-label", describe(lineLabel(k), pts, w));
    }
  }

  function renderTimeline() {
    const w = win();
    el.axis.firstChild.textContent = live() ? "15 minutes ago" : fmtHMS(w.start);
    el.axis.lastChild.textContent = live() ? "now" : fmtHMS(w.end);
    const t = live() ? w.end : st.at;
    const frac = Math.min(1, Math.max(0, (t - w.start) / (w.end - w.start)));
    el.thumb.style.setProperty("--x", (frac * 100).toFixed(2));
    el.scrub.setAttribute("aria-valuemin", String(Math.round(w.start / 1000)));
    el.scrub.setAttribute("aria-valuemax", String(Math.round(w.end / 1000)));
    el.scrub.setAttribute("aria-valuenow", String(Math.round(t / 1000)));
    el.scrub.setAttribute("aria-valuetext", live() ? "now (live)" : fmtHMS(t));
    el.scrubLabel.textContent = live() ? "" : fmtHMS(t);
    el.scrubLabel.style.setProperty("--x", (frac * 100).toFixed(2));
    clear(el.markers);
    for (const m of st.markers) {
      if (!(m.t >= w.start && m.t <= w.end)) continue;
      const kind = m.kind === "incident" || m.kind === "drill" ? m.kind : "ext";
      const x = (((m.t - w.start) / (w.end - w.start)) * 100).toFixed(2);
      const ic = kind === "incident" ? "alert" : kind === "drill" ? "drill" : "link";
      const label = (kind === "incident" ? "Incident" : kind === "drill" ? "Drill" : "Event") + " at " + fmtHMS(m.t) + ": " + String(m.text || "");
      const node = kiosk
        ? h("span", { class: "marker m-" + kind, vars: { "--x": x }, title: label }, icon(ic), h("span", { class: "sr", text: label }))
        : h("button", { class: "marker m-" + kind, type: "button", vars: { "--x": x }, title: label, on: { click: () => enterRewind(m.t) } }, icon(ic), h("span", { class: "sr", text: label }));
      node.dataset.kind = kind;
      el.markers.appendChild(node);
    }
  }

  function renderFailing() {
    const f = st.state && Array.isArray(st.state.failing) ? st.state.failing : [];
    const cards = el.failing.querySelector(".cards");
    clear(cards);
    el.failing.hidden = !f.length || kiosk;
    for (const g of f) {
      if (!g || !Array.isArray(g.items)) continue;
      cards.appendChild(h("article", { class: "card", data: { line: g.line } },
        h("h3", {}, icon(lineIcon(g.line)), lineLabel(g.line)),
        h("ul", {}, g.items.map((it) => h("li", {},
          h("span", { class: "what", text: String(it.text || "") }),
          typeof it.count === "number" && it.count > 1 ? h("span", { class: "count", text: " x" + it.count }) : null,
          Array.isArray(it.ports) && it.ports.length ? h("span", { class: "ports", text: "Ports: " + it.ports.slice(0, 12).join(", ") + (it.ports.length > 12 ? " +" + (it.ports.length - 12) : "") }) : null)))));
    }
  }

  function renderIncidents() {
    const list = el.openInc.querySelector("ul");
    clear(list);
    const items = live() && !kiosk ? st.incidents.filter((i) => i && i.end === null) : [];
    el.openInc.hidden = !items.length;
    for (const i of items) {
      list.appendChild(h("li", { data: { incident: i.id } }, icon("alert"),
        h("span", { class: "inc-what", text: lineLabel(i.line) + " " + String(i.kind) + " since " + fmtHMS(parseTs(i.start)) }),
        Array.isArray(i.facts) && i.facts.length ? h("span", { class: "inc-facts", text: String(i.facts[0]) }) : null,
        h("a", { href: "/incidents", "data-spa": "", text: "Incidents" })));
    }
  }

  function renderDetails() {
    const box = el.details.querySelector(".cards");
    clear(box);
    const sum = st.summary;
    el.details.hidden = kiosk || !live() || !sum;
    if (el.details.hidden) return;
    for (const k of Object.keys(DETAIL_TITLE)) {
      const rows = Array.isArray(sum[k]) ? sum[k].slice(0, 50) : [];
      if (!rows.length) continue;
      const cols = [];
      for (const r of rows) for (const c of Object.keys(r || {})) if (c !== "probe" && !cols.includes(c)) cols.push(c);
      box.appendChild(h("article", { class: "card", data: { table: k } }, h("h3", { text: DETAIL_TITLE[k] }),
        h("div", { class: "scroll" }, h("table", {},
          h("thead", {}, h("tr", {}, cols.map((c) => h("th", { scope: "col", text: c.replace(/_/g, " ") })))),
          h("tbody", {}, rows.map((r) => h("tr", {}, cols.map((c) => h("td", { text: r[c] === null || r[c] === undefined ? "" : String(r[c]) })))))))));
    }
  }

  function renderBanners() {
    const stale = isStale();
    el.stale.hidden = !stale;
    if (stale) el.stale.querySelector(".banner-why").textContent = " " + stale;
    el.error.hidden = !st.error;
    el.error.textContent = st.error;
    el.rewind.hidden = live();
    if (!live()) {
      clear(el.rewind);
      el.rewind.append(icon("rewind"), h("span", {}, "Looking back at ", h("time", { datetime: toIso(st.at), text: fmtDateTime(st.at) }), ". Live updates are paused."),
        kiosk ? null : h("button", { class: "btn", type: "button", on: { click: () => goLive() } }, "Back to live"));
    }
    if (live()) {
      if (st.newestMs !== null) {
        const age = Math.max(0, (serverNow() - st.newestMs) / 1000);
        el.asof.textContent = "As of " + fmtHMS(st.newestMs) + " (" + dur(age) + " ago)";
      } else el.asof.textContent = st.state ? "No results yet" : "";
    } else el.asof.textContent = "As of " + fmtHMS(st.at);
    if (String(!!stale) !== board.dataset.stale && st.state) {   // staleness flipped between data refreshes
      renderVerdict();
      renderLines();
    }
    board.dataset.stale = stale ? "true" : "false";
  }

  // ---- rewind
  function pushUrl(replace) {
    const q = new URLSearchParams(location.search);
    if (st.at === null) q.delete("at"); else q.set("at", toIso(st.at));
    const s = q.toString();
    opts.navigate("/probe/" + probe + (s ? "?" + s : ""), replace);
  }

  const fetchRewind = debounce(() => refresh(), 150);

  function enterRewind(t, replace) {
    if (kiosk || !Number.isFinite(t)) return;
    t = Math.round(t / 1000) * 1000;
    const first = st.at === null;
    if (first) {
      const w = win();                       // keep the window the user was looking at: no jump
      st.rwin = { start: w.start, end: w.end };
      closeStream();
    }
    if (t < st.rwin.start || t > st.rwin.end) st.rwin = { start: t + REWIND_AHEAD_MS - WINDOW_MS, end: t + REWIND_AHEAD_MS };
    st.at = t;
    pushUrl(first ? !!replace : true);
    renderHeader(); renderTimeline(); renderBanners();
    board.dataset.mode = "rewind";
    drawStrips();
    fetchRewind();
  }

  function goLive() {
    if (st.at === null) return;
    st.at = null;
    st.rwin = null;
    pushUrl(false);
    openStream();
    refresh();
  }

  function tFromPointer(ev, node) {
    const r = node.getBoundingClientRect();
    const w = win();
    const f = Math.min(1, Math.max(0, (ev.clientX - r.left) / Math.max(1, r.width)));
    return w.start + f * (w.end - w.start);
  }

  function attachScrub(node) {
    node.addEventListener("pointerdown", (ev) => {
      if (ev.button !== 0) return;
      ev.preventDefault();
      node.setPointerCapture(ev.pointerId);
      enterRewind(tFromPointer(ev, node));
      const move = (e) => enterRewind(tFromPointer(e, node));
      const up = () => { node.removeEventListener("pointermove", move); node.removeEventListener("pointerup", up); node.removeEventListener("pointercancel", up); };
      node.addEventListener("pointermove", move);
      node.addEventListener("pointerup", up);
      node.addEventListener("pointercancel", up);
    });
  }

  if (!kiosk) {
    attachScrub(el.scrub);
    el.scrub.addEventListener("keydown", (ev) => {
      const step = ev.shiftKey ? 60000 : BEAT_MS;
      if (ev.key === "ArrowLeft" || ev.key === "ArrowRight") {
        ev.preventDefault();
        const cur = live() ? win().end : st.at;
        enterRewind(cur + (ev.key === "ArrowLeft" ? -step : step));
      } else if (ev.key === "Escape") { ev.preventDefault(); goLive(); }
    });
  }
  const onKey = (ev) => { if (ev.key === "Escape" && !live() && !kiosk) goLive(); };
  document.addEventListener("keydown", onKey);

  // ---- live updates
  let stream = null;
  let rafPending = false;
  const refetchState = debounce(() => refresh(), 200);

  function openStream() {
    if (staticMode || stream) return;
    stream = new Live({ probes: probe }, {
      status: (up) => {
        st.streamUp = up;
        st.downSince = up ? null : Date.now();
        if (up && st.state) refetchState();
        renderBanners();
      },
      beat: (e) => {
        if (e.probe !== probe || !live() || typeof e.line !== "string" || !Number.isFinite(e.t) || !(e.v >= 0 && e.v <= 3)) return;
        const arr = st.beats[e.line] || (st.beats[e.line] = []);
        if (!arr.some((p) => p[0] === e.t)) arr.push([e.t, e.v]);
        if (st.newestMs === null || e.t > st.newestMs) st.newestMs = e.t;
        st.collectorDown = false;
        if (!rafPending) { rafPending = true; requestAnimationFrame(() => { rafPending = false; drawStrips(); renderBanners(); }); }
      },
      state: (e) => { if (e.probe === probe && live()) refetchState(); },
      incident: (e) => {
        if (e.probe !== probe || !live() || typeof e.id !== "string") return;
        st.incidents = st.incidents.filter((i) => i.id !== e.id);
        st.incidents.push(e);
        const t = parseTs(e.start);
        st.markers = st.markers.filter((m) => m.ref !== e.id);
        if (Number.isFinite(t)) st.markers.push({ t, kind: "incident", text: lineLabel(e.line) + " " + String(e.kind), ref: e.id });
        renderTimeline(); renderIncidents();
      },
      collector: (e) => { if (st.collectorId && e.collector_id === st.collectorId) { st.collectorDown = e.ok === false; renderBanners(); } },
    });
  }

  function closeStream() {
    if (stream) { stream.close(); stream = null; }
    st.streamUp = staticMode ? true : null;
    st.downSince = null;
  }

  const tick = setInterval(() => {
    if (st.dead) return;
    renderBanners();
    if (live()) {
      renderTimeline();
      if (Math.floor(Date.now() / 1000) % 5 === 0) drawStrips();
    }
  }, 1000);
  const poll = staticMode ? null : setInterval(() => { if (live()) refresh(); }, REFRESH_MS);

  openStream();
  refresh();

  return {
    destroy() {
      st.dead = true;
      clearInterval(tick);
      if (poll) clearInterval(poll);
      closeStream();
      refetchState.cancel();
      fetchRewind.cancel();
      document.removeEventListener("keydown", onKey);
      clear(root);
    },
  };
}
