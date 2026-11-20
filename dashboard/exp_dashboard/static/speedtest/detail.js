// Test detail (/speedtests/test/<id>): the two legs side by side, score parts, the diagnosis with cited evidence, an
// evidence timeline across the correlation window and one card per evidence kind. Also the "share link" support
// landing: a result link pasted on the support page lands here with the full evidence.
//
// Privacy (SR-25): raw client IP/MAC/hostname/username are asked for ONLY by an admin session (the dashboard drops
// the flag for everyone else and the collector redacts anyway). The user's comment is plain text.
import {
  api, qs, subNav, h, s, clear, icon, errorBanner, errText, num, fmt, mbps, ms, bytes, scoreBadge,
  scoreState, SCORE_WORD, STATE_ICON, causeLabel, isAdmin, iso, barRows, ApiError,
} from "./common.js";
import { purgePanel } from "./purge.js";
import { drawStrip } from "../js/trace.js";
import { fmtDateTime, fmtHMS, parseTs } from "../js/util.js";

const KIND_LABEL = { wifi: "Wi-Fi", wired: "Wired port", flows: "Flows and apps", wan: "WAN", security: "Security log", baseline: "Probe baseline", dns: "DNS", identity: "Identity and location", legs: "Test legs" };
const KIND_ORDER = ["wifi", "wired", "flows", "wan", "security", "baseline", "dns", "identity"];
const W = 900;
const LANE_H = 34;
const clip = (v, n) => { const t = String(v === undefined || v === null ? "" : v); return t.length > n ? t.slice(0, n - 1) + "..." : t; };

function kv(pairs) {
  const rows = pairs.filter((p) => p && p[1] !== undefined && p[1] !== null && p[1] !== "" && p[1] !== "-");
  if (!rows.length) return h("p", { class: "empty", text: "Nothing recorded." });
  return h("dl", { class: "kv" }, rows.map((p) => [h("dt", { text: p[0] }), h("dd", { text: String(p[1]) })]));
}
const pct = (v) => (num(v) ? Math.round(v) + " %" : null);
const tsMs = (v) => (num(v) ? (v < 1e11 ? v * 1000 : v) : NaN);   // Mist and EC send epoch seconds, ISO strings elsewhere

export function mountDetail(root, opts) {
  const st = { id: opts.id, doc: null, error: "", dead: false, probeBeats: [], state: "loading" };
  const body = h("div", { class: "st-body" });
  root.append(subNav(""), h("section", { class: "st st-detail", "aria-label": "Speedtest detail" }, body));

  async function load() {
    try {
      const doc = await api("/api/v1/speedtests/" + st.id + qs({ identifiers: isAdmin() ? "1" : "" }));
      if (st.dead) return;
      st.doc = doc;
      st.state = "ready";
      st.error = "";
      render();
      loadBeats();
    } catch (e) {
      if (st.dead) return;
      st.state = "error";
      st.error = e instanceof ApiError && e.status === 404 ? "No test with this id was found. It may have been purged or expired (tests are kept for 30 days by default)." : errText(e, "Could not load this test.");
      render();
    }
  }

  const evOf = (kind) => ((st.doc && st.doc.evidence) || []).find((e) => e && e.kind === kind) || null;
  const dataOf = (kind) => { const e = evOf(kind); return e && e.data && typeof e.data === "object" ? e.data : {}; };

  function windowMs() {
    const t = st.doc.test;
    let a = parseTs(t.started) - 5 * 60000;
    let b = parseTs(t.ended) + 2 * 60000;
    for (const e of st.doc.evidence || []) {
      const f = parseTs(e.window && e.window.from);
      const to = parseTs(e.window && e.window.to);
      if (Number.isFinite(f) && f < a) a = f;
      if (Number.isFinite(to) && to > b) b = to;
    }
    if (!(b > a)) b = a + 60000;
    return { start: a, end: b };
  }

  async function loadBeats() {
    const b = dataOf("baseline");
    if (!b.probe || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(b.probe)) return;
    const w = windowMs();
    if (w.end - w.start > 6 * 3600 * 1000) return;
    try {
      const d = await api("/api/v1/beats" + qs({ probe: b.probe, from: iso(w.start), to: iso(w.end) }));
      if (st.dead) return;
      const worst = new Map();
      const rank = { 0: 0, 3: 1, 1: 2, 2: 3 };
      for (const k of Object.keys(d.lines || {})) for (const p of d.lines[k] || []) {
        if (Array.isArray(p) && num(p[0]) && p[1] >= 0 && p[1] <= 3 && (!worst.has(p[0]) || rank[p[1]] > rank[worst.get(p[0])])) worst.set(p[0], p[1]);
      }
      st.probeBeats = [...worst.entries()].sort((x, y) => x[0] - y[0]);
      const old = body.querySelector("#st-timeline");      // redraw only the timeline: an open purge confirmation must survive
      if (old) old.replaceWith(timeline());
    } catch (e) {
      st.probeBeats = [];
    }
  }

  // ---- sections
  function header() {
    const t = st.doc.test;
    const sc = t.score && num(t.score.total) ? t.score.total : null;
    const es = st.doc.evidence_state || {};
    return h("div", { class: "st-detail-head" },
      h("a", { class: "back", href: "/speedtests", "data-spa": "" }, icon("rewind"), "All speedtests"),
      h("h1", { class: "st-title" }, "Test ", h("span", { class: "mono", id: "st-id", text: t.id })),
      h("p", { class: "sub", id: "st-meta" }, fmtDateTime(parseTs(t.started)) + " - " + fmtHMS(parseTs(t.ended)), " - zone ", h("strong", { text: t.zone || "unresolved" }),
        " (" + (t.zone_source || "?") + ") - site " + (t.site || "?") + (st.doc.collector_id ? " - collector " + st.doc.collector_id : "")),
      h("div", { class: "st-badges" }, scoreBadge(sc),
        ...(Array.isArray(t.flags) ? t.flags : []).map((f) => h("span", { class: "chip st-warn", data: { flag: f } }, icon("alert"), h("span", { class: "chip-text", text: String(f).replace(/_/g, " ") }))),
        h("span", { class: "chip st-" + (es.state === "final" ? "ok" : es.state === "unavailable" ? "unknown" : "warn"), data: { evidence: es.state || "" } },
          icon(es.state === "final" ? "check" : "clock"), h("span", { class: "chip-text", text: "Evidence: " + (es.state || "unknown") }))));
  }

  function legCard(name, leg, extra) {
    const l = leg || {};
    const rows = [["Status", l.status], ["Download", mbps(l.down_mbps)], ["Upload", mbps(l.up_mbps)], ["Idle latency", ms(l.idle_ms)], ["Jitter", ms(l.jitter_ms)],
      ["Loaded down", ms(l.loaded_down_ms)], ["Loaded up", ms(l.loaded_up_ms)], ["Responsiveness", num(l.rpm) ? l.rpm + " RPM" : null], ["Stability (CV)", num(l.cv) ? fmt(l.cv, 2) : null],
      ["Failures", num(l.failures) ? String(l.failures) : null], ["Bytes", bytes(l.bytes)], ["Server", l.server]].concat(extra || []);
    return h("div", { class: "card leg-card", data: { leg: name.toLowerCase() } }, h("h3", {}, icon(name === "Internet" ? "internet" : "network"), name), kv(rows));
  }

  function legs() {
    const L = st.doc.test.legs || {};
    const dns = L.dns || {};
    const path = L.path || {};
    const seg = (k) => { const o = path[k]; return o && typeof o === "object" ? (num(o.idle) ? fmt(o.idle) : "-") + " / " + (num(o.loaded) ? fmt(o.loaded) : "-") + " ms" : null; };
    return h("div", { class: "panel st-panel", id: "st-legs" }, h("h2", { text: "Legs" }),
      h("div", { class: "legs" }, legCard("Local", L.local), legCard("Internet", L.internet)),
      h("div", { class: "cards st-cards" },
        h("div", { class: "card" }, h("h3", {}, icon("dns"), "DNS leg"), kv([["Cold lookup", ms(dns.cold_ms)], ["Warm lookup", ms(dns.warm_ms)], ["Resolver", dns.resolver_ip], ["Source", dns.source]])),
        h("div", { class: "card" }, h("h3", {}, icon("path"), "Path (idle / loaded)"),
          kv([["Gateway", seg("gateway_ms")], ["Edge", seg("edge_ms")], ["Edge +1", seg("edge1_ms")], ["Device ICMP", num(path.device_icmp_ms) ? ms(path.device_icmp_ms) : null]]),
          h("p", { class: "sub", text: "The path legs are venue-infrastructure context timed from the box, not per user." }))));
  }

  function scoreParts() {
    const sc = st.doc.test.score;
    if (!sc) return h("div", { class: "panel st-panel", id: "st-score" }, h("h2", { text: "Score" }), h("p", { class: "empty", text: "This test has no score (a leg did not complete)." }));
    const items = [["total", "Total"], ["speed", "Speed"], ["responsiveness", "Responsiveness"], ["stability", "Stability"]].filter(([k]) => num(sc[k]))
      .map(([k, label]) => ({ key: k, label, value: sc[k], text: Math.round(sc[k]) + " " + SCORE_WORD[scoreState(sc[k])], state: scoreState(sc[k]) }));
    return h("div", { class: "panel st-panel", id: "st-score" }, h("h2", { text: "Score parts" }), barRows(items, { label: "Score parts", max: 100 }));
  }

  function diagnosis() {
    const d = st.doc.diagnosis;
    const box = h("div", { class: "panel st-panel", id: "st-diagnosis" }, h("h2", { text: "Diagnosis" }));
    if (!d) { box.append(h("p", { class: "empty", text: "No diagnosis yet." })); return box; }
    const final = d.stage === "final";
    box.append(h("p", { class: "sub" }, h("span", { class: "chip st-" + (final ? "ok" : "warn") }, icon(final ? "check" : "clock"), h("span", { class: "chip-text", text: final ? "Final" : "Quick (evidence still arriving)" })),
      " updated " + fmtDateTime(parseTs(d.updated))));
    if (d.noc_text) box.append(h("p", { class: "noc-text", id: "st-noc-text", text: d.noc_text }));
    if (d.user_text) box.append(h("p", { class: "sub", text: "Shown to the user: " + d.user_text }));
    const causes = Array.isArray(d.cause) ? d.cause : [];
    if (!causes.length) box.append(h("p", { class: "empty", text: "Could not pinpoint a cause from the evidence." }));
    else {
      box.append(h("ol", { class: "causes" }, causes.map((c, i) => h("li", { class: "cause", data: { cause: c.id } },
        h("div", { class: "cause-top" }, h("strong", { text: causeLabel(c.id) }), h("span", { class: "chip", text: Math.round((c.confidence || 0) * 100) + " % confidence" }), i === 0 ? h("span", { class: "chip st-fail" }, icon("alert"), h("span", { class: "chip-text", text: "Most likely" })) : null),
        h("ul", { class: "cites", "aria-label": "Cited evidence" }, (c.cites || []).map((ct) => h("li", {}, h("a", { class: "cite", href: "#ev-" + ct.kind, text: (KIND_LABEL[ct.kind] || ct.kind) + (ct.ref ? ": " + ct.ref : "") }))))))));
    }
    return box;
  }

  // ---- timeline
  function timeline() {
    const w = windowMs();
    const X = (t) => Math.min(W, Math.max(0, ((t - w.start) / (w.end - w.start)) * W));
    const t0 = parseTs(st.doc.test.started);
    const t1 = parseTs(st.doc.test.ended);
    const events = [];      // for the text alternative
    const lanes = [];
    const mk = () => s("svg", { class: "lane-svg", viewBox: "0 0 " + W + " " + LANE_H, preserveAspectRatio: "none", role: "img" });
    const band = (svg) => svg.append(s("rect", { class: "test-band", x: X(t0).toFixed(1), y: 0, width: Math.max(2, X(t1) - X(t0)).toFixed(1), height: LANE_H }));
    const base = (svg) => svg.append(s("line", { class: "base", x1: 0, y1: LANE_H - 0.5, x2: W, y2: LANE_H - 0.5 }));
    const lane = (name, svg, desc, valueText) => { svg.setAttribute("aria-label", name + ": " + desc); lanes.push(h("div", { class: "lane", data: { lane: name } }, h("div", { class: "lane-label" }, h("strong", { text: name }), valueText ? h("span", { class: "lane-val", text: valueText }) : null), svg)); };

    const wifi = dataOf("wifi");
    // Wi-Fi events and roams
    {
      const svg = mk(); band(svg); base(svg);
      let n = 0;
      for (const r of Array.isArray(wifi.roams) ? wifi.roams : []) {
        const t = tsMs(r.timestamp); if (!Number.isFinite(t)) continue;
        const bad = r.type && r.type !== "success";
        svg.append(s("path", { class: "mk roam " + (bad ? "st-fail" : "st-ok"), d: "M" + X(t).toFixed(1) + " 6 l6 8 l-6 8 l-6 -8 z" }, s("title", {}, "Roam (" + (r.type || "?") + ")")));
        events.push([t, "Wi-Fi", "Roam " + (r.type || "") + (num(r.latency_s) ? " in " + fmt(r.latency_s) + " s" : "")]); n++;
      }
      for (const e of Array.isArray(wifi.events) ? wifi.events : []) {
        const t = tsMs(e.timestamp); if (!Number.isFinite(t)) continue;
        svg.append(s("circle", { class: "mk ev", cx: X(t).toFixed(1), cy: 26, r: 4 }, s("title", {}, clip(e.type || e.text || "event", 60))));
        events.push([t, "Wi-Fi", clip(e.type || "", 40) + (e.text ? " " + clip(e.text, 80) : "")]); n++;
      }
      lane("Wi-Fi events", svg, n + " roams and association events", wifi.roam_count !== undefined ? wifi.roam_count + " roams, " + (wifi.auth_failures || 0) + " auth failures" : "");
    }
    // levels: RSSI, AP utilization
    const level = (name, frac, text) => {
      const svg = mk(); band(svg); base(svg);
      if (Number.isFinite(frac)) svg.append(s("rect", { class: "level", x: X(t0).toFixed(1), y: (LANE_H - 4 - frac * (LANE_H - 8)).toFixed(1), width: Math.max(2, X(t1) - X(t0)).toFixed(1), height: (frac * (LANE_H - 8) + 2).toFixed(1) }));
      lane(name, svg, text || "no sample", text);
    };
    const c = wifi.client || {};
    const rad = (wifi.ap && wifi.ap.radio) || {};
    level("Wi-Fi signal", num(c.rssi) ? Math.min(1, Math.max(0, (c.rssi + 90) / 60)) : NaN, num(c.rssi) ? "RSSI " + c.rssi + " dBm" + (num(c.snr) ? ", SNR " + c.snr + " dB" : "") : "");
    level("AP utilization", num(rad.util_all) ? Math.min(1, rad.util_all / 100) : NaN, num(rad.util_all) ? rad.util_all + " % airtime" + (num(wifi.ap && wifi.ap.num_clients) ? ", " + wifi.ap.num_clients + " clients" : "") : "");
    // flows
    {
      const fl = dataOf("flows");
      const svg = mk(); band(svg); base(svg);
      const flows = (Array.isArray(fl.flows) ? fl.flows : []).slice().sort((a, b) => (b.bytes_total || 0) - (a.bytes_total || 0)).slice(0, 8);
      flows.forEach((f, i) => {
        const a = tsMs(f.start_s); const b = tsMs(f.end_s);
        if (!Number.isFinite(a) || !Number.isFinite(b)) return;
        svg.append(s("rect", { class: "flow-bar" + (f.firewall_dropped ? " dropped" : ""), x: X(a).toFixed(1), y: 3 + (i % 4) * 7, width: Math.max(3, X(b) - X(a)).toFixed(1), height: 5 }, s("title", {}, (f.application || "flow") + " " + bytes(f.bytes_total))));
        events.push([a, "Flows", (f.application || "flow") + " " + bytes(f.bytes_total) + (f.firewall_dropped ? " (dropped by firewall)" : "")]);
      });
      lane("Top flows", svg, flows.length + " flows", flows.length ? (flows[0].application || "flow") + " " + bytes(flows[0].bytes_total) : "");
    }
    // WAN
    {
      const wan = dataOf("wan");
      const ap = Array.isArray(wan.appliances) ? wan.appliances[0] : null;
      const svg = mk(); band(svg); base(svg);
      let text = "";
      if (ap) {
        const ifc = (ap.interfaces || []).find((i) => i.wan_if) || (ap.interfaces || [])[0] || {};
        const cap = num(ifc.max_wan_bandwidth_kbps) ? ifc.max_wan_bandwidth_kbps * 1000 : 0;
        const rows = ap.timeseries && Array.isArray(ap.timeseries.rows) ? ap.timeseries.rows : [];
        if (cap && rows.length) {
          const pts = rows.filter((r) => Array.isArray(r) && num(r[0]) && num(r[1])).map((r) => X(tsMs(r[0])).toFixed(1) + "," + (LANE_H - 3 - Math.min(1, ((r[1] || 0) + (r[2] || 0)) / cap) * (LANE_H - 8)).toFixed(1));
          if (pts.length > 1) svg.append(s("polyline", { class: "wan-line", points: pts.join(" ") }));
        }
        for (const al of ap.alarms || []) {
          const t = num(al.time_occurred_ms) ? al.time_occurred_ms : NaN; if (!Number.isFinite(t)) continue;
          svg.append(s("path", { class: "mk alarm st-warn", d: "M" + X(t).toFixed(1) + " 4 l6 11 h-12 z" }, s("title", {}, clip(al.alarm_name || al.type, 60))));
          events.push([t, "WAN", "Alarm " + clip(al.alarm_name || al.type, 60) + (al.severity ? " (" + al.severity + ")" : "")]);
        }
        text = num(wan.wan_util_pct) ? "WAN " + Math.round(wan.wan_util_pct) + " % used" : num(ifc.util_pct) ? "WAN " + Math.round(ifc.util_pct) + " % used" : "";
      }
      lane("WAN utilization", svg, text || "no data", text);
    }
    // security
    {
      const sec = dataOf("security");
      const svg = mk(); band(svg); base(svg);
      const evs = Array.isArray(sec.events) ? sec.events : [];
      for (const e of evs) {
        const t = parseTs(e.ts); if (!Number.isFinite(t)) continue;
        svg.append(s("rect", { class: "mk sec st-fail", x: (X(t) - 4).toFixed(1), y: 10, width: 8, height: 14 }, s("title", {}, (e.action || "event") + " " + clip(e.rule || e.host || "", 60))));
        events.push([t, "Security", (e.action || "event") + (e.rule ? " by " + clip(e.rule, 50) : "") + (e.host ? " " + clip(e.host, 50) : "") + (num(e.count) && e.count > 1 ? " x" + e.count : "")]);
      }
      const cnt = sec.counts || {};
      const hits = (cnt.deny || 0) + (cnt.drop || 0) + (cnt.block || 0) + (cnt.session_limit || 0);
      lane("Security hits", svg, evs.length + " log lines", hits ? hits + " denied or blocked" : "");
    }
    // probe beats
    {
      const svg = s("svg", { class: "lane-svg strip", viewBox: "0 0 900 44", preserveAspectRatio: "none", role: "img" });
      if (st.probeBeats.length) drawStrip(svg, st.probeBeats, w, null);
      const b = dataOf("baseline");
      svg.setAttribute("aria-label", "Probe beats: " + (st.probeBeats.length ? st.probeBeats.length + " beats" : "no beats loaded"));
      lanes.push(h("div", { class: "lane", data: { lane: "Probe beats" } }, h("div", { class: "lane-label" }, h("strong", { text: "Probe beats" }), h("span", { class: "lane-val", text: b.probe ? b.probe + (b.distance ? " (" + String(b.distance).replace("_", " ") + ")" : "") : "no baseline" })), svg));
    }
    events.sort((a, b) => a[0] - b[0]);
    const text = events.length ? h("details", { class: "tl-text" }, h("summary", { text: "Timeline as text (" + events.length + " events)" }),
      h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Source", "Event"].map((x) => h("th", { scope: "col", text: x })))),
        h("tbody", {}, events.map((e) => h("tr", {}, h("td", { text: fmtHMS(e[0]) }), h("td", { text: e[1] }), h("td", { text: e[2] })))))) : null;
    return h("div", { class: "panel st-panel", id: "st-timeline" }, h("h2", { text: "Evidence timeline" }),
      h("p", { class: "sub", text: "Window " + fmtHMS(w.start) + " to " + fmtHMS(w.end) + "; the shaded band is the test." }),
      h("div", { class: "lanes" }, lanes), text);
  }

  // ---- evidence cards
  function status(e) {
    const ok = e.status === "ok";
    return h("span", { class: "chip st-" + (ok ? "ok" : e.status === "partial" ? "warn" : "unknown") }, icon(ok ? "check" : "alert"), h("span", { class: "chip-text", text: e.status + " - " + e.source }));
  }

  function card(e, content) {
    return h("div", { class: "card ev-card", id: "ev-" + e.kind, data: { kind: e.kind } }, h("h3", {}, icon(e.kind === "wifi" ? "wifi" : e.kind === "dns" ? "dns" : e.kind === "wan" ? "internet" : "network"), KIND_LABEL[e.kind] || e.kind),
      h("div", { class: "ev-meta" }, status(e), h("span", { class: "sub", text: "collected " + fmtHMS(parseTs(e.collected_at)) })),
      e.status === "unavailable" || e.status === "error" ? h("p", { class: "empty", text: "This source was not available for the test." }) : content);
  }

  function table(head, rows) {
    if (!rows.length) return h("p", { class: "empty", text: "No rows." });
    return h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, head.map((x) => h("th", { scope: "col", text: x })))), h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", { text: c === null || c === undefined ? "-" : String(c) })))))));
  }

  function evCards() {
    const out = [];
    const evs = (st.doc.evidence || []).slice().sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind));
    for (const e of evs) {
      const d = e.data || {};
      let c;
      if (e.kind === "wifi") {
        const cl = d.client || {}; const ap = d.ap || {}; const r = ap.radio || {};
        c = kv([["AP", ap.ap_name], ["SSID", cl.ssid], ["Band / channel", [cl.band, cl.channel].filter((x) => x !== undefined && x !== null).join(" / ")], ["Protocol", cl.proto], ["RSSI", num(cl.rssi) ? cl.rssi + " dBm" : null], ["SNR", num(cl.snr) ? cl.snr + " dB" : null],
          ["TX / RX rate", num(cl.tx_rate_mbps) ? fmt(cl.tx_rate_mbps) + " / " + fmt(cl.rx_rate_mbps) + " Mb/s" : null], ["Retry rate", pct(cl.retry_pct)], ["Airtime in use", pct(r.util_all)], ["Radio clients", num(r.num_clients) ? String(r.num_clients) : null],
          ["Noise floor", num(r.noise_floor_dbm) ? r.noise_floor_dbm + " dBm" : null], ["Roams", num(d.roam_count) ? String(d.roam_count) : null], ["Auth failures", num(d.auth_failures) ? String(d.auth_failures) : null], ["Device", [cl.manufacture, cl.family, cl.os].filter(Boolean).join(" ")]]);
      } else if (e.kind === "wired") {
        const p = d.port || {};
        c = kv([["Switch port", p.port_id], ["Link", p.up === undefined ? null : p.up ? "up" : "down"], ["Speed", num(p.speed_mbps) ? p.speed_mbps + " Mb/s" : null], ["Duplex", p.full_duplex === undefined ? null : p.full_duplex ? "full" : "half"],
          ["RX / TX errors", num(p.rx_errors) || num(p.tx_errors) ? (p.rx_errors || 0) + " / " + (p.tx_errors || 0) : null], ["PoE", p.poe_on === undefined ? null : p.poe_on ? "on" : "off"], ["Neighbour", p.neighbor_system_name], ["Auth", (d.client || {}).auth_state]]);
      } else if (e.kind === "flows") {
        const fl = (Array.isArray(d.flows) ? d.flows : []).slice().sort((a, b) => (b.bytes_total || 0) - (a.bytes_total || 0)).slice(0, 10);
        c = h("div", {}, kv([["Flows seen", num((d.counts || {}).total_flows) ? String(d.counts.total_flows) : null], ["Matched the client", num((d.counts || {}).matched_flows) ? String(d.counts.matched_flows) : null], ["Dropped by firewall", num((d.counts || {}).flows_firewall_dropped) ? String(d.counts.flows_firewall_dropped) : null]]),
          table(["Application", "Remote", "Proto", "Bytes", "Class", "Slow", "Dropped"], fl.map((f) => [f.application, f.domain || (f.ip2 ? f.ip2 + (num(f.port2) ? ":" + f.port2 : "") : "-"), f.protocol, bytes(f.bytes_total), f.traffic_class, num(f.slow_duration) ? f.slow_duration : null, f.firewall_dropped ? "yes" : "no"])));
      } else if (e.kind === "wan") {
        const ap = (Array.isArray(d.appliances) ? d.appliances : [])[0] || {};
        const health = ap.health || {};
        const hrow = (k, label) => (health[k] || []).map((t) => [label, t.tunnel_id, t.health_status, num(t.max) ? t.max : "-"]);
        c = h("div", {}, kv([["Appliance", ap.hostname], ["WAN utilization", num(d.wan_util_pct) ? fmt(d.wan_util_pct, 1) + " %" : null]]),
          table(["Interface", "Utilization", "Down", "Up"], (ap.interfaces || []).filter((i) => i.wan_if).map((i) => [i.ifname, num(i.util_pct) ? fmt(i.util_pct, 1) + " %" : "-", num(i.rx_bps) ? mbps(i.rx_bps / 1e6) : "-", num(i.tx_bps) ? mbps(i.tx_bps / 1e6) : "-"])),
          table(["Metric", "Tunnel", "Health", "Max"], [...hrow("latency", "Latency"), ...hrow("loss", "Loss"), ...hrow("jitter", "Jitter")]),
          (ap.alarms || []).length ? table(["Alarm", "Severity", "Description"], ap.alarms.map((a) => [a.alarm_name || a.type, a.severity, clip(a.description, 120)])) : null);
      } else if (e.kind === "security") {
        const cn = d.counts || {};
        c = h("div", {}, kv([["Denied", num(cn.deny) ? String(cn.deny) : null], ["Dropped", num(cn.drop) ? String(cn.drop) : null], ["Blocked", num(cn.block) ? String(cn.block) : null], ["Session limit", num(cn.session_limit) ? String(cn.session_limit) : null], ["Truncated", d.truncated ? "yes" : null]]),
          table(["Time", "Action", "Rule", "Destination", "Reason", "Count"], (Array.isArray(d.events) ? d.events : []).slice(0, 20).map((x) => [fmtHMS(parseTs(x.ts)), x.action, clip(x.rule, 60), x.host || (x.dst_ip ? x.dst_ip + (num(x.dst_port) ? ":" + x.dst_port : "") : "-"), clip(x.reason, 80), x.count])),
          (Array.isArray(d.events) ? d.events : []).some((x) => x.raw) ? h("details", { class: "raw" }, h("summary", { text: "Matching log lines" }), h("ul", {}, d.events.filter((x) => x.raw).slice(0, 10).map((x) => h("li", {}, h("code", { text: clip(x.raw, 240) }))))) : null);
      } else if (e.kind === "baseline") {
        c = h("div", {}, kv([["Probe", d.probe], ["Nearness", d.distance ? String(d.distance).replace("_", " ") : null], ["Severity", d.severity], ["Probe throughput", d.throughput ? mbps(d.throughput.down_mbps) + " down / " + mbps(d.throughput.up_mbps) + " up" : null], ["Probe Wi-Fi", d.wifi ? [d.wifi.ssid, d.wifi.band, num(d.wifi.rssi_dbm) ? d.wifi.rssi_dbm + " dBm" : null].filter(Boolean).join(" ") : null]]),
          (d.lines || []).length ? h("ul", { class: "chips" }, d.lines.map((l) => h("li", { class: "chip st-" + (["ok", "warn", "fail"].includes(l.state) ? l.state : "unknown") }, icon(STATE_ICON[["ok", "warn", "fail"].includes(l.state) ? l.state : "unknown"]), h("span", { class: "chip-text", text: l.key + (l.detail ? ": " + l.detail : "") })))) : null);
      } else if (e.kind === "dns") {
        c = h("div", {}, kv([["Resolver", d.resolver_ip], ["Failures", num(d.failures) ? String(d.failures) : null], ["Slow lookups", num(d.slow) ? String(d.slow) : null], ["Slowest", num(d.slowest_ms) ? ms(d.slowest_ms) : null], ["Probe DNS", d.probe_dns ? d.probe_dns.state + (num(d.probe_dns.rtt_ms) ? " " + ms(d.probe_dns.rtt_ms) : "") : null]]),
          table(["Time", "Name", "Type", "Result", "RTT"], (Array.isArray(d.queries) ? d.queries : []).slice(0, 10).map((q) => [fmtHMS(parseTs(q.ts)), clip(q.qname, 80), q.qtype, q.rcode, num(q.rtt_ms) ? ms(q.rtt_ms) : "-"])));
      } else if (e.kind === "identity") {
        c = h("div", {}, kv([["Resolved by", d.resolved_by], ["Zone", d.zone ? d.zone + (d.zone_source ? " (" + d.zone_source + ")" : "") : null], ["AP", d.ap_name], ["SSID", d.ssid], ["Band", d.band], ["Switch port", d.switch_port], ["VLAN", num(d.vlan) ? String(d.vlan) : null],
          ["Manufacturer", d.manufacture], ["OS family", d.os_family], ["Connection", d.wired === undefined ? null : d.wired ? "wired" : "Wi-Fi"], ["Candidates", num(d.candidates) ? String(d.candidates) : null], ["Address translation suspected", d.nat_suspected ? "yes (" + (d.nat_reason || "?") + "): the test was not tied to a device" : null]]),
          d.scrubbed ? h("p", { class: "sub", text: isAdmin() ? "Raw identifiers were removed by the privacy setting after diagnosis." : "Raw identifiers are hidden for your role." }) : null);
      } else c = kv([]);
      out.push(card(e, c));
    }
    return h("div", { class: "panel st-panel", id: "st-evidence" }, h("h2", { text: "Evidence" }), out.length ? h("div", { class: "cards st-cards" }, out) : h("p", { class: "empty", text: "No evidence was collected for this test (no connector, or it is still being gathered)." }));
  }

  function comment() {
    const t = st.doc.test;
    return h("div", { class: "panel st-panel", id: "st-comment" }, h("h2", { text: "The user's comment" }),
      t.comment ? h("blockquote", { class: "comment", id: "st-comment-text", text: t.comment }) : h("p", { class: "empty", text: "No comment was left." }));
  }

  function device() {
    const t = st.doc.test;
    const ua = (t.client && t.client.ua) || {};
    const id = dataOf("identity");
    const admin = isAdmin() && st.doc.identifiers;
    const rows = [["Device key", st.doc.device_key], ["OS", [ua.os_family, ua.os_version].filter(Boolean).join(" ")], ["Browser", ua.browser], ["Device class", ua.device_class], ["Connection hint", t.client && t.client.connection_hint], ["Manufacturer", id.manufacture]];
    if (admin) rows.push(["IP address", t.client && t.client.ip], ["MAC address", id.mac], ["Hostname", id.hostname], ["802.1X / portal user", id.username]);
    return h("div", { class: "panel st-panel", id: "st-device" }, h("h2", { text: "Device" }), kv(rows),
      admin ? h("p", { class: "sub", text: "Raw identifiers are shown because you are an admin. Each view is audited." }) : h("p", { class: "sub", id: "st-ident-note", text: "Raw device identifiers (IP, MAC, hostname, username) are visible to admins only." }));
  }

  function render() {
    clear(body);
    if (st.state === "loading") { body.append(h("p", { class: "sub", text: "Loading test..." })); return; }
    if (st.state === "error") { body.append(h("a", { class: "back", href: "/speedtests", "data-spa": "" }, icon("rewind"), "All speedtests"), errorBanner(st.error)); return; }
    const t = st.doc.test;
    body.append(header(), h("div", { class: "st-cols" }, legs(), h("div", { class: "st-side" }, scoreParts(), diagnosis())), timeline(), evCards(), h("div", { class: "st-cols" }, comment(), device()));
    const subjects = [{ by: "test", value: t.id }];
    if (st.doc.device_key) subjects.push({ by: "device_key", value: st.doc.device_key });
    const p = purgePanel(subjects, { onDone: (by) => { if (by === "test") opts.go("/speedtests"); } });
    if (p) body.append(p);
  }

  render();
  load();
  return { destroy() { st.dead = true; clear(root); } };
}
