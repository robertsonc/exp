// Speedtests overview (/speedtests): tests/hour, medians by leg, score distribution, top causes, zones coloured by
// p50 score, "users vs probes", and the filterable list of tests. Federated over every collector; a collector that is
// down is flagged ("Partial results"), never hidden. Auto-refreshes every 30 s unless ?static=1.
import {
  api, qs, h, s, clear, icon, barRows, stat, viewHead, field, select, collectorBanner, errorBanner, errText,
  loadAll, subNav, median, num, mbps, ms, fmt, scoreBadge, scoreState, SCORE_WORD, STATE_ICON, causeLabel, RANGES,
  rangeSeconds, sites, hourLabel, iso, testLink, isAdmin,
} from "./common.js";
import { isSlug } from "../js/dom.js";
import { fmtDateTime, fmtHM, parseTs, pref } from "../js/util.js";

const POLL_MS = 30000;
const LIST_PAGE = 25;
const BEATS_CHUNK_MS = 6 * 3600 * 1000;
const RANK = { 0: 0, 3: 1, 1: 2, 2: 3 };       // worst beat of a bucket: fail > warn > no data > ok

export function mountOverview(root, opts) {
  const url = new URL(location.href);
  const st = {
    range: RANGES.some((r) => r[0] === url.searchParams.get("range")) ? url.searchParams.get("range") : (pref("st.range") || "24h"),
    site: isSlug(url.searchParams.get("site")) ? url.searchParams.get("site") : "",
    probe: "", filters: { zone: url.searchParams.get("zone") || "", ap: url.searchParams.get("ap") || "", ssid: url.searchParams.get("ssid") || "", cause: url.searchParams.get("cause") || "", max: url.searchParams.get("max") || "" },
    rows: [], more: false, shown: LIST_PAGE, collectors: [], error: "", dead: false, seq: 0, probes: [], beats: [], hours: [], causes: [], zones: [], zoneCount: new Map(), inetLoaded: null, loaded: false,
  };
  if (!RANGES.some((r) => r[0] === st.range)) st.range = "24h";

  const body = h("div", { class: "st-body" });
  root.append(subNav("overview"), h("section", { class: "st", "aria-label": "Speedtests overview" }, body));

  const win = () => { const to = Date.now(); return { from: to - rangeSeconds(st.range) * 1000, to }; };

  function syncUrl() {
    const q = new URLSearchParams();
    q.set("range", st.range);
    if (st.site) q.set("site", st.site);
    for (const k of Object.keys(st.filters)) if (st.filters[k]) q.set(k, st.filters[k]);
    history.replaceState(null, "", location.pathname + "?" + q.toString());
  }

  // ---- data
  async function load() {
    const seq = ++st.seq;
    const w = win();
    const base = { from: iso(w.from), to: iso(w.to + 1000), site: st.site };
    try {
      const [list, hours, causes, zonesP50, zonesN, inet] = await Promise.all([
        loadAll("/api/v1/speedtests", { ...base, limit: 1000 }, 1),
        api("/api/v1/speedtests/aggregate" + qs({ ...base, group_by: "hour", metric: "count" })),
        api("/api/v1/speedtests/aggregate" + qs({ ...base, group_by: "cause", metric: "count" })),
        api("/api/v1/speedtests/aggregate" + qs({ ...base, group_by: "zone", metric: "score_p50" })),
        api("/api/v1/speedtests/aggregate" + qs({ ...base, group_by: "zone", metric: "count" })),
        api("/api/v1/speedtests/aggregate" + qs({ ...base, group_by: "zone", metric: "loaded_p50", leg: "internet" })),
      ]);
      if (seq !== st.seq || st.dead) return;
      st.rows = list.items;
      st.more = list.more;
      st.collectors = mergeCollectors([list.collectors, hours.collectors, causes.collectors]);
      st.hours = hours.items || [];
      st.causes = causes.items || [];
      st.zones = zonesP50.items || [];
      st.zoneCount = new Map((zonesN.items || []).map((i) => [i.key, i.count]));
      st.inetLoaded = weighted(inet.items || []);
      st.error = "";
      st.loaded = true;
      render();
      loadProbes();
    } catch (e) {
      if (seq !== st.seq || st.dead) return;
      st.error = errText(e, "Could not load the speedtests.");
      render();
    }
  }

  function mergeCollectors(lists) {
    const by = new Map();
    for (const l of lists) for (const c of l || []) { const p = by.get(c.collector_id); if (!p || p.ok) by.set(c.collector_id, c); }
    return [...by.values()];
  }
  function weighted(items) {
    let n = 0;
    let sum = 0;
    for (const i of items) if (num(i.value) && num(i.count) && i.count > 0) { n += i.count; sum += i.value * i.count; }
    return n ? sum / n : null;
  }

  async function loadProbes() {
    try {
      const doc = await api("/api/v1/probes" + qs(st.site ? { site: st.site } : {}));
      if (st.dead) return;
      st.probes = (doc.items || []).filter((p) => p && isSlug(p.probe));
      if (!st.probes.some((p) => p.probe === st.probe)) st.probe = st.probes.length ? st.probes[0].probe : "";
    } catch (e) {
      st.probes = [];
    }
    await loadBeats();
  }

  async function loadBeats() {
    st.beats = [];
    if (st.probe) {
      const w = win();
      const from = Math.max(w.from, w.to - 24 * 3600 * 1000);      // the chart covers at most the last 24 h
      const calls = [];
      for (let a = from; a < w.to; a += BEATS_CHUNK_MS) {
        const b = Math.min(w.to, a + BEATS_CHUNK_MS);
        calls.push(api("/api/v1/beats" + qs({ probe: st.probe, from: iso(a), to: iso(b) })).catch(() => null));
      }
      const docs = await Promise.all(calls);
      if (st.dead) return;
      const worst = new Map();
      for (const d of docs) {
        if (!d || !d.lines) continue;
        for (const k of Object.keys(d.lines)) for (const p of d.lines[k] || []) {
          if (!Array.isArray(p) || !num(p[0]) || !(p[1] >= 0 && p[1] <= 3)) continue;
          const key = Math.floor(p[0] / 60000);
          if (!worst.has(key) || RANK[p[1]] > RANK[worst.get(key)]) worst.set(key, p[1]);
        }
      }
      st.beats = [...worst.entries()].map(([k, v]) => [k * 60000, v]).sort((a, b) => a[0] - b[0]);
    }
    render();
  }

  // ---- derived
  const q = () => st.rows.filter((r) => (!st.filters.zone || r.zone === st.filters.zone) && (!st.filters.ap || r.ap_name === st.filters.ap)
    && (!st.filters.ssid || r.ssid === st.filters.ssid) && (!st.filters.cause || (r.cause || "unknown") === st.filters.cause)
    && (!st.filters.max || (num(r.score) && r.score <= Number(st.filters.max))));

  // ---- render
  function controls() {
    const siteOpts = [["", "All sites"], ...sites().map((x) => [x, x])];
    return viewHead("Speedtests",
      field("Range", select("st-range", RANGES.map((r) => [r[0], r[1]]), st.range, (v) => { st.range = v; pref("st.range", v); syncUrl(); load(); })),
      sites().length > 1 ? field("Site", select("st-site", siteOpts, st.site, (v) => { st.site = v; syncUrl(); load(); })) : null,
      h("button", { class: "btn", type: "button", on: { click: () => load() } }, "Refresh"));
  }

  function tiles() {
    const r = st.rows;
    const withScore = r.filter((x) => num(x.score));
    const poor = withScore.filter((x) => x.score < 50).length;
    const total = st.hours.reduce((a, i) => a + (i.count || 0), 0) || r.length;
    return h("div", { class: "stats", "aria-label": "Summary" },
      stat("Tests", String(total), st.more ? "latest 1000 analysed" : (st.range === "1h" ? "last hour" : "in range")),
      stat("Median score", withScore.length ? String(Math.round(median(withScore.map((x) => x.score)))) : "-", withScore.length ? poor + " poor" : ""),
      stat("Median download", mbps(median(r.map((x) => x.local_down_mbps))), "venue network"),
      stat("Median upload", mbps(median(r.map((x) => x.local_up_mbps))), "venue network"));
  }

  function legTable() {
    const loc = (k) => median(st.rows.map((x) => x[k]));
    return h("div", { class: "panel st-panel" }, h("h2", { text: "Medians by leg" }),
      h("div", { class: "scroll" }, h("table", { class: "legs-table" },
        h("thead", {}, h("tr", {}, ["Leg", "Download", "Upload", "Responsiveness"].map((t) => h("th", { scope: "col", text: t })))),
        h("tbody", {},
          h("tr", { data: { leg: "local" } }, h("th", { scope: "row", text: "Local (venue network)" }), h("td", { text: mbps(loc("local_down_mbps")) }), h("td", { text: mbps(loc("local_up_mbps")) }), h("td", { text: ms(loc("loaded_ms")) + " loaded" })),
          h("tr", { data: { leg: "internet" } }, h("th", { scope: "row", text: "Internet" }), h("td", { text: mbps(loc("internet_down_mbps")) }), h("td", { text: mbps(loc("internet_up_mbps")) }),
            h("td", { text: num(st.inetLoaded) ? "~" + ms(st.inetLoaded) + " loaded" : "-" }))))));
  }

  function perHour() {
    const items = st.hours.slice().sort((a, b) => String(a.key).localeCompare(String(b.key)));
    const max = Math.max(1, ...items.map((i) => i.count));
    const W = 900;
    const H = 120;
    const svg = s("svg", { class: "chart hours", viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Tests per hour" });
    const bw = items.length ? Math.min(40, (W / items.length) * 0.7) : 0;
    items.forEach((i, n) => {
      const x = items.length ? (n + 0.5) * (W / items.length) - bw / 2 : 0;
      const hh = Math.max(2, (i.count / max) * (H - 18));
      svg.append(s("rect", { class: "bar-h", x: x.toFixed(1), y: (H - 14 - hh).toFixed(1), width: bw.toFixed(1), height: hh.toFixed(1) }, s("title", {}, hourLabel(i.key) + ": " + i.count + " tests")));
      if (items.length <= 24 || n % Math.ceil(items.length / 12) === 0) svg.append(s("text", { class: "axis-t", x: (x + bw / 2).toFixed(1), y: H - 2, "text-anchor": "middle" }, hourLabel(i.key)));
    });
    const sr = h("p", { class: "sr", text: items.map((i) => hourLabel(i.key) + " " + i.count).join(", ") });
    return h("div", { class: "panel st-panel" }, h("h2", { text: "Tests per hour" }), items.length ? svg : h("p", { class: "empty", text: "No tests in this range." }), sr);
  }

  function distribution() {
    const buckets = [["0-19", 0, 19], ["20-39", 20, 39], ["40-59", 40, 59], ["60-79", 60, 79], ["80-100", 80, 100]];
    const scored = st.rows.filter((r) => num(r.score));
    const items = buckets.map(([label, lo, hi]) => ({ key: label, label: label + " " + SCORE_WORD[scoreState((lo + hi) / 2)],
      value: scored.filter((r) => r.score >= lo && r.score <= hi).length, state: scoreState((lo + hi) / 2) }));
    return h("div", { class: "panel st-panel", id: "st-dist" }, h("h2", { text: "Score distribution" }),
      scored.length ? barRows(items.map((i) => ({ ...i, text: String(i.value) })), { label: "Tests by score" }) : h("p", { class: "empty", text: "No scored tests in this range." }));
  }

  function causes() {
    const items = st.causes.slice(0, 8).map((i) => ({ key: i.key, label: causeLabel(i.key), value: i.count, text: String(i.count) }));
    return h("div", { class: "panel st-panel", id: "st-causes" }, h("h2", { text: "Top causes" }),
      items.length ? barRows(items, { label: "Tests by diagnosed cause" }) : h("p", { class: "empty", text: "No diagnoses yet." }));
  }

  function zones() {
    const items = st.zones.slice().sort((a, b) => a.value - b.value);
    return h("div", { class: "panel st-panel", id: "st-zones" }, h("h2", { text: "Zones by median score" }),
      items.length ? h("ul", { class: "zone-tiles" }, items.map((z) => {
        const sv = scoreState(z.value);
        const a = h("a", { class: "zone-tile st-" + sv, href: "/speedtests/breakdowns?group=zone", "data-spa": "", data: { zone: z.key, state: sv } },
          h("span", { class: "zone-name", text: z.key }), h("span", { class: "zone-score" }, icon(STATE_ICON[sv]), h("strong", { text: String(Math.round(z.value)) }), " ", SCORE_WORD[sv]),
          h("span", { class: "zone-n", text: (st.zoneCount.get(z.key) || z.count) + " tests" + (z.approximate ? " (approx.)" : "") }));
        return h("li", {}, a);
      })) : h("p", { class: "empty", text: "No zones in this range." }));
  }

  function usersVsProbes() {
    const wrap = h("div", { class: "panel st-panel", id: "st-vs" }, h("h2", { text: "Users vs probes" }),
      h("p", { class: "sub", text: "Each dot is a user test (height = score). The band above shows the nearest probe's worst line state over time." }));
    const probeSel = st.probes.length ? field("Probe", select("st-probe", st.probes.map((p) => [p.probe, String(p.label || p.probe)]), st.probe, (v) => { st.probe = v; loadBeats(); })) : null;
    if (probeSel) wrap.append(probeSel);
    const w = win();
    const from = Math.max(w.from, w.to - 24 * 3600 * 1000);
    const tests = st.rows.filter((r) => num(r.score) && parseTs(r.ended) >= from);
    if (!tests.length && !st.beats.length) { wrap.append(h("p", { class: "empty", text: "No tests or probe data in the last 24 hours." })); return wrap; }
    const W = 900;
    const Hh = 190;
    const X = (t) => ((t - from) / (w.to - from)) * W;
    const svg = s("svg", { class: "chart vs", viewBox: "0 0 " + W + " " + Hh, role: "img", "aria-label": "User test scores against the probe state over time" });
    const names = ["ok", "warn", "fail", "unknown"];
    const heights = [12, 24, 40, 40];
    for (const [t, v] of st.beats) svg.append(s("rect", { class: "beat " + names[v], x: X(t).toFixed(1), y: 44 - heights[v], width: 4, height: heights[v] }));
    svg.append(s("line", { class: "base", x1: 0, y1: 45, x2: W, y2: 45 }));
    const Y = (sc) => 60 + (100 - sc) * 1.15;
    for (const g of [50, 80]) {
      svg.append(s("line", { class: "grid", x1: 0, y1: Y(g), x2: W, y2: Y(g) }), s("text", { class: "axis-t", x: 4, y: Y(g) - 3 }, String(g)));
    }
    const probeAt = (t) => { let best = null; for (const [bt, v] of st.beats) { if (Math.abs(bt - t) <= 90000 && (best === null || RANK[v] > RANK[best])) best = v; } return best; };
    const groups = { ok: [], bad: [] };
    for (const r of tests) {
      const t = parseTs(r.ended);
      const sv = scoreState(r.score);
      const shape = sv === "ok" ? "circle" : sv === "warn" ? "rect" : "path";
      const cx = X(t);
      const cy = Y(r.score);
      const node = shape === "circle" ? s("circle", { cx: cx.toFixed(1), cy: cy.toFixed(1), r: 6 })
        : shape === "rect" ? s("rect", { x: (cx - 5.5).toFixed(1), y: (cy - 5.5).toFixed(1), width: 11, height: 11 })
          : s("path", { d: "M" + cx.toFixed(1) + " " + (cy - 7).toFixed(1) + " l7 12 h-14 z" });
      node.setAttribute("class", "dot st-" + sv);
      node.setAttribute("tabindex", "0");
      node.setAttribute("role", "link");
      node.setAttribute("aria-label", "Test " + Math.round(r.score) + " " + SCORE_WORD[sv] + " at " + fmtHM(t) + ", open details");
      node.dataset.test = r.id;
      node.append(s("title", {}, "Score " + Math.round(r.score) + " at " + fmtHM(t)));
      node.addEventListener("click", () => opts.go(testLink(r.id)));
      node.addEventListener("keydown", (ev) => { if (ev.key === "Enter") opts.go(testLink(r.id)); });
      svg.append(node);
      const pv = probeAt(t);
      (pv === 0 || pv === null ? groups.ok : groups.bad).push(r.score);
    }
    svg.append(s("text", { class: "axis-t", x: 0, y: Hh - 2 }, fmtHM(from)), s("text", { class: "axis-t", x: W, y: Hh - 2, "text-anchor": "end" }, fmtHM(w.to)));
    wrap.append(svg);
    const mo = median(groups.ok);
    const mb = median(groups.bad);
    wrap.append(h("p", { class: "vs-summary", id: "st-vs-summary" },
      "Median user score while the probe was fine: ", h("strong", { text: num(mo) ? String(Math.round(mo)) : "-" }), " (" + groups.ok.length + " tests). ",
      "While it showed a warning or failure: ", h("strong", { text: num(mb) ? String(Math.round(mb)) : "-" }), " (" + groups.bad.length + " tests)."));
    return wrap;
  }

  function listPanel() {
    const all = q();
    const view = all.slice(0, st.shown);
    const mk = (id, label, key, first) => {
      const vals = [...new Set(st.rows.map((r) => (key === "cause" ? (r.cause || "unknown") : r[key])).filter((v) => typeof v === "string" && v))].sort();
      return field(label, select(id, [["", first], ...vals.map((v) => [v, key === "cause" ? causeLabel(v) : v])], st.filters[key === "ap_name" ? "ap" : key] || "", (v) => {
        st.filters[key === "ap_name" ? "ap" : key] = v; st.shown = LIST_PAGE; syncUrl(); render();
      }));
    };
    const tbl = h("table", { class: "tests-table" },
      h("thead", {}, h("tr", {}, ["When", "Score", "Zone", "AP", "SSID", "Band", "Down", "Up", "Cause", ""].map((t) => h("th", { scope: "col", text: t })))),
      h("tbody", {}, view.map((r) => h("tr", { data: { test: r.id } },
        h("td", { text: fmtDateTime(parseTs(r.ended)) }), h("td", {}, scoreBadge(r.score)), h("td", { text: r.zone || "-" }),
        h("td", { text: r.ap_name || "-" }), h("td", { text: r.ssid || "-" }), h("td", { text: r.band || "-" }),
        h("td", { text: fmt(r.local_down_mbps) }), h("td", { text: fmt(r.local_up_mbps) }), h("td", { text: causeLabel(r.cause) }),
        h("td", {}, h("a", { href: testLink(r.id), "data-spa": "", text: "Details", "aria-label": "Details of the test at " + fmtDateTime(parseTs(r.ended)) }))))));
    return h("div", { class: "panel st-panel", id: "st-list" }, h("h2", { text: "Tests" }),
      h("div", { class: "filters" }, mk("f-zone", "Zone", "zone", "All zones"), mk("f-ap", "AP", "ap_name", "All APs"), mk("f-ssid", "SSID", "ssid", "All SSIDs"), mk("f-cause", "Cause", "cause", "Any cause"),
        field("Score at most", select("f-max", [["", "Any score"], ["79", "79 (not good)"], ["49", "49 (poor)"]], st.filters.max, (v) => { st.filters.max = v; st.shown = LIST_PAGE; syncUrl(); render(); }))),
      all.length ? h("div", { class: "scroll" }, tbl) : h("p", { class: "empty", text: "No tests match." }),
      all.length > st.shown ? h("button", { class: "btn", type: "button", on: { click: () => { st.shown += LIST_PAGE; render(); } } }, "Show more (" + (all.length - st.shown) + ")") : null,
      isAdmin() ? h("p", { class: "sub", text: "Raw device identifiers are shown only on a test's detail page (audited), never in lists." }) : null);
  }

  function render() {
    const keepFocus = document.activeElement && document.activeElement.id;
    clear(body);
    body.append(controls(), collectorBanner(st.collectors), errorBanner(st.error));
    if (!st.loaded) { if (!st.error) body.append(h("p", { class: "sub", text: "Loading speedtests..." })); return; }
    body.append(tiles(), h("div", { class: "st-grid" }, legTable(), perHour(), distribution(), causes()), zones(), usersVsProbes(), listPanel());
    if (keepFocus) { const el = document.getElementById(keepFocus); if (el) el.focus(); }
  }

  render();
  load();
  const poll = opts.static ? null : setInterval(load, POLL_MS);
  return { destroy() { st.dead = true; if (poll) clearInterval(poll); clear(root); } };
}
