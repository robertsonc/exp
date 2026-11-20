// Breakdowns (/speedtests/breakdowns): one metric grouped by zone, AP, SSID, band, OS family or hour, and the ten
// worst APs by p50 score with at least N tests (a single test never makes an AP "worst").
import {
  api, qs, h, clear, subNav, barRows, viewHead, field, select, collectorBanner, errorBanner, errText, num, fmt,
  scoreState, SCORE_WORD, RANGES, rangeSeconds, sites, hourLabel, iso, icon, STATE_ICON,
} from "./common.js";
import { isSlug } from "../js/dom.js";
import { pref } from "../js/util.js";

const GROUPS = [["zone", "Zone"], ["ap", "AP"], ["ssid", "SSID"], ["band", "Band"], ["os_family", "OS family"], ["hour", "Hour"]];
const METRICS = [["score_p50", "Median score"], ["down_p50", "Median download (Mb/s)"], ["up_p50", "Median upload (Mb/s)"],
  ["loaded_p50", "Median loaded latency (ms)"], ["count", "Number of tests"]];
const MIN_N = [1, 2, 3, 5, 10, 20];

export function mountBreakdowns(root, opts) {
  const u = new URL(location.href);
  const pick = (k, list, d) => (list.some((x) => x[0] === u.searchParams.get(k)) ? u.searchParams.get(k) : d);
  const st = {
    group: pick("group", GROUPS, "zone"), metric: pick("metric", METRICS, "score_p50"), leg: u.searchParams.get("leg") === "internet" ? "internet" : "local",
    range: pick("range", RANGES, pref("st.range") || "24h"), site: isSlug(u.searchParams.get("site")) ? u.searchParams.get("site") : "", minN: MIN_N.includes(Number(u.searchParams.get("min"))) ? Number(u.searchParams.get("min")) : 3,
    doc: null, aps: null, error: "", dead: false, seq: 0,
  };
  const body = h("div", { class: "st-body" });
  root.append(subNav("breakdowns"), h("section", { class: "st", "aria-label": "Speedtest breakdowns" }, body));

  function syncUrl() {
    const q = new URLSearchParams({ group: st.group, metric: st.metric, leg: st.leg, range: st.range, min: String(st.minN) });
    if (st.site) q.set("site", st.site);
    history.replaceState(null, "", location.pathname + "?" + q.toString());
  }

  async function load() {
    const seq = ++st.seq;
    const to = Date.now();
    const base = { from: iso(to - rangeSeconds(st.range) * 1000), to: iso(to + 1000), site: st.site };
    try {
      const [main, aps] = await Promise.all([
        api("/api/v1/speedtests/aggregate" + qs({ ...base, group_by: st.group, metric: st.metric, leg: st.leg })),
        api("/api/v1/speedtests/aggregate" + qs({ ...base, group_by: "ap", metric: "score_p50" })),
      ]);
      if (seq !== st.seq || st.dead) return;
      st.doc = main;
      st.aps = aps;
      st.error = "";
    } catch (e) {
      if (seq !== st.seq || st.dead) return;
      st.error = errText(e, "Could not load the breakdown.");
    }
    render();
  }

  const unit = () => ({ score_p50: "", down_p50: " Mb/s", up_p50: " Mb/s", loaded_p50: " ms", count: "" })[st.metric];

  function mainPanel() {
    const label = (GROUPS.find((g) => g[0] === st.group) || GROUPS[0])[1];
    const items = ((st.doc && st.doc.items) || []).slice();
    if (st.group === "hour") items.sort((a, b) => String(a.key).localeCompare(String(b.key)));
    else if (st.metric === "score_p50") items.sort((a, b) => a.value - b.value);
    else items.sort((a, b) => b.value - a.value);
    const rows = items.slice(0, 40).map((i) => ({
      key: i.key, label: st.group === "hour" ? hourLabel(i.key) : String(i.key), value: i.value,
      state: st.metric === "score_p50" ? scoreState(i.value) : "", text: fmt(i.value, st.metric === "count" ? 0 : undefined) + unit() + "  (" + i.count + " tests" + (i.approximate ? ", approx." : "") + ")",
    }));
    return h("div", { class: "panel st-panel", id: "st-breakdown" }, h("h2", { text: (METRICS.find((m) => m[0] === st.metric) || METRICS[0])[1] + " by " + label.toLowerCase() }),
      rows.length ? barRows(rows, { label: "Breakdown by " + label, max: st.metric === "score_p50" ? 100 : undefined }) : h("p", { class: "empty", text: "No tests in this range." }),
      items.length > 40 ? h("p", { class: "sub", text: "Showing 40 of " + items.length + "." }) : null);
  }

  function worstAps() {
    const items = ((st.aps && st.aps.items) || []).filter((i) => num(i.value) && i.count >= st.minN).sort((a, b) => a.value - b.value || b.count - a.count).slice(0, 10);
    return h("div", { class: "panel st-panel", id: "st-worst" }, h("h2", { text: "Worst 10 APs by median score" }),
      h("p", { class: "sub" }, "Only APs with at least ", h("strong", { text: String(st.minN) }), " tests are ranked."),
      items.length ? h("div", { class: "scroll" }, h("table", { class: "worst-table" },
        h("thead", {}, h("tr", {}, ["#", "AP", "Median score", "Tests"].map((t) => h("th", { scope: "col", text: t })))),
        h("tbody", {}, items.map((i, n) => {
          const sv = scoreState(i.value);
          return h("tr", { data: { ap: i.key, state: sv } }, h("td", { text: String(n + 1) }), h("td", { text: i.key }),
            h("td", {}, h("span", { class: "badge st-" + sv }, icon(STATE_ICON[sv]), h("span", { class: "badge-text", text: Math.round(i.value) + " " + SCORE_WORD[sv] + (i.approximate ? " (approx.)" : "") }))),
            h("td", {}, h("a", { href: "/speedtests?ap=" + encodeURIComponent(i.key) + "&range=" + st.range, "data-spa": "", text: String(i.count) + " tests", "aria-label": "Tests on AP " + i.key })));
        })))) : h("p", { class: "empty", text: "No AP has " + st.minN + " or more tests in this range." }));
  }

  function controls() {
    const sel = (id, label, list, key, after) => field(label, select(id, list, String(st[key]), (v) => { st[key] = key === "minN" ? Number(v) : v; syncUrl(); (after || load)(); }));
    return viewHead("Breakdowns",
      sel("b-group", "Group by", GROUPS, "group"), sel("b-metric", "Metric", METRICS, "metric"),
      sel("b-leg", "Leg", [["local", "Local"], ["internet", "Internet"]], "leg"),
      sel("b-range", "Range", RANGES.map((r) => [r[0], r[1]]), "range"),
      sites().length > 1 ? sel("b-site", "Site", [["", "All sites"], ...sites().map((x) => [x, x])], "site") : null,
      sel("b-min", "Min tests per AP", MIN_N.map((n) => [String(n), String(n)]), "minN", render));
  }

  function render() {
    clear(body);
    body.append(controls(), collectorBanner(st.doc && st.doc.collectors), errorBanner(st.error));
    if (!st.doc && !st.error) { body.append(h("p", { class: "sub", text: "Loading..." })); return; }
    if (st.doc) body.append(h("div", { class: "st-grid" }, mainPanel(), worstAps()));
  }

  render();
  load();
  const poll = opts.static ? null : setInterval(load, 60000);
  return { destroy() { st.dead = true; if (poll) clearInterval(poll); clear(root); } };
}
