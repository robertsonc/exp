// Overview (/): every probe's State-lite across all collectors, grouped by site.
// UX ported from reference/exm/lib/exm/static/overview.html (headline count, one row per probe with line dots,
// worst first); federation and the partial-results banner are the dashboard's own (spec 04 section 3).
import { api, qs, ApiError } from "./api.js";
import { h, clear, icon, normState, STATE_ICON, STATE_WORD, isSlug } from "./dom.js";
import { Live } from "./stream.js";
import { titleCase, dur, parseTs, lineLabel, lineIcon, LINE_ORDER, SEV_RANK, staleAfterS } from "./util.js";

const POLL_MS = 8000;

export function mountOverview(root, opts) {
  const kiosk = !!opts.kiosk;
  const st = { probes: new Map(), states: new Map(), collectors: [], error: "", live: null, dead: false, maxT: new Map(), newest: new Map() };

  const el = {
    headline: h("h1", { class: "headline", id: "headline", "aria-live": "polite", text: "Checking every probe..." }),
    sub: h("p", { class: "sub" }),
    partial: h("div", { class: "banner banner-partial", role: "alert", hidden: true }),
    error: h("div", { class: "banner banner-error", role: "alert", hidden: true }),
    groups: h("div", { class: "sites" }),
  };
  root.append(h("section", { class: "overview", "aria-label": "All probes" }, el.partial, el.error, el.headline, el.sub, el.groups));

  function ageOf(probe) {
    const t = st.newest.get(probe);
    return t === undefined ? null : (Date.now() - t) / 1000;
  }

  function rows() {
    const out = [];
    for (const [id, lite] of st.states) {
      const p = st.probes.get(id) || {};
      const age = ageOf(id);
      const stale = age === null || age > staleAfterS(p.cadence_s);
      out.push({ id, lite, label: String(p.label || id), site: String(lite.site || p.site || ""), age, stale,
        sev: stale ? "unknown" : normState(lite.severity) });
    }
    for (const [id, p] of st.probes) {
      if (st.states.has(id)) continue;
      const age = ageOf(id);
      out.push({ id, lite: { headline: "No state yet", lines: [] }, label: String(p.label || id), site: String(p.site || ""), age, stale: true, sev: "unknown" });
    }
    return out;
  }

  function render() {
    const all = rows();
    const need = all.filter((r) => r.sev !== "ok").length;
    el.headline.textContent = !all.length ? "No probes yet." : need ? need + " of " + all.length + (all.length > 1 ? " probes need" : " probe needs") + " a look."
      : all.length > 1 ? "All " + all.length + " probes are good." : "The probe is good.";
    el.headline.dataset.need = String(need);
    el.sub.textContent = !all.length && !st.error ? "Probes appear here once a collector reports them." : "";
    const down = st.collectors.filter((c) => c && c.ok === false);
    el.partial.hidden = !down.length;
    clear(el.partial);
    if (down.length) {
      el.partial.append(icon("alert"), h("div", {}, h("strong", { text: "Partial results. " }),
        h("ul", {}, down.map((c) => h("li", { text: (c.site ? titleCase(String(c.site)) : String(c.collector_id)) + " collector unreachable" }))),
        h("span", { text: "Probes served by it are not shown." })));
    }
    el.error.hidden = !st.error;
    el.error.textContent = st.error;
    clear(el.groups);
    const bySite = new Map();
    for (const r of all) { const a = bySite.get(r.site) || []; a.push(r); bySite.set(r.site, a); }
    const worst = (a) => Math.min(...a.map((r) => SEV_RANK[r.sev]));
    const sites = [...bySite.entries()].sort((a, b) => worst(a[1]) - worst(b[1]) || a[0].localeCompare(b[0]));
    for (const [site, list] of sites) {
      list.sort((a, b) => SEV_RANK[a.sev] - SEV_RANK[b.sev] || a.label.localeCompare(b.label));
      const bad = list.filter((r) => r.sev !== "ok").length;
      el.groups.appendChild(h("section", { class: "site", data: { site }, "aria-label": titleCase(site) },
        h("h2", { class: "site-name" }, icon("site"), titleCase(site) || "No site",
          h("span", { class: "site-count", text: bad ? bad + " of " + list.length + " need a look" : list.length + (list.length === 1 ? " probe" : " probes") + ", all good" }),
          site ? h("a", { class: "site-lines", href: "/site/" + encodeURIComponent(site) + "/lines", "data-spa": "", text: "Lines board" }) : null),
        h("ul", { class: "probe-rows" }, list.map(row))));
    }
  }

  function row(r) {
    const lines = Array.isArray(r.lite.lines) ? r.lite.lines.slice().sort((a, b) => LINE_ORDER.indexOf(a.key) - LINE_ORDER.indexOf(b.key)) : [];
    const live = r.age !== null && !r.stale;
    const fresh = r.age === null ? "no results" : r.stale ? "stale " + dur(r.age) : "live";
    const link = isSlug(r.id) ? "/probe/" + r.id : "/";
    // kiosk rows are plain boxes: a wall screen has nothing to click
    return h("li", {}, h(kiosk ? "div" : "a", { class: "row st-" + r.sev, href: kiosk ? null : link, "data-spa": kiosk ? null : "", data: { probe: r.id, sev: r.sev, live: live ? "true" : "false" } },
      h("span", { class: "row-name", text: r.label }),
      h("span", { class: "chips", "aria-label": "Lines" }, lines.map((l) => {
        const s = normState(l.state);
        return h("span", { class: "chip st-" + s, data: { line: l.key, state: s }, title: lineLabel(l.key) + ": " + STATE_WORD[s] },
          icon(STATE_ICON[s]), icon(lineIcon(l.key), "chip-line"), h("span", { class: "chip-text", text: lineLabel(l.key) }), h("span", { class: "sr", text: " " + STATE_WORD[s] }));
      })),
      h("span", { class: "row-say" }, r.stale ? "Nothing current: " : "", h("span", { class: "row-headline", text: String(r.lite.headline || "") })),
      h("span", { class: "fresh " + (live ? "is-live" : "is-stale"), text: fresh })));
  }

  async function load() {
    try {
      const q = opts.site && isSlug(opts.site) ? { site: opts.site } : {};
      const [pr, sr] = await Promise.all([api("/api/v1/probes" + qs(q)), api("/api/v1/states" + qs(q))]);
      if (st.dead) return;
      st.error = "";
      st.collectors = Array.isArray(sr.collectors) ? sr.collectors : Array.isArray(pr.collectors) ? pr.collectors : [];
      st.probes = new Map((pr.items || []).filter((p) => p && isSlug(p.probe)).map((p) => [p.probe, p]));
      st.states = new Map((sr.items || []).filter((p) => p && isSlug(p.probe)).map((p) => [p.probe, p]));
      for (const [id, p] of st.probes) {
        const t = parseTs(p.last_seen);
        if (Number.isFinite(t)) st.maxT.set(id, t);
        if (typeof p.newest_s === "number") st.newest.set(id, Date.now() - p.newest_s * 1000); else st.newest.delete(id);
      }
      render();
      ensureStream();
    } catch (e) {
      if (st.dead) return;
      st.error = e instanceof ApiError ? e.message : "Could not load the probes.";
      render();
    }
  }

  let streamKey = "";
  function ensureStream() {
    if (opts.static) return;
    const ids = [...new Set([...st.probes.keys(), ...st.states.keys()])].sort().slice(0, 200);
    const key = ids.join(",");
    if (key === streamKey) return;
    if (st.live) st.live.close();
    streamKey = key;
    st.live = ids.length ? new Live({ probes: key }, {
      state: (e) => { if (isSlug(e.probe)) { st.states.set(e.probe, e); render(); } },
      beat: (e) => {
        if (!isSlug(e.probe) || !Number.isFinite(e.t)) return;
        if (e.t > (st.maxT.get(e.probe) || 0)) { st.maxT.set(e.probe, e.t); st.newest.set(e.probe, Date.now()); }
      },
      collector: (e) => {
        const c = st.collectors.find((x) => x.collector_id === e.collector_id);
        if (c && typeof e.ok === "boolean") { c.ok = e.ok; render(); load(); }
      },
      reconnected: () => load(),
    }) : null;
  }

  load();
  const poll = opts.static ? null : setInterval(load, POLL_MS);
  const tick = opts.static ? null : setInterval(render, 5000);
  return {
    destroy() {
      st.dead = true;
      if (poll) clearInterval(poll);
      if (tick) clearInterval(tick);
      if (st.live) st.live.close();
      clear(root);
    },
  };
}
