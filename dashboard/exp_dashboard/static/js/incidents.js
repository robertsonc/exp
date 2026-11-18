// Incidents (/incidents): filterable list; operators acknowledge; every row links to the board at the incident start.
import { api, qs, ApiError, isOperator, session } from "./api.js";
import { h, clear, icon, isSlug } from "./dom.js";
import { Live } from "./stream.js";
import { fmtDateTime, parseTs, toIso, titleCase, lineLabel, lineIcon, LINE_ORDER, dur } from "./util.js";

const INC_ID = /^inc_[0-9A-Za-z]{10,40}$/;

export function mountIncidents(root, opts) {
  const st = { items: [], collectors: [], error: "", dead: false, live: null, notes: new Map(), busy: new Set() };
  const q0 = new URLSearchParams(location.search);
  const f = { open: ["true", "false"].includes(q0.get("open")) ? q0.get("open") : (q0.has("open") ? "" : "true"), site: q0.get("site") || "", line: q0.get("line") || "", q: q0.get("q") || "" };
  if (!isSlug(f.site)) f.site = "";

  const el = {
    open: h("select", { id: "f-open" }, h("option", { value: "true", text: "Open" }), h("option", { value: "false", text: "Resolved" }), h("option", { value: "", text: "All" })),
    site: h("select", { id: "f-site" }, h("option", { value: "", text: "All sites" })),
    line: h("select", { id: "f-line" }, h("option", { value: "", text: "All lines" }), LINE_ORDER.map((k) => h("option", { value: k, text: lineLabel(k) }))),
    q: h("input", { id: "f-q", type: "search", placeholder: "Probe or text", maxlength: "80", autocomplete: "off" }),
    list: h("ul", { class: "inc-rows" }),
    count: h("p", { class: "sub", role: "status" }),
    partial: h("div", { class: "banner banner-partial", role: "alert", hidden: true }),
    error: h("div", { class: "banner banner-error", role: "alert", hidden: true }),
  };
  el.open.value = f.open;
  el.line.value = LINE_ORDER.includes(f.line) ? f.line : "";
  el.q.value = f.q.slice(0, 80);
  const field = (label, ctl) => h("div", { class: "field" }, h("label", { for: ctl.id, text: label }), ctl);
  const form = h("form", { class: "filters", role: "search", on: { submit: (e) => e.preventDefault() } },
    field("Status", el.open), field("Site", el.site), field("Line", el.line), field("Search", el.q));
  root.append(h("section", { class: "incidents", "aria-label": "Incidents" }, h("h1", { class: "headline", text: "Incidents" }), el.count, el.partial, el.error, form, el.list));

  function syncUrl() {
    const p = new URLSearchParams();
    if (f.open !== "true") p.set("open", f.open);
    if (f.site) p.set("site", f.site);
    if (f.line) p.set("line", f.line);
    if (f.q) p.set("q", f.q);
    const s = p.toString();
    history.replaceState(null, "", "/incidents" + (s ? "?" + s : ""));
  }

  el.open.addEventListener("change", () => { f.open = el.open.value; syncUrl(); load(); });
  el.site.addEventListener("change", () => { f.site = el.site.value; syncUrl(); load(); });
  el.line.addEventListener("change", () => { f.line = el.line.value; syncUrl(); render(); });
  el.q.addEventListener("input", () => { f.q = el.q.value.trim().slice(0, 80); syncUrl(); render(); });

  function visible() {
    const needle = f.q.toLowerCase();
    return st.items.filter((i) => (!f.line || i.line === f.line) && (!f.site || i.site === f.site) &&
      (f.open === "" || (f.open === "true") === (i.end === null)) &&
      (!needle || (String(i.probe) + " " + String(i.line) + " " + (Array.isArray(i.facts) ? i.facts.join(" ") : "")).toLowerCase().includes(needle)))
      .sort((a, b) => parseTs(b.start) - parseTs(a.start));
  }

  function render() {
    const items = visible();
    el.count.textContent = items.length + (items.length === 1 ? " incident" : " incidents") + (f.open === "true" ? " open" : "");
    const down = st.collectors.filter((c) => c && c.ok === false);
    el.partial.hidden = !down.length;
    clear(el.partial);
    if (down.length) el.partial.append(icon("alert"), h("span", { text: "Partial results: " + down.map((c) => (c.site ? titleCase(String(c.site)) : String(c.collector_id)) + " collector unreachable").join("; ") }));
    el.error.hidden = !st.error;
    el.error.textContent = st.error;
    clear(el.list);
    if (!items.length) el.list.appendChild(h("li", { class: "empty", text: "Nothing matches these filters." }));
    for (const i of items) el.list.appendChild(row(i));
  }

  function row(i) {
    const open = i.end === null;
    const start = parseTs(i.start);
    const end = parseTs(i.end);
    const boardHref = isSlug(i.probe) ? "/probe/" + i.probe + "?at=" + encodeURIComponent(Number.isFinite(start) ? toIso(start) : "") : "/";
    const acked = typeof i.acked_by === "string" && i.acked_by;
    const where = i.where && typeof i.where === "object" ? [i.where.seg, i.where.ip].filter(Boolean).join(" ") : "";
    const err = st.notes.get(i.id);
    const op = isOperator() && INC_ID.test(String(i.id));
    return h("li", { class: "incident " + (open ? "st-fail" : "st-ok"), data: { incident: i.id, open: open ? "true" : "false", acked: acked ? "true" : "false" } },
      h("div", { class: "inc-top" },
        h("span", { class: "badge " + (open ? "st-fail" : "st-ok") }, icon(open ? "alert" : "check"), h("span", { class: "badge-text", text: open ? "Open" : "Resolved" })),
        h("h3", {}, icon(lineIcon(i.line)), lineLabel(i.line) + " " + String(i.kind)),
        h("a", { class: "inc-probe", href: isSlug(i.probe) ? "/probe/" + i.probe : "/", "data-spa": "", text: String(i.probe) }),
        h("span", { class: "inc-site", text: titleCase(String(i.site)) })),
      Array.isArray(i.facts) && i.facts.length ? h("ul", { class: "inc-facts" }, i.facts.slice(0, 5).map((t) => h("li", { text: String(t) }))) : null,
      where ? h("p", { class: "inc-where", text: "Where: " + where }) : null,
      h("p", { class: "inc-meta" }, h("time", { datetime: i.start, text: fmtDateTime(start) }),
        open ? " - ongoing" : " - ended " + fmtDateTime(end) + (Number.isFinite(end - start) ? " (" + dur((end - start) / 1000) + ")" : ""),
        acked ? " - acknowledged by " + acked : ""),
      h("div", { class: "inc-actions" },
        h("a", { class: "btn", href: boardHref, "data-spa": "" }, icon("rewind"), "View board at start"),
        op && !acked ? h("button", { class: "btn btn-primary ack", type: "button", disabled: st.busy.has(i.id), on: { click: () => ack(i) } }, icon("check"), "Acknowledge") : null),
      err ? h("p", { class: "inline-error", role: "alert", text: err }) : null);
  }

  async function ack(i) {
    if (st.busy.has(i.id)) return;
    st.busy.add(i.id);
    st.notes.delete(i.id);
    render();
    try {
      await api("/api/v1/incidents/" + i.id + "/ack", { method: "POST", json: {} });
      i.acked_by = session ? session.user : "you";
    } catch (e) {
      st.notes.set(i.id, e instanceof ApiError ? "Could not acknowledge: " + e.message : "Could not acknowledge.");
    }
    st.busy.delete(i.id);
    if (!st.dead) render();
  }

  async function load() {
    try {
      const d = await api("/api/v1/incidents" + qs({ open: f.open || undefined, site: f.site || undefined }));
      if (st.dead) return;
      st.error = "";
      st.items = (d.items || []).filter((i) => i && typeof i.id === "string" && typeof i.start === "string");
      st.collectors = Array.isArray(d.collectors) ? d.collectors : [];
      const sites = [...new Set(st.items.map((i) => i.site).filter(isSlug))].sort();
      const have = new Set([...el.site.options].map((o) => o.value));
      for (const s of sites) if (!have.has(s)) el.site.appendChild(h("option", { value: s, text: titleCase(s) }));
      el.site.value = f.site;
      render();
    } catch (e) {
      if (st.dead) return;
      st.error = e instanceof ApiError ? e.message : "Could not load incidents.";
      render();
    }
  }

  async function startStream() {
    if (opts.static) return;
    try {
      const d = await api("/api/v1/probes");
      const ids = (d.items || []).map((p) => p.probe).filter(isSlug).slice(0, 200);
      if (st.dead || !ids.length) return;
      st.live = new Live({ probes: ids.join(",") }, {
        incident: (e) => {
          if (typeof e.id !== "string" || typeof e.start !== "string") return;
          const k = st.items.findIndex((x) => x.id === e.id);
          if (k >= 0) st.items[k] = e; else st.items.push(e);
          render();
        },
        reconnected: () => load(),
      });
    } catch (e) {
      st.error = e instanceof ApiError ? e.message : "";
    }
  }

  load();
  startStream();
  const poll = opts.static ? null : setInterval(load, 20000);
  return {
    destroy() {
      st.dead = true;
      if (poll) clearInterval(poll);
      if (st.live) st.live.close();
      clear(root);
    },
  };
}
