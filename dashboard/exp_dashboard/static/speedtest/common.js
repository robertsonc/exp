// Speedtest analytics: shared helpers (12 section 8). Every string from the API (comment, hostname, AP name, SSID...)
// is user- or network-supplied and reaches the page only through dom.js (textContent). Raw client identifiers are
// never requested by the browser unless the session is an admin; the dashboard enforces that server-side as well.
import { api, qs, session, ApiError } from "../js/api.js";
import { h, s, clear, icon, normState, STATE_ICON, STATE_WORD } from "../js/dom.js";
import { titleCase } from "../js/util.js";

export { api, qs, ApiError, h, s, clear, icon, normState, STATE_ICON, STATE_WORD };

export const ST_ID = /^st_[0-9A-HJKMNP-TV-Z]{26}$/;
export const ST_ID_FIND = /st_[0-9A-HJKMNP-TV-Z]{26}/;
export const isAdmin = () => !!session && session.role === "admin";
export const isStId = (v) => typeof v === "string" && ST_ID.test(v);

export const CAUSE = {
  wifi_signal: "Weak Wi-Fi signal", wifi_congestion: "Wi-Fi congestion", wifi_roaming: "Roaming trouble",
  wired_port: "Wired port problem", device_limit: "Device limit", wan_saturation: "WAN saturated",
  internet_path: "Internet path", policy_block: "Blocked by policy", qos_shaping: "QoS shaping", dns: "DNS slow",
  network_wide: "Network-wide issue", none: "No problem found", unknown: "Could not pinpoint",
};
export const causeLabel = (id) => CAUSE[id] || (id ? String(id) : CAUSE.unknown);

export const RANGES = [["1h", "Last hour", 3600], ["6h", "Last 6 hours", 6 * 3600], ["24h", "Last 24 hours", 86400],
  ["7d", "Last 7 days", 7 * 86400], ["30d", "Last 30 days", 30 * 86400]];
export const rangeSeconds = (key) => (RANGES.find((r) => r[0] === key) || RANGES[2])[2];

// score -> state: >= 80 is "good" (the collector's none_score), 50..79 needs a look, below 50 is poor.
export function scoreState(v) {
  if (typeof v !== "number" || !Number.isFinite(v)) return "unknown";
  return v >= 80 ? "ok" : v >= 50 ? "warn" : "fail";
}
export const SCORE_WORD = { ok: "Good", warn: "Fair", fail: "Poor", unknown: "No score" };

// icon + number + word, never colour alone
export function scoreBadge(v) {
  const st = scoreState(v);
  return h("span", { class: "badge st-" + st, data: { state: st } }, icon(STATE_ICON[st]),
    h("span", { class: "badge-text", text: (typeof v === "number" ? Math.round(v) + " " : "") + SCORE_WORD[st] }));
}

export const num = (v) => typeof v === "number" && Number.isFinite(v);
export function fmt(v, digits, unit) {
  if (!num(v)) return "-";
  const d = digits === undefined ? (Math.abs(v) >= 100 ? 0 : Math.abs(v) >= 10 ? 1 : 2) : digits;
  return v.toFixed(d) + (unit ? " " + unit : "");
}
export const mbps = (v) => fmt(v, undefined, "Mb/s");
export const ms = (v) => fmt(v, undefined, "ms");
export function bytes(v) {
  if (!num(v)) return "-";
  const u = ["B", "kB", "MB", "GB", "TB"];
  let i = 0;
  let x = v;
  while (x >= 1000 && i < u.length - 1) { x /= 1000; i++; }
  return (i ? x.toFixed(x >= 100 ? 0 : 1) : String(Math.round(x))) + " " + u[i];
}
export function median(a) {
  const v = a.filter(num).sort((x, y) => x - y);
  if (!v.length) return null;
  const m = v.length >> 1;
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
}

export function collectorBanner(collectors) {
  const bad = (collectors || []).filter((c) => c && c.ok === false);
  const box = h("div", { class: "banner banner-partial", role: "alert", hidden: !bad.length, data: { partial: bad.length ? "true" : "false" } });
  if (bad.length) {
    box.append(icon("alert"), h("div", {}, h("strong", { text: "Partial results. " }),
      h("ul", {}, bad.map((c) => h("li", { text: (c.site ? titleCase(String(c.site)) : String(c.collector_id)) +
        (c.error === "speedtests_disabled" ? " collector has speedtest analytics turned off" : " collector unreachable") }))),
      h("span", { text: "Tests held by it are not included." })));
  }
  return box;
}

export function errorBanner(msg) {
  return h("div", { class: "banner banner-error", role: "alert", hidden: !msg, text: msg || "" });
}
export const errText = (e, fallback) => (e instanceof ApiError ? e.message : fallback);

// Sites the dashboard federates (session.collectors) for the filter.
export function sites() {
  const out = new Set();
  for (const c of (session && session.collectors) || []) if (c && typeof c.site === "string") out.add(c.site);
  return [...out].sort();
}

export function field(label, control, id) {
  return h("div", { class: "field" }, h("label", { for: id, text: label }), control);
}
export function select(id, options, value, onchange) {
  const el = h("select", { id }, options.map(([v, label]) => h("option", { value: v, text: label, selected: v === value })));
  el.value = value;
  if (onchange) el.addEventListener("change", () => onchange(el.value));
  return el;
}

// Horizontal bar rows: label | bar | value. Width goes through a CSS custom property (no inline styles).
export function barRows(items, opts) {
  const o = opts || {};
  const max = Math.max(1, ...items.map((i) => i.value));
  return h("ul", { class: "bars", "aria-label": o.label || null }, items.map((i) => h("li", { class: "bar-row" + (i.state ? " st-" + i.state : ""), data: { key: i.key } },
    h("span", { class: "bar-label", text: i.label }),
    h("span", { class: "bar-track", "aria-hidden": "true" }, h("span", { class: "bar-fill", vars: { "--w": Math.max(1, (i.value / (o.max || max)) * 100).toFixed(1) } })),
    h("span", { class: "bar-value", text: i.text !== undefined ? i.text : String(i.value) }))));
}

export function stat(label, value, sub, extra) {
  return h("div", { class: "stat" + (extra ? " " + extra : "") }, h("span", { class: "stat-label", text: label }),
    h("span", { class: "stat-value", text: value }), sub ? h("span", { class: "stat-sub", text: sub }) : null);
}

export function viewHead(title, ...tools) {
  return h("div", { class: "st-head" }, h("h1", { class: "st-title", text: title }), h("div", { class: "head-tools st-tools" }, ...tools));
}

export const hourLabel = (key) => {
  const t = Date.parse(key);
  return Number.isFinite(t) ? new Date(t).toISOString().slice(11, 13) + ":00" : String(key);
};

export async function loadAll(path, params, pages) {
  // follows the composite cursor until exhausted or `pages` pages (a list is capped; the overview says so)
  const items = [];
  let collectors = [];
  let cursor = "";
  for (let i = 0; i < (pages || 1); i++) {
    const doc = await api(path + qs({ ...params, cursor }));
    items.push(...(Array.isArray(doc.items) ? doc.items : []));
    collectors = Array.isArray(doc.collectors) ? doc.collectors : collectors;
    cursor = doc.next_cursor || "";
    if (!cursor) return { items, collectors, more: false };
  }
  return { items, collectors, more: true };
}

export function iso(msv) { return new Date(msv).toISOString().replace(/\.\d{3}Z$/, "Z"); }
export const testLink = (id) => "/speedtests/test/" + id;

// Sub navigation shared by the speedtest views.
export function subNav(active) {
  const items = [["overview", "/speedtests", "Overview"], ["breakdowns", "/speedtests/breakdowns", "Breakdowns"], ["support", "/speedtests/support", "Support lookup"]];
  return h("nav", { class: "st-subnav", "aria-label": "Speedtest views" }, items.map(([k, href, label]) =>
    h("a", { class: "st-subnav-link", href, "data-spa": "", "aria-current": k === active ? "page" : null, text: label })));
}
