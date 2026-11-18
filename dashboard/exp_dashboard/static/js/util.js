// Formatting and small helpers shared by the views.
let tz;

export function setTimezone(name) {
  try {
    new Intl.DateTimeFormat("en-GB", { timeZone: name });
    tz = name;
  } catch (e) {
    tz = undefined;
  }
}

const hms = () => new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: tz });
const hm = () => new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: tz });
const dt = () => new Intl.DateTimeFormat("en-GB", { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: tz });

export const fmtHMS = (ms) => (Number.isFinite(ms) ? hms().format(new Date(ms)) : "-");
export const fmtHM = (ms) => (Number.isFinite(ms) ? hm().format(new Date(ms)) : "-");
export const fmtDateTime = (ms) => (Number.isFinite(ms) ? dt().format(new Date(ms)) : "-");

export function parseTs(iso) {
  if (typeof iso !== "string") return NaN;
  return Date.parse(iso);
}

export function toIso(ms) {
  return new Date(ms).toISOString();
}

export function dur(sec) {
  const s = Math.max(0, Math.round(sec));
  if (s < 90) return s + " s";
  const m = Math.round(s / 60);
  if (m < 90) return m + " min";
  const hh = Math.floor(m / 60);
  const r = m % 60;
  return hh + " h" + (r ? " " + r + " min" : "");
}

export function titleCase(slug) {
  return String(slug || "")
    .split("-")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export const LINE_LABEL = { network: "Network", dhcp: "DHCP", dns: "DNS", internet: "Internet", apps: "Apps", wifi: "Wi-Fi", path: "Path", probe: "Probe" };
export const LINE_ORDER = ["network", "dhcp", "dns", "internet", "apps", "wifi", "path"];
// Incident.line additionally allows "probe" (silent-probe incident, CR-wp2-incident-line-probe); it is not a State line.
export const INCIDENT_LINE_ORDER = [...LINE_ORDER, "probe"];
export const lineLabel = (k) => LINE_LABEL[k] || String(k);
export const lineIcon = (k) => (LINE_LABEL[k] ? k : "probe");
export const SEV_RANK = { fail: 0, warn: 1, unknown: 2, ok: 3 };

// Only same-origin absolute paths are followed after login.
export function safeNext(v) {
  if (typeof v !== "string" || !v.startsWith("/") || v.startsWith("//") || v.includes("\\") || /[\x00-\x1f]/.test(v)) return "/";
  return v;
}

export function debounce(fn, ms) {
  let t = null;
  const wrapped = (...a) => {
    if (t) clearTimeout(t);
    t = setTimeout(() => { t = null; fn(...a); }, ms);
  };
  wrapped.cancel = () => { if (t) clearTimeout(t); t = null; };
  return wrapped;
}

export function pref(name, value) {
  try {
    if (value === undefined) return window.localStorage.getItem("exp." + name);
    if (value === null) window.localStorage.removeItem("exp." + name);
    else window.localStorage.setItem("exp." + name, value);
  } catch (e) {
    return null;
  }
  return value;
}
