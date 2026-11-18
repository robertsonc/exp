// Formatting rules from docs/spec/11-manager-ui.md section 6. Pure functions, no DOM.

export const DASH = '—';

function isNum(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

/** Significant-digit style: one decimal under 10, none from 10 up. */
function compact(n: number): string {
  const a = Math.abs(n);
  if (a < 10) return String(Math.round(n * 10) / 10);
  return String(Math.round(n));
}

/** Packets per second with SI suffixes: `41.2k pps`. */
export function formatPps(v: number | null | undefined): string {
  if (!isNum(v)) return DASH;
  const a = Math.abs(v);
  if (a >= 1000) {
    // 41.2k keeps one decimal below 100k
    let x = a;
    let i = 0;
    const u = ['', 'k', 'M', 'G'];
    while (x >= 1000 && i < u.length - 1) {
      x /= 1000;
      i += 1;
    }
    const s = x < 100 ? (Math.round(x * 10) / 10).toFixed(1) : String(Math.round(x));
    return `${s}${u[i]} pps`;
  }
  return `${compact(v)} pps`;
}

/** Bit rates (input in bits per second) in kb/s, Mb/s or Gb/s. */
export function formatBps(v: number | null | undefined): string {
  if (!isNum(v)) return DASH;
  const a = Math.abs(v);
  if (a >= 1e9) return `${compact(v / 1e9)} Gb/s`;
  if (a >= 1e5) return `${a < 1e6 ? (Math.round(v / 1e4) / 100).toFixed(2) : compact(v / 1e6)} Mb/s`;
  if (a >= 1e3) return `${compact(v / 1e3)} kb/s`;
  return `${compact(v)} b/s`;
}

/** Mb/s with two decimals under 1 (used where a column fixes the unit). */
export function formatMbps(v: number | null | undefined): string {
  if (!isNum(v)) return DASH;
  const m = v / 1e6;
  if (m >= 1000) return `${compact(m / 1000)} Gb/s`;
  if (m < 1) return `${(Math.round(m * 100) / 100).toFixed(2)} Mb/s`;
  return `${compact(m)} Mb/s`;
}

/** Binary byte units. */
export function formatBytes(v: number | null | undefined): string {
  if (!isNum(v)) return DASH;
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let x = Math.abs(v);
  let i = 0;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i += 1;
  }
  const s = i === 0 ? String(Math.round(x)) : compact(x);
  return `${v < 0 ? '-' : ''}${s} ${units[i]}`;
}

/** Gigabytes reported by agents (treated as GiB) to a binary unit string. */
export function formatGiB(v: number | null | undefined): string {
  if (!isNum(v)) return DASH;
  return formatBytes(v * 1024 ** 3);
}

/** Megabytes (MiB) to a binary unit string. */
export function formatMiB(v: number | null | undefined): string {
  if (!isNum(v)) return DASH;
  return formatBytes(v * 1024 ** 2);
}

/** Whole percentages, one decimal under 10 %. */
export function formatPct(v: number | null | undefined): string {
  if (!isNum(v)) return DASH;
  if (Math.abs(v) < 10) return `${(Math.round(v * 10) / 10).toFixed(1)}%`;
  return `${Math.round(v)}%`;
}

/** Generic count with SI suffix for large values (18.2k). */
export function formatCount(v: number | null | undefined, digits = 1): string {
  if (!isNum(v)) return DASH;
  const a = Math.abs(v);
  if (a >= 1e6) return `${(v / 1e6).toFixed(digits)}M`;
  if (a >= 1e4) return `${(v / 1e3).toFixed(digits)}k`;
  if (a >= 1000) return `${(v / 1e3).toFixed(digits)}k`;
  if (a < 10 && !Number.isInteger(v)) return String(Math.round(v * 10) / 10);
  return String(Math.round(v));
}

/** Rate per second / minute: `305/s`. */
export function formatRate(v: number | null | undefined, per: 's' | 'min'): string {
  if (!isNum(v)) return DASH;
  return `${formatCount(v)}/${per}`;
}

/** Durations: `45 s`, `12 min`, `4 h 12 min`, `12 d 4 h`. */
export function formatDuration(seconds: number | null | undefined): string {
  if (!isNum(seconds) || seconds < 0) return DASH;
  const s = Math.floor(seconds);
  if (s < 60) return `${s} s`;
  const min = Math.floor(s / 60);
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  if (h < 24) {
    const m = min % 60;
    return m ? `${h} h ${m} min` : `${h} h`;
  }
  const d = Math.floor(h / 24);
  const hh = h % 24;
  return hh ? `${d} d ${hh} h` : `${d} d`;
}

/** Relative time for lists: `45 s ago`. `nowMs` is the (skew-corrected) current time. */
export function formatAgo(ts: string | number | null | undefined, nowMs: number): string {
  const ms = toMs(ts);
  if (ms === null) return DASH;
  const diff = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (diff < 5) return 'just now';
  return `${formatDuration(diff)} ago`;
}

export function toMs(ts: string | number | null | undefined): number | null {
  if (ts === null || ts === undefined) return null;
  if (typeof ts === 'number') return Number.isFinite(ts) ? ts : null;
  const ms = Date.parse(ts);
  return Number.isNaN(ms) ? null : ms;
}

function fmtIn(ms: number, tz: string | undefined, opts: Intl.DateTimeFormatOptions = {}): string {
  const base: Intl.DateTimeFormatOptions = {
    year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false, timeZoneName: 'short', ...opts,
  };
  try {
    return new Intl.DateTimeFormat('en-GB', { ...base, ...(tz ? { timeZone: tz } : {}) }).format(ms);
  } catch {
    // Invalid time zone name from an untrusted source: fall back to UTC.
    return new Intl.DateTimeFormat('en-GB', { ...base, timeZone: 'UTC' }).format(ms);
  }
}

/** Absolute time in the site's timezone plus UTC, for tooltips. */
export function formatAbsolute(ts: string | number | null | undefined, tz?: string | null): string {
  const ms = toMs(ts);
  if (ms === null) return DASH;
  const utc = fmtIn(ms, 'UTC');
  if (!tz || tz === 'UTC') return utc;
  return `${fmtIn(ms, tz)} / ${utc}`;
}

/** Clock time only (chart axes and cursors). */
export function formatClock(ms: number, tz?: string | null, withDate = false): string {
  return fmtIn(ms, tz ?? 'UTC', withDate
    ? { year: undefined, second: undefined, timeZoneName: 'short' }
    : { year: undefined, month: undefined, day: undefined, second: undefined, timeZoneName: undefined });
}

export function formatVersion(v: number | null | undefined): string {
  return isNum(v) ? `v${v}` : DASH;
}

/** days-to-full projection label. */
export function formatDaysToFull(days: number | null | undefined): string {
  if (days === null || days === undefined) return 'no growth';
  if (!isNum(days)) return DASH;
  if (days < 1) return `${Math.max(0, Math.round(days * 24))} h to full`;
  if (days < 10) return `${Math.round(days * 10) / 10} days to full`;
  return `${Math.round(days)} days to full`;
}

/** Sort-friendly lowercase. */
export function collate(a: string, b: string): number {
  return a.localeCompare(b, 'en', { numeric: true, sensitivity: 'base' });
}
