// Tiny History-API router: real URLs, filters in the query string. No dependency.
import { useEffect, useState } from 'preact/hooks';

export interface Location {
  path: string;
  query: URLSearchParams;
}

function read(): Location {
  return { path: window.location.pathname.replace(/\/+$/, '') || '/', query: new URLSearchParams(window.location.search) };
}

const listeners = new Set<() => void>();

export function navigate(to: string, opts: { replace?: boolean } = {}): void {
  const url = new URL(to, window.location.origin);
  if (url.origin !== window.location.origin) return; // never navigate off-site from app code
  const target = url.pathname + url.search + url.hash;
  if (target === window.location.pathname + window.location.search + window.location.hash) return;
  if (opts.replace) window.history.replaceState(null, '', target);
  else window.history.pushState(null, '', target);
  for (const l of [...listeners]) l();
  if (!url.hash) window.scrollTo?.(0, 0);
}

export function initRouter(): () => void {
  const onPop = () => listeners.forEach((l) => l());
  window.addEventListener('popstate', onPop);
  return () => window.removeEventListener('popstate', onPop);
}

export function useLocation(): Location {
  const [loc, setLoc] = useState<Location>(read);
  useEffect(() => {
    const l = () => setLoc(read());
    listeners.add(l);
    l();
    return () => {
      listeners.delete(l);
    };
  }, []);
  return loc;
}

export interface Match { name: string; params: Record<string, string> }

const ROUTES: [string, RegExp, string[]][] = [
  ['fleet', /^\/(?:fleet)?$/, []],
  ['ops', /^\/ops$/, []],
  ['issues', /^\/issues$/, []],
  ['hosts', /^\/hosts$/, []],
  ['hostnew', /^\/hosts\/new$/, []],
  ['host', /^\/hosts\/(h_[0-9A-Za-z]+)$/, ['id']],
  ['component', /^\/hosts\/(h_[0-9A-Za-z]+)\/components\/(cmp_[0-9A-Za-z]+)$/, ['id', 'cid']],
  ['sites', /^\/sites$/, []],
  ['site', /^\/sites\/([a-z0-9][a-z0-9-]{0,63})$/, ['site']],
  ['speedtestsite', /^\/sites\/([a-z0-9][a-z0-9-]{0,63})\/speedtest$/, ['site']],
  ['speedtest', /^\/speedtest$/, []],
  ['releases', /^\/releases$/, []],
  ['dashboards', /^\/dashboards$/, []],
  ['drills', /^\/drills$/, []],
  ['audit', /^\/audit$/, []],
  ['settings', /^\/settings$/, []],
];

export function matchRoute(path: string): Match {
  for (const [name, re, keys] of ROUTES) {
    const m = re.exec(path);
    if (m) {
      const params: Record<string, string> = {};
      keys.forEach((k, i) => {
        params[k] = m[i + 1] ?? '';
      });
      return { name, params };
    }
  }
  return { name: 'notfound', params: {} };
}

/** Build a path with a query string, dropping empty values. */
export function href(path: string, query?: Record<string, string | null | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) if (v !== null && v !== undefined && v !== '') q.set(k, v);
  const s = q.toString();
  return s ? `${path}?${s}` : path;
}

/** Update some query params (replace-state; filters should not flood history). */
export function setQuery(patch: Record<string, string | null | undefined>, opts: { replace?: boolean } = { replace: true }): void {
  const q = new URLSearchParams(window.location.search);
  for (const [k, v] of Object.entries(patch)) {
    if (v === null || v === undefined || v === '') q.delete(k);
    else q.set(k, v);
  }
  const s = q.toString();
  navigate(window.location.pathname + (s ? `?${s}` : ''), opts);
}
