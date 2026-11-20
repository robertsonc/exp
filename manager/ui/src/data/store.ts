// Polling data layer (docs/spec/11-manager-ui.md section 2).
//  - one cache entry per endpoint URL, ETag / If-None-Match
//  - 30 s polling, paused while the tab is hidden, immediate refetch on focus and after mutations
//  - exponential backoff per entry; connection state drives the "can't reach the manager" banner
//  - 401 / 403 are surfaced as their own states and stop polling
import { POLL_MS, backoffMs } from '../lib/state';

export class ApiFailure extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiFailure';
    this.status = status;
    this.code = code;
  }
  /** Network-level or server-side trouble (as opposed to a definite answer like 404). */
  get transient(): boolean {
    return this.status === 0 || this.status >= 500 || this.status === 429 || this.status === 408;
  }
}

export interface Entry<T = unknown> {
  key: string;
  data: T | undefined;
  etag: string | null;
  fetchedAt: number | null; // client ms of the last successful fetch (200 or 304)
  error: ApiFailure | null;
  loading: boolean;
  failures: number;
  nextAt: number;
  paged: boolean;
}

export type AuthState = 'ok' | 'unauthorized' | 'forbidden';
export interface ConnState {
  auth: AuthState;
  authMessage: string;
  lastOk: number | null; // client ms of the last successful response of any endpoint
  failures: number; // consecutive failed polls (any endpoint) since the last success
  nextRetryAt: number | null;
  skewMs: number; // serverTime - clientTime, from the Date header
  version: number;
}

export interface StoreDeps {
  fetch: typeof fetch;
  now: () => number;
  timeoutMs: number;
  pollMs: number;
  isVisible: () => boolean;
}

export interface SubscribeOpts { paged?: boolean }
type Listener = () => void;

interface Slot { entry: Entry; subs: number; listeners: Set<Listener>; inflight: Promise<void> | null }

const MAX_PAGES = 20;

function envDeps(): StoreDeps {
  return {
    fetch: (...a) => window.fetch(...a),
    now: () => Date.now(),
    timeoutMs: 15_000,
    pollMs: POLL_MS,
    isVisible: () => document.visibilityState !== 'hidden',
  };
}

export class DataStore {
  private readonly d: StoreDeps;
  private readonly slots = new Map<string, Slot>();
  private readonly connListeners = new Set<Listener>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private conn_: ConnState = { auth: 'ok', authMessage: '', lastOk: null, failures: 0, nextRetryAt: null, skewMs: 0, version: 0 };

  constructor(deps: Partial<StoreDeps> = {}) {
    this.d = { ...envDeps(), ...deps };
  }

  /** Server-corrected current time. */
  now(): number {
    return this.d.now() + this.conn_.skewMs;
  }
  clientNow(): number {
    return this.d.now();
  }

  conn(): ConnState {
    return this.conn_;
  }
  subscribeConn(fn: Listener): () => void {
    this.connListeners.add(fn);
    return () => this.connListeners.delete(fn);
  }
  private setConn(patch: Partial<ConnState>): void {
    this.conn_ = { ...this.conn_, ...patch, version: this.conn_.version + 1 };
    for (const l of [...this.connListeners]) l();
  }

  entry<T = unknown>(key: string): Entry<T> | undefined {
    return this.slots.get(key)?.entry as Entry<T> | undefined;
  }

  /** Subscribe to a key. The first subscriber triggers a fetch; the last one's unsubscribe stops polling it. */
  subscribe(key: string, listener: Listener, opts: SubscribeOpts = {}): () => void {
    let slot = this.slots.get(key);
    if (!slot) {
      slot = {
        entry: { key, data: undefined, etag: null, fetchedAt: null, error: null, loading: false, failures: 0, nextAt: 0, paged: !!opts.paged },
        subs: 0, listeners: new Set(), inflight: null,
      };
      this.slots.set(key, slot);
    }
    slot.subs += 1;
    slot.listeners.add(listener);
    this.ensureTimer();
    const e = slot.entry;
    if (e.fetchedAt === null || this.d.now() >= e.nextAt) void this.refresh(key);
    let done = false;
    return () => {
      if (done) return;
      done = true;
      const s = this.slots.get(key);
      if (!s) return;
      s.listeners.delete(listener);
      s.subs -= 1;
      if (s.subs <= 0) this.maybeStopTimer();
    };
  }

  private active(): Slot[] {
    return [...this.slots.values()].filter((s) => s.subs > 0);
  }

  private ensureTimer(): void {
    if (this.timer !== null) return;
    this.timer = setInterval(() => this.tick(), 1000);
  }
  private maybeStopTimer(): void {
    if (this.timer !== null && this.active().length === 0) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
  /** Stops all timers (tests). */
  dispose(): void {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
  }

  private tick(): void {
    if (!this.d.isVisible() || this.conn_.auth !== 'ok') return;
    const t = this.d.now();
    for (const s of this.active()) {
      if (!s.inflight && t >= s.entry.nextAt) void this.refresh(s.entry.key);
    }
  }

  /** Refetch every subscribed entry now (focus, after a mutation, manual retry). */
  refreshAll(): Promise<void> {
    return Promise.all(this.active().map((s) => this.refresh(s.entry.key))).then(() => undefined);
  }

  /** Visibility / focus hook: refetch when the page comes back. */
  onResume(): void {
    if (this.d.isVisible() && this.conn_.auth === 'ok') void this.refreshAll();
  }

  /** Clear a terminal auth state (after the user reloads the session) and retry. */
  retry(): void {
    this.setConn({ auth: 'ok', authMessage: '' });
    void this.refreshAll();
  }

  refresh(key: string): Promise<void> {
    const slot = this.slots.get(key);
    if (!slot) return Promise.resolve();
    if (slot.inflight) return slot.inflight;
    slot.entry.loading = slot.entry.fetchedAt === null;
    slot.inflight = this.doFetch(slot).finally(() => {
      slot.inflight = null;
    });
    this.notify(slot);
    return slot.inflight;
  }

  private notify(slot: Slot): void {
    slot.entry = { ...slot.entry };
    for (const l of [...slot.listeners]) l();
  }

  private async request(path: string, etag: string | null): Promise<{ status: number; body: unknown; etag: string | null; date: number | null }> {
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), this.d.timeoutMs);
    try {
      const headers: Record<string, string> = { Accept: 'application/json' };
      if (etag) headers['If-None-Match'] = etag;
      const res = await this.d.fetch(path, { headers, signal: ctl.signal, credentials: 'same-origin', cache: 'no-store' });
      const date = res.headers.get('date');
      const dateMs = date ? Date.parse(date) : NaN;
      if (res.status === 304) return { status: 304, body: undefined, etag, date: Number.isNaN(dateMs) ? null : dateMs };
      let body: unknown;
      const text = await res.text();
      if (text) {
        try {
          body = JSON.parse(text);
        } catch {
          body = undefined;
        }
      }
      if (!res.ok) throw failureFrom(res.status, body, text);
      return { status: res.status, body, etag: res.headers.get('etag'), date: Number.isNaN(dateMs) ? null : dateMs };
    } catch (err) {
      if (err instanceof ApiFailure) throw err;
      const aborted = err instanceof DOMException && err.name === 'AbortError';
      throw new ApiFailure(0, aborted ? 'timeout' : 'network', aborted ? 'The request timed out' : 'Network error');
    } finally {
      clearTimeout(to);
    }
  }

  private async doFetch(slot: Slot): Promise<void> {
    const e = slot.entry;
    try {
      const r = await this.request(e.key, e.etag);
      let data: unknown = e.data;
      let etag = e.etag;
      if (r.status !== 304) {
        data = r.body;
        etag = r.etag;
        if (e.paged && isPage(data)) data = await this.followPages(e.key, data);
      }
      const now = this.d.now();
      if (r.date !== null) {
        // The Date header has 1 s resolution; ignore sub-2 s differences so the clock does not jitter.
        const skew = r.date - now;
        if (Math.abs(skew - this.conn_.skewMs) > 2000) this.setConn({ skewMs: Math.abs(skew) < 2000 ? 0 : skew });
      }
      slot.entry = { ...e, data, etag, fetchedAt: now, error: null, loading: false, failures: 0, nextAt: now + this.d.pollMs };
      if (this.conn_.failures > 0 || this.conn_.lastOk === null || this.conn_.nextRetryAt !== null) this.setConn({ failures: 0, lastOk: now, nextRetryAt: null });
      else this.conn_ = { ...this.conn_, lastOk: now };
      if (this.conn_.auth === 'ok') this.notifyConnTick();
    } catch (err) {
      const f = err instanceof ApiFailure ? err : new ApiFailure(0, 'network', 'Network error');
      const now = this.d.now();
      const failures = e.failures + 1;
      let delay = backoffMs(failures, this.d.pollMs);
      if (f.status === 401) {
        this.setConn({ auth: 'unauthorized', authMessage: f.message });
      } else if (isNotAdmin(f)) {
        this.setConn({ auth: 'forbidden', authMessage: f.message });
      } else if (f.transient) {
        this.setConn({ failures: this.conn_.failures + 1, nextRetryAt: now + delay });
      } else {
        delay = this.d.pollMs * 2;
      }
      slot.entry = { ...e, error: f, loading: false, failures, nextAt: now + delay, fetchedAt: e.fetchedAt };
    }
    this.notify(slot);
  }

  private notifyConnTick(): void {
    for (const l of [...this.connListeners]) l();
  }

  private async followPages(path: string, first: Page): Promise<Page> {
    const items = [...first.items];
    let cursor = first.next_cursor;
    let n = 0;
    while (cursor && n < MAX_PAGES) {
      const sep = path.includes('?') ? '&' : '?';
      const r = await this.request(`${path}${sep}cursor=${encodeURIComponent(cursor)}`, null);
      if (!isPage(r.body)) break;
      items.push(...r.body.items);
      cursor = r.body.next_cursor;
      n += 1;
    }
    return { items, next_cursor: cursor ?? null };
  }

  /** JSON mutation. Success triggers an immediate refetch of everything on screen. */
  async mutate<T = unknown>(method: 'POST' | 'PUT' | 'PATCH' | 'DELETE', path: string, body?: unknown): Promise<T> {
    const init: MutationInit = body !== undefined ? { body: JSON.stringify(body), contentType: 'application/json' } : {};
    const r = await this.send(method, path, init, 'application/json');
    const parsed = parseJson(r.text);
    if (!r.ok) throw this.fail(r.status, parsed, r.text);
    void this.refreshAll();
    return parsed as T;
  }

  /** Mutation whose success answer is not JSON (the SSO handoff form). Returns the raw text. */
  async mutateText(method: 'POST', path: string): Promise<string> {
    const r = await this.send(method, path, {}, 'text/html, application/json');
    if (!r.ok) throw this.fail(r.status, parseJson(r.text), r.text);
    return r.text;
  }

  /** Multipart upload (release upload). The browser sets the boundary; no content type is forced. */
  async mutateForm<T = unknown>(path: string, form: FormData): Promise<T> {
    const r = await this.send('POST', path, { form }, 'application/json');
    const parsed = parseJson(r.text);
    if (!r.ok) throw this.fail(r.status, parsed, r.text);
    void this.refreshAll();
    return parsed as T;
  }

  /** Raw-bytes upload with its own content type (the speedtest logo: image/png, image/svg+xml or image/jpeg). */
  async mutateBytes<T = unknown>(path: string, bytes: Blob | ArrayBuffer, contentType: string): Promise<T> {
    const r = await this.send('POST', path, { body: bytes, contentType }, 'application/json');
    const parsed = parseJson(r.text);
    if (!r.ok) throw this.fail(r.status, parsed, r.text);
    void this.refreshAll();
    return parsed as T;
  }

  private fail(status: number, parsed: unknown, text: string): ApiFailure {
    const f = failureFrom(status, parsed, text);
    if (f.status === 401) this.setConn({ auth: 'unauthorized', authMessage: f.message });
    return f;
  }

  /**
   * One state-changing request. Every mutation carries X-Exp-Request, a custom header that a cross-site form or
   * simple request cannot set, so a forged request never reaches the manager (on top of the Access cookie, the
   * Worker's JWT check and its Origin check, SR-13).
   */
  private async send(method: string, path: string, init: MutationInit, accept: string): Promise<{ ok: boolean; status: number; text: string }> {
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), this.d.timeoutMs);
    try {
      const headers: Record<string, string> = { Accept: accept, 'X-Exp-Request': '1' };
      if (init.contentType) headers['Content-Type'] = init.contentType;
      const res = await this.d.fetch(path, {
        method, headers, signal: ctl.signal, credentials: 'same-origin',
        ...(init.body !== undefined ? { body: init.body } : {}),
        ...(init.form !== undefined ? { body: init.form } : {}),
      });
      const text = await res.text();
      return { ok: res.ok, status: res.status, text };
    } catch (err) {
      const aborted = err instanceof DOMException && err.name === 'AbortError';
      throw new ApiFailure(0, aborted ? 'timeout' : 'network', aborted ? 'The request timed out' : 'Network error');
    } finally {
      clearTimeout(to);
    }
  }
}

interface MutationInit { body?: BodyInit; contentType?: string; form?: FormData }

function parseJson(text: string): unknown {
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

interface Page { items: unknown[]; next_cursor: string | null }
function isPage(v: unknown): v is Page {
  return typeof v === 'object' && v !== null && Array.isArray((v as Page).items);
}

/** 403 because the account is not an admin at all (as opposed to a role that is too low for one endpoint). */
export function isNotAdmin(f: ApiFailure): boolean {
  return f.status === 403 && (f.code === 'unknown_admin' || f.code === 'http_error');
}

/** Build an ApiFailure from an error envelope; message text is untrusted but only ever rendered as text. */
export function failureFrom(status: number, body: unknown, text: string): ApiFailure {
  let code = 'http_error';
  let message = `HTTP ${status}`;
  if (typeof body === 'object' && body !== null && 'error' in body) {
    const er = (body as { error?: { code?: unknown; message?: unknown } }).error;
    if (er && typeof er.code === 'string') code = er.code.slice(0, 64);
    if (er && typeof er.message === 'string') message = er.message.slice(0, 300);
  } else if (text && text.length < 200 && !text.trimStart().startsWith('<')) {
    message = text;
  }
  return new ApiFailure(status, code, message);
}

export const store = new DataStore();
