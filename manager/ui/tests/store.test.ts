import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiFailure, DataStore } from '../src/data/store';

type Handler = (url: string, init: RequestInit) => Response | Promise<Response>;

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

let visible = true;
let calls: { url: string; init: RequestInit }[] = [];
let handler: Handler;
let store: DataStore;

function make(): DataStore {
  return new DataStore({
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      return handler(String(input), init ?? {});
    }) as typeof fetch,
    now: () => Date.now(),
    isVisible: () => visible,
  });
}

const flush = async () => {
  await vi.advanceTimersByTimeAsync(0);
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-11-18T12:00:00Z'));
  visible = true;
  calls = [];
  handler = () => json({ n: calls.length }, 200, { etag: '"v1"' });
  store = make();
});
afterEach(() => {
  store.dispose();
  vi.useRealTimers();
});

describe('data layer', () => {
  it('fetches on first subscribe, shares one request per endpoint, caches the ETag', async () => {
    const a = vi.fn();
    const b = vi.fn();
    store.subscribe('/api/x', a);
    store.subscribe('/api/x', b);
    await flush();
    expect(calls).toHaveLength(1);
    expect(store.entry<{ n: number }>('/api/x')?.data).toEqual({ n: 1 });
    expect(store.entry('/api/x')?.etag).toBe('"v1"');
    expect(a).toHaveBeenCalled();
    expect(b).toHaveBeenCalled();
  });

  it('polls every 30 s with If-None-Match and keeps the data on 304', async () => {
    handler = (_u, init) => {
      const inm = (init.headers as Record<string, string>)['If-None-Match'];
      return inm === '"v1"' ? new Response(null, { status: 304 }) : json({ hello: 'world' }, 200, { etag: '"v1"' });
    };
    store.subscribe('/api/x', () => undefined);
    await flush();
    expect(calls).toHaveLength(1);
    expect((calls[0]?.init.headers as Record<string, string>)['If-None-Match']).toBeUndefined();
    await vi.advanceTimersByTimeAsync(29_000);
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(calls).toHaveLength(2);
    expect((calls[1]?.init.headers as Record<string, string>)['If-None-Match']).toBe('"v1"');
    expect(store.entry('/api/x')?.data).toEqual({ hello: 'world' });
    expect(store.entry('/api/x')?.fetchedAt).toBeGreaterThan(Date.parse('2026-11-18T12:00:29Z'));
    expect(store.conn().lastOk).not.toBeNull();
  });

  it('pauses polling while the tab is hidden and refetches immediately on resume', async () => {
    store.subscribe('/api/x', () => undefined);
    await flush();
    visible = false;
    await vi.advanceTimersByTimeAsync(120_000);
    expect(calls).toHaveLength(1);
    visible = true;
    store.onResume();
    await flush();
    expect(calls).toHaveLength(2);
  });

  it('stops polling an endpoint when its last subscriber leaves', async () => {
    const un = store.subscribe('/api/x', () => undefined);
    await flush();
    un();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(calls).toHaveLength(1);
  });

  it('backs off exponentially on failures and flags the connection', async () => {
    handler = () => {
      throw new TypeError('network down');
    };
    store.subscribe('/api/x', () => undefined);
    await flush();
    expect(calls).toHaveLength(1);
    expect(store.conn().failures).toBe(1);
    expect(store.entry('/api/x')?.error?.transient).toBe(true);
    await vi.advanceTimersByTimeAsync(59_000);
    expect(calls).toHaveLength(1); // first retry after 60 s, not 30 s
    await vi.advanceTimersByTimeAsync(2_000);
    expect(calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(100_000);
    expect(calls).toHaveLength(2); // second retry after 120 s
    await vi.advanceTimersByTimeAsync(30_000);
    expect(calls).toHaveLength(3);
    expect(store.conn().failures).toBe(3);
  });

  it('recovers automatically and clears the failure state', async () => {
    let down = true;
    handler = () => (down ? json({ error: { code: 'bad_gateway', message: 'x' } }, 502) : json({ ok: true }));
    store.subscribe('/api/x', () => undefined);
    await flush();
    expect(store.conn().failures).toBe(1);
    down = false;
    await vi.advanceTimersByTimeAsync(61_000);
    expect(store.conn().failures).toBe(0);
    expect(store.conn().nextRetryAt).toBeNull();
    expect(store.entry('/api/x')?.data).toEqual({ ok: true });
  });

  it('401 means the Access session expired and stops polling', async () => {
    handler = () => json({ error: { code: 'unauthenticated', message: 'no jwt' } }, 401);
    store.subscribe('/api/x', () => undefined);
    await flush();
    expect(store.conn().auth).toBe('unauthorized');
    await vi.advanceTimersByTimeAsync(300_000);
    expect(calls).toHaveLength(1);
  });

  it('403 unknown_admin means the account is not an admin; insufficient_role is only local', async () => {
    handler = (u) => (u === '/api/a'
      ? json({ error: { code: 'unknown_admin', message: 'not an admin' } }, 403)
      : json({ error: { code: 'insufficient_role', message: 'viewer' } }, 403));
    store.subscribe('/api/b', () => undefined);
    await flush();
    expect(store.conn().auth).toBe('ok');
    expect(store.entry('/api/b')?.error?.code).toBe('insufficient_role');
    store.subscribe('/api/a', () => undefined);
    await flush();
    expect(store.conn().auth).toBe('forbidden');
  });

  it('refetches everything on screen after a mutation and surfaces the error envelope', async () => {
    store.subscribe('/api/x', () => undefined);
    await flush();
    handler = (u, init) => (init.method === 'POST' ? json({ ok: 1 }, 202) : json({ n: 2 }, 200, { etag: '"v2"' }));
    const r = await store.mutate<{ ok: number }>('POST', '/api/act', { for: '1h' });
    expect(r).toEqual({ ok: 1 });
    await flush();
    const post = calls.find((c) => c.init.method === 'POST');
    expect(post?.init.body).toBe('{"for":"1h"}');
    expect(calls.filter((c) => c.url === '/api/x')).toHaveLength(2);
    handler = () => json({ error: { code: 'insufficient_role', message: 'requires admin' } }, 403);
    await expect(store.mutate('POST', '/api/act')).rejects.toMatchObject({ status: 403, code: 'insufficient_role', message: 'requires admin' });
    handler = () => json({ error: { code: 'unauthenticated', message: 'expired' } }, 401);
    await expect(store.mutate('DELETE', '/api/act')).rejects.toBeInstanceOf(ApiFailure);
    expect(store.conn().auth).toBe('unauthorized');
  });

  it('follows cursors for paged lists', async () => {
    handler = (u) => (u.includes('cursor=c2') ? json({ items: [3], next_cursor: null }) : u.includes('cursor=c1') ? json({ items: [2], next_cursor: 'c2' }) : json({ items: [1], next_cursor: 'c1' }, 200, { etag: '"p"' }));
    store.subscribe('/api/list?limit=1', () => undefined, { paged: true });
    await flush();
    expect(store.entry<{ items: number[] }>('/api/list?limit=1')?.data?.items).toEqual([1, 2, 3]);
  });

  it('a 404 is a per-endpoint error, not a connectivity problem', async () => {
    handler = () => json({ error: { code: 'not_found', message: 'no such host' } }, 404);
    store.subscribe('/api/h', () => undefined);
    await flush();
    expect(store.conn().failures).toBe(0);
    expect(store.entry('/api/h')?.error?.status).toBe(404);
  });

  it('times out a hung request', async () => {
    handler = (_u, init) => new Promise<Response>((_res, rej) => {
      init.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')));
    });
    store.subscribe('/api/x', () => undefined);
    await vi.advanceTimersByTimeAsync(16_000);
    expect(store.entry('/api/x')?.error?.code).toBe('timeout');
    expect(store.conn().failures).toBe(1);
  });

  it('corrects for clock skew using the Date header', async () => {
    handler = () => json({}, 200, { date: new Date(Date.now() + 600_000).toUTCString() });
    store.subscribe('/api/x', () => undefined);
    await flush();
    expect(Math.abs(store.now() - Date.now() - 600_000)).toBeLessThan(2000);
  });

  it('every mutation carries the CSRF header; JSON bodies set a JSON content type, multipart sets none', async () => {
    handler = () => json({ ok: 1 }, 201);
    await store.mutate('POST', '/api/a', { x: 1 });
    await store.mutate('DELETE', '/api/b');
    const fd = new FormData();
    fd.append('manifest', new Blob(['{}']), 'm.json');
    await store.mutateForm('/api/up', fd);
    const posts = calls.filter((c) => c.init.method !== undefined && c.init.method !== 'GET');
    expect(posts).toHaveLength(3);
    for (const c of posts) {
      const h = c.init.headers as Record<string, string>;
      expect(h['X-Exp-Request']).toBe('1');
      expect(c.init.credentials).toBe('same-origin');
    }
    expect((posts[0]?.init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
    expect((posts[2]?.init.headers as Record<string, string>)['Content-Type']).toBeUndefined();
    expect(posts[2]?.init.body).toBeInstanceOf(FormData);
  });

  it('mutateText returns a non-JSON answer and still reports failures as ApiFailure', async () => {
    handler = () => new Response('<form></form>', { status: 200, headers: { 'content-type': 'text/html' } });
    expect(await store.mutateText('POST', '/api/sso')).toBe('<form></form>');
    handler = () => json({ error: { code: 'dashboard_not_ready', message: 'dashboard not ready' } }, 409);
    await expect(store.mutateText('POST', '/api/sso')).rejects.toMatchObject({ status: 409, code: 'dashboard_not_ready' });
  });
});
