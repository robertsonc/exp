import { useCallback, useEffect, useReducer, useRef, useState } from 'preact/hooks';
import { store as defaultStore, type ConnState, type DataStore, type Entry } from './store';

let current: DataStore = defaultStore;
/** Tests can swap the store. */
export function setStore(s: DataStore): void {
  current = s;
}
export function getStore(): DataStore {
  return current;
}

export interface Resource<T> {
  data: T | undefined;
  error: Entry['error'];
  loading: boolean;
  fetchedAt: number | null;
  refresh: () => void;
}

/** Subscribe to an endpoint. `null` disables the subscription (conditional fetch). */
export function useResource<T>(path: string | null, opts: { paged?: boolean } = {}): Resource<T> {
  const [, bump] = useReducer((n: number) => n + 1, 0);
  const paged = !!opts.paged;
  useEffect(() => {
    if (path === null) return undefined;
    return current.subscribe(path, () => bump(0), { paged });
  }, [path, paged]);
  const e = path === null ? undefined : current.entry<T>(path);
  const refresh = useCallback(() => {
    if (path !== null) void current.refresh(path);
  }, [path]);
  return {
    data: e?.data,
    error: e?.error ?? null,
    loading: path !== null && (e === undefined || (e.fetchedAt === null && e.error === null)),
    fetchedAt: e?.fetchedAt ?? null,
    refresh,
  };
}

export function useConn(): ConnState {
  const [, bump] = useReducer((n: number) => n + 1, 0);
  useEffect(() => current.subscribeConn(() => bump(0)), []);
  return current.conn();
}

/** Re-render every second (relative times, freshness). */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => current.now());
  const ref = useRef(setNow);
  ref.current = setNow;
  useEffect(() => {
    const t = setInterval(() => ref.current(current.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function mutate<T = unknown>(method: 'POST' | 'PUT' | 'PATCH' | 'DELETE', path: string, body?: unknown): Promise<T> {
  return current.mutate<T>(method, path, body);
}

export function mutateText(method: 'POST', path: string): Promise<string> {
  return current.mutateText(method, path);
}

export function mutateForm<T = unknown>(path: string, form: FormData): Promise<T> {
  return current.mutateForm<T>(path, form);
}

export function mutateBytes<T = unknown>(path: string, bytes: Blob | ArrayBuffer, contentType: string): Promise<T> {
  return current.mutateBytes<T>(path, bytes, contentType);
}
