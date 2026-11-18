import type { JSX } from 'preact';
import { useEffect, useState } from 'preact/hooks';

export interface Toast { id: number; kind: 'ok' | 'error'; text: string }
let seq = 0;
let items: Toast[] = [];
const subs = new Set<() => void>();

/** Mutation results; rendered in an ARIA live region. */
export function notify(kind: Toast['kind'], text: string): void {
  const t = { id: ++seq, kind, text };
  items = [...items, t].slice(-4);
  subs.forEach((s) => s());
  setTimeout(() => {
    items = items.filter((x) => x.id !== t.id);
    subs.forEach((s) => s());
  }, kind === 'error' ? 9000 : 5000);
}

export function ToastHost(): JSX.Element {
  const [, bump] = useState(0);
  useEffect(() => {
    const s = () => bump((n) => n + 1);
    subs.add(s);
    return () => {
      subs.delete(s);
    };
  }, []);
  return (
    <div class="toasts" role="status" aria-live="polite">
      {items.map((t) => <div key={t.id} class={`toast toast-${t.kind}`}>{t.text}</div>)}
    </div>
  );
}
