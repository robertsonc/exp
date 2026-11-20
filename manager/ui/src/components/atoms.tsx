import type { ComponentChildren, JSX } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { Icon, Glyph, type IconName } from './Icon';
import { DASH } from '../lib/format';
import type { Sev } from '../lib/state';
import { own } from '../lib/own';

export type PillState = 'ok' | 'warn' | 'fail' | 'unknown' | 'stale' | 'offline';
const PILL: Record<PillState, { icon: IconName; text: string }> = {
  ok: { icon: 'check', text: 'ok' },
  warn: { icon: 'alert', text: 'warn' },
  fail: { icon: 'x', text: 'fail' },
  unknown: { icon: 'clock', text: 'unknown' },
  stale: { icon: 'clock', text: 'stale' },
  offline: { icon: 'x', text: 'offline' },
};

/** Status pill: always an icon plus text, never colour alone. */
export function StatusPill({ state, label, title }: { state: PillState; label?: string; title?: string }): JSX.Element {
  const p = own(PILL, state) ?? PILL.unknown;
  return (
    <span class={`pill pill-${state}`} title={title}>
      <Icon name={p.icon} size={12} />
      <span>{label ?? p.text}</span>
    </span>
  );
}

export function healthPill(h: string): PillState {
  return h === 'ok' ? 'ok' : h === 'degraded' ? 'warn' : h === 'fail' ? 'fail' : 'unknown';
}

export function sevClass(s: Sev): string {
  return `sev-${s}`;
}

/** Missing value with a reason in the tooltip. */
export function Missing({ why }: { why: string }): JSX.Element {
  return <span class="missing" title={why} aria-label={why}>{DASH}</span>;
}

export function Skeleton({ h = 16, w = '100%' }: { h?: number; w?: string }): JSX.Element {
  return <span class="skeleton" style={{ height: `${h}px`, width: w }} aria-hidden="true" />;
}

export function SkeletonBlock({ rows = 4, label = 'Loading' }: { rows?: number; label?: string }): JSX.Element {
  return (
    <div class="skel-block" role="status" aria-label={label} aria-busy="true">
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} h={18} w={`${70 + ((i * 13) % 30)}%`} />)}
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ComponentChildren; action?: ComponentChildren }): JSX.Element {
  return (
    <div class="empty">
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  );
}

/** Partial or failed data: what failed plus a retry. */
export function ErrorBanner({ what, message, onRetry }: { what: string; message?: string; onRetry?: () => void }): JSX.Element {
  return (
    <div class="banner banner-warn" role="alert">
      <Icon name="alert" />
      <span><strong>{what}</strong>{message ? ` ${message}` : ''}</span>
      {onRetry ? <button type="button" class="btn btn-sm" onClick={onRetry}>Retry</button> : null}
    </div>
  );
}

export function Badge({ children, title, tone }: { children: ComponentChildren; title?: string; tone?: 'warn' | 'fail' | 'ok' | 'neutral' }): JSX.Element {
  return <span class={`badge badge-${tone ?? 'neutral'}`} title={title}>{children}</span>;
}

const SHAPE_ICON: Record<string, { letter: string; icon: IconName }> = {
  probe: { letter: 'P', icon: 'probe' },
  collector: { letter: 'C', icon: 'collector' },
  dashboard: { letter: 'D', icon: 'dashboard' },
  runner: { letter: 'R', icon: 'runner' },
  speedtest: { letter: 'S', icon: 'internet' },
};
export function ShapeBadges({ shapes }: { shapes: readonly string[] }): JSX.Element {
  return (
    <span class="shapes">
      {shapes.map((s) => (
        <span key={s} class="shape" title={s} aria-label={s}>{own(SHAPE_ICON, s)?.letter ?? '?'}</span>
      ))}
    </span>
  );
}

export function Button({ children, variant = 'secondary', small, ...rest }: JSX.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger'; small?: boolean }): JSX.Element {
  const cls = `btn btn-${variant}${small ? ' btn-sm' : ''}`;
  return <button type="button" {...rest} class={cls}>{children}</button>;
}

export function Tabs({ tabs, active, onChange, label }: { tabs: { id: string; label: string }[]; active: string; onChange: (id: string) => void; label: string }): JSX.Element {
  const onKey = (e: KeyboardEvent) => {
    const i = tabs.findIndex((t) => t.id === active);
    let n = i;
    if (e.key === 'ArrowRight') n = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') n = 0;
    else if (e.key === 'End') n = tabs.length - 1;
    else return;
    e.preventDefault();
    const t = tabs[n];
    if (t) {
      onChange(t.id);
      requestAnimationFrame(() => document.getElementById(`tab-${t.id}`)?.focus());
    }
  };
  return (
    <div class="tabs" role="tablist" aria-label={label} onKeyDown={onKey}>
      {tabs.map((t) => (
        <button key={t.id} id={`tab-${t.id}`} type="button" role="tab" aria-selected={t.id === active} aria-controls={t.id === active ? `panel-${t.id}` : undefined}
          tabIndex={t.id === active ? 0 : -1} class={`tab${t.id === active ? ' tab-active' : ''}`} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

/** Copy a value to the clipboard; the value is shown as text only. */
export function CopyField({ value, label }: { value: string; label: string }): JSX.Element {
  const [done, setDone] = useState(false);
  const copy = () => {
    const finish = () => {
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    };
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(value).then(finish, () => undefined);
  };
  return (
    <div class="copyfield">
      <code aria-label={label}>{value}</code>
      <button type="button" class="btn btn-sm" onClick={copy} aria-label={`Copy ${label}`}><Glyph name="copy" size={14} /> {done ? 'Copied' : 'Copy'}</button>
    </div>
  );
}

/** Countdown to an absolute time. */
export function Countdown({ until, now }: { until: string; now: number }): JSX.Element {
  const left = Math.max(0, Math.round((Date.parse(until) - now) / 1000));
  const m = Math.floor(left / 60);
  const s = String(left % 60).padStart(2, '0');
  return <span class="countdown" role="timer">{left === 0 ? 'expired' : `${m}:${s}`}</span>;
}

/** Modal dialog on <dialog>; Escape closes; focus returns to the opener. */
export function Dialog({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ComponentChildren; wide?: boolean }): JSX.Element {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return undefined;
    const opener = document.activeElement as HTMLElement | null;
    if (typeof d.showModal === 'function' && !d.open) d.showModal();
    else d.setAttribute('open', '');
    return () => {
      if (d.open && typeof d.close === 'function') d.close();
      opener?.focus?.();
    };
  }, []);
  return (
    <dialog ref={ref} class={`dialog${wide ? ' dialog-wide' : ''}`} aria-labelledby="dlg-title" onCancel={(e) => { e.preventDefault(); onClose(); }}>
      <h2 id="dlg-title">{title}</h2>
      {children}
    </dialog>
  );
}

/** Destructive actions type the host name to confirm. */
export function ConfirmDialog({ title, body, confirmText, typeName, busy, error, onConfirm, onCancel }: {
  title: string; body: ComponentChildren; confirmText: string; typeName?: string; busy?: boolean; error?: string | null;
  onConfirm: () => void; onCancel: () => void;
}): JSX.Element {
  const [typed, setTyped] = useState('');
  const ok = !typeName || typed === typeName;
  return (
    <Dialog title={title} onClose={onCancel}>
      <div class="dialog-body">{body}</div>
      {typeName ? (
        <label class="field">
          <span>Type <code>{typeName}</code> to confirm</span>
          <input type="text" value={typed} autocomplete="off" spellcheck={false} onInput={(e) => setTyped((e.currentTarget as HTMLInputElement).value)} />
        </label>
      ) : null}
      {error ? <p class="form-error" role="alert">{error}</p> : null}
      <div class="dialog-actions">
        <Button onClick={onCancel}>Cancel</Button>
        <Button variant="danger" disabled={!ok || busy} onClick={onConfirm}>{busy ? 'Working…' : confirmText}</Button>
      </div>
    </Dialog>
  );
}

/** Slide-in drawer (mobile navigation). */
export function Drawer({ open, onClose, label, children }: { open: boolean; onClose: () => void; label: string; children: ComponentChildren }): JSX.Element | null {
  useEffect(() => {
    if (!open) return undefined;
    const k = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div class="drawer-wrap">
      <div class="drawer-scrim" onClick={onClose} aria-hidden="true" />
      <aside class="drawer" role="dialog" aria-modal="true" aria-label={label}>{children}</aside>
    </div>
  );
}

export function Panel({ title, actions, children, class: cls, id }: { title?: string; actions?: ComponentChildren; children: ComponentChildren; class?: string; id?: string }): JSX.Element {
  return (
    <section class={`panel${cls ? ` ${cls}` : ''}`} aria-labelledby={id ? `${id}-h` : undefined}>
      {title ? (
        <header class="panel-head">
          <h2 id={id ? `${id}-h` : undefined}>{title}</h2>
          {actions}
        </header>
      ) : null}
      {children}
    </section>
  );
}
