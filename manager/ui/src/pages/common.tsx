import type { ComponentChildren, JSX } from 'preact';
import { Link } from '../components/viz';
import { ErrorBanner, SkeletonBlock } from '../components/atoms';
import type { ApiFailure } from '../data/store';
import { formatAgo } from '../lib/format';

export function PageHeader({ title, sub, actions, crumbs }: { title: string; sub?: ComponentChildren; actions?: ComponentChildren; crumbs?: { to: string; label: string }[] }): JSX.Element {
  return (
    <header class="page-head">
      {crumbs?.length ? (
        <nav aria-label="Breadcrumb" class="crumbs">
          {crumbs.map((c) => <span key={c.to}><Link to={c.to}>{c.label}</Link> <span aria-hidden="true">/</span> </span>)}
        </nav>
      ) : null}
      <div class="page-title">
        <h1>{title}</h1>
        {actions ? <div class="page-actions">{actions}</div> : null}
      </div>
      {sub ? <p class="page-sub">{sub}</p> : null}
    </header>
  );
}

/** "as of 45 s ago" caption for a data set. */
export function AsOf({ ts, now, label = 'as of' }: { ts: string | null | undefined; now: number; label?: string }): JSX.Element {
  return <span class="asof" title={ts ?? ''}>{ts ? `${label} ${formatAgo(ts, now)}` : ''}</span>;
}

/** Standard loading / error / content switch for a resource. */
export function Loadable({ loading, error, onRetry, what, children, rows = 5 }: {
  loading: boolean; error: ApiFailure | null; onRetry: () => void; what: string; children: ComponentChildren; rows?: number;
}): JSX.Element {
  if (loading) return <SkeletonBlock rows={rows} label={`Loading ${what}`} />;
  if (error) return <ErrorBanner what={`Could not load ${what}.`} message={error.message} onRetry={onRetry} />;
  return <>{children}</>;
}
