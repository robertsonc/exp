import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { AuditEvent, Me, Page } from '../api/types';
import { useResource } from '../data/hooks';
import { Button, EmptyState } from '../components/atoms';
import { TextField } from '../components/forms';
import { canAdmin } from '../components/Issues';
import { Loadable, PageHeader } from './common';
import { formatAbsolute } from '../lib/format';
import { redact } from '../lib/redact';
import { setQuery, useLocation } from '../router';

/** `datetime-local` value (local wall time) to the API's UTC timestamp, or undefined when empty or invalid. */
export function toApiTs(local: string): string | undefined {
  if (!local) return undefined;
  const ms = Date.parse(local);
  return Number.isFinite(ms) ? new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z') : undefined;
}

function toLocalInput(ts: string | null): string {
  if (!ts) return '';
  const ms = Date.parse(ts);
  if (!Number.isFinite(ms)) return '';
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function Details({ e }: { e: AuditEvent }): JSX.Element {
  const keys = Object.keys(e.details ?? {});
  if (keys.length === 0) return <span class="dim">none</span>;
  return (
    <details class="audit-details">
      <summary>{keys.length} field{keys.length === 1 ? '' : 's'}</summary>
      <pre class="code" tabIndex={0} aria-label={`Details of ${e.action}`}>{JSON.stringify(redact(e.details), null, 2)}</pre>
    </details>
  );
}

export function AuditPage({ me }: { me: Me | undefined }): JSX.Element {
  const { query } = useLocation();
  const actor = query.get('actor') ?? '';
  const resource = query.get('resource') ?? '';
  const from = query.get('from');
  const to = query.get('to');
  const [fActor, setFActor] = useState(actor);
  const [fRes, setFRes] = useState(resource);
  const [fFrom, setFFrom] = useState(toLocalInput(from));
  const [fTo, setFTo] = useState(toLocalInput(to));
  const allowed = canAdmin(me) || me === undefined;
  const path = ep.auditQuery({ actor: actor || undefined, resource: resource || undefined, from: from ?? undefined, to: to ?? undefined });
  const res = useResource<Page<AuditEvent>>(allowed ? path : null, { paged: true });
  const items = res.data?.items ?? [];
  const apply = (e: Event) => {
    e.preventDefault();
    setQuery({ actor: fActor.trim() || null, resource: fRes.trim() || null, from: toApiTs(fFrom) ?? null, to: toApiTs(fTo) ?? null });
  };
  const clear = () => {
    setFActor('');
    setFRes('');
    setFFrom('');
    setFTo('');
    setQuery({ actor: null, resource: null, from: null, to: null });
  };
  return (
    <>
      <PageHeader title="Audit" sub="Every change made through the manager: who did what, to which resource, and when. Secret values are never recorded." />
      {!allowed ? <p class="banner banner-warn" role="status">The audit log is visible to admins and owners.</p> : (
        <>
          <form class="filterform" onSubmit={apply} aria-label="Audit filters" noValidate>
            <TextField label="Actor" value={fActor} onInput={setFActor} placeholder="owner@example.com" hint="Exact email, agent:h_… or system." />
            <TextField label="Resource starts with" value={fRes} onInput={setFRes} placeholder="host:" />
            <TextField label="From" value={fFrom} onInput={setFFrom} type="datetime-local" />
            <TextField label="To" value={fTo} onInput={setFTo} type="datetime-local" />
            <div class="filter-actions"><Button type="submit" variant="primary">Apply filters</Button><Button onClick={clear}>Clear</Button></div>
          </form>
          <Loadable loading={res.loading} error={res.data ? null : res.error} onRetry={res.refresh} what="audit events" rows={8}>
            <p class="result-count" data-testid="audit-count" role="status">{items.length} event{items.length === 1 ? '' : 's'}</p>
            {items.length === 0 ? <EmptyState title="No audit events match">Widen the time range or clear a filter.</EmptyState> : (
              <div class="table-scroll">
                <table class="plain" data-testid="audit-table">
                  <caption class="sr-only">Audit events, newest first</caption>
                  <thead><tr><th scope="col">Time (UTC)</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Resource</th><th scope="col">Details</th></tr></thead>
                  <tbody>
                    {items.map((e) => (
                      <tr key={e.evt_id}>
                        <td><time dateTime={e.ts}>{formatAbsolute(e.ts)}</time></td>
                        <td>{e.actor}</td>
                        <th scope="row"><code>{e.action}</code></th>
                        <td>{e.resource}</td>
                        <td><Details e={e} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Loadable>
        </>
      )}
    </>
  );
}
