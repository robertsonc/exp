import type { JSX } from 'preact';
import { useMemo } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { Issue, Me, Page } from '../api/types';
import { useNow, useResource } from '../data/hooks';
import { useDirectory } from '../data/directory';
import { EmptyState, Tabs } from '../components/atoms';
import { FilterBar } from '../components/FilterBar';
import { SeverityMark, SnoozeActions } from '../components/Issues';
import { VirtualTable, type Column } from '../components/VirtualTable';
import { Link } from '../components/viz';
import { Loadable, PageHeader } from './common';
import { formatAbsolute, formatAgo } from '../lib/format';
import { isSnoozed, issueScope, issueValue, kindLabel, SCOPES, sortIssues } from '../lib/issues';
import { setQuery, useLocation } from '../router';

const WEEK_MS = 7 * 86_400_000;

export function IssuesPage({ me }: { me: Me | undefined }): JSX.Element {
  const { query } = useLocation();
  const tab = query.get('tab') === 'recent' ? 'recent' : 'open';
  const sev = query.get('severity') ?? '';
  const site = query.get('site') ?? '';
  const scope = query.get('type') ?? '';
  const kind = query.get('kind') ?? '';
  const showSnoozed = query.get('snoozed') === '1';
  const now = useNow();
  const res = useResource<Page<Issue>>(ep.issues(tab === 'recent' ? 'resolved' : 'open'), { paged: true });
  const dir = useDirectory(true);

  const all = res.data?.items ?? [];
  const filtered = useMemo(() => {
    const f = all.filter((i) => (!sev || i.severity === sev) && (!site || i.site === site) && (!kind || i.kind === kind) && (!scope || issueScope(i.kind) === scope)
      && (tab === 'open' || (i.resolved_at !== null && now - Date.parse(i.resolved_at) <= WEEK_MS)));
    return sortIssues(f);
    // `now` is intentionally coarse: recompute on data change only
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [all, sev, site, kind, scope, tab]);
  const snoozedCount = filtered.filter((i) => isSnoozed(i, now)).length;
  const rows = tab === 'open' && !showSnoozed ? filtered.filter((i) => !isSnoozed(i, now)) : filtered;

  const sites = [...new Set(all.map((i) => i.site))].sort();
  const kinds = [...new Set(all.map((i) => i.kind))].sort();
  const set = (k: string, v: string) => setQuery({ [k]: v });

  const hostName = (i: Issue) => dir.byId.get(i.host_id)?.name ?? i.host_id;
  const columns: Column<Issue>[] = [
    { id: 'sev', header: 'Severity', width: '6.5rem', cell: (i) => <SeverityMark sev={i.severity} /> },
    { id: 'issue', header: 'Issue', cell: (i) => <span><strong>{kindLabel(i.kind)}</strong><br /><span class="dim">{i.detail}</span></span> },
    { id: 'where', header: 'Host / component', cell: (i) => (
      <span>
        <Link to={`/hosts/${i.host_id}`}>{hostName(i)}</Link>
        {i.component_id ? <><br /><Link to={`/hosts/${i.host_id}/components/${i.component_id}`} class="dim">{dir.comps.get(i.component_id)?.id ?? i.component_id}</Link></> : null}
      </span>) },
    { id: 'site', header: 'Site', width: '7rem', cell: (i) => i.site },
    { id: 'since', header: tab === 'recent' ? 'Resolved' : 'Since', width: '8rem', cell: (i) => <span title={formatAbsolute(tab === 'recent' ? i.resolved_at : i.opened_at)}>{formatAgo(tab === 'recent' ? i.resolved_at : i.opened_at, now)}</span> },
    { id: 'value', header: 'Last value', width: '6rem', align: 'right', cell: (i) => issueValue(i) || '—' },
    ...(tab === 'open' ? [{ id: 'act', header: 'Actions', width: '11rem', cell: (i: Issue) => (
      <span class="row-actions">
        {isSnoozed(i, now) ? <span class="dim snooze-note">snoozed {i.snoozed_until && i.snoozed_until !== 'resolved' ? `until ${i.snoozed_until.slice(11, 16)} UTC` : 'until resolved'}</span> : null}
        <SnoozeActions issue={i} me={me} now={now} />
      </span>) } as Column<Issue>] : []),
  ];

  return (
    <>
      <PageHeader title="Issues" sub="Open fleet issues. Snoozing hides one issue kind for one host; it stays recorded and audited." />
      <Tabs label="Issue lists" active={tab} onChange={(t) => setQuery({ tab: t === 'recent' ? 'recent' : null })} tabs={[{ id: 'open', label: 'Open' }, { id: 'recent', label: 'Recently resolved (7 d)' }]} />
      <FilterBar
        filters={[
          { id: 'severity', label: 'Severity', value: sev, options: [{ value: 'crit', label: 'Critical' }, { value: 'warn', label: 'Warning' }] },
          { id: 'site', label: 'Site', value: site, options: sites.map((s) => ({ value: s, label: s })) },
          { id: 'type', label: 'Type', value: scope, options: SCOPES.map((s) => ({ value: s, label: s })) },
          { id: 'kind', label: 'Kind', value: kind, options: kinds.map((k) => ({ value: k, label: kindLabel(k) })) },
        ]}
        onChange={set} onClear={() => setQuery({ severity: null, site: null, type: null, kind: null })}
      >
        {tab === 'open' ? (
          <label class="chip">
            <input type="checkbox" checked={showSnoozed} onChange={(e) => set('snoozed', (e.currentTarget as HTMLInputElement).checked ? '1' : '')} />
            <span>Show snoozed ({snoozedCount})</span>
          </label>
        ) : null}
      </FilterBar>
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
      <Loadable loading={res.loading} error={res.data ? null : res.error} onRetry={res.refresh} what="issues">
        <p class="result-count" role="status">{rows.length} issue{rows.length === 1 ? '' : 's'}</p>
        <VirtualTable
          rows={rows} columns={columns} rowKey={(i) => i.issue_id} label="Issues" rowHeight={58} cardHeight={150} viewHeight={620}
          card={(i) => (
            <div class="issue-card">
              <span class="row-top"><SeverityMark sev={i.severity} /><span class="dim">{site ? '' : i.site}</span></span>
              <strong>{kindLabel(i.kind)}</strong>
              <span class="dim">{i.detail}</span>
              <Link to={`/hosts/${i.host_id}`}>{hostName(i)}</Link>
              {tab === 'open' ? <SnoozeActions issue={i} me={me} now={now} /> : null}
            </div>
          )}
          empty={<EmptyState title={tab === 'open' ? 'No open issues' : 'Nothing resolved in the last 7 days'}>{all.length ? 'No issue matches the current filters.' : 'The fleet is healthy.'}</EmptyState>}
        />
      </Loadable>
      </div>
    </>
  );
}
