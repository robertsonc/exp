import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import type { Issue, Me } from '../api/types';
import { ep } from '../api/endpoints';
import { Icon } from './Icon';
import { Button } from './atoms';
import { Link } from './viz';
import { mutate } from '../data/hooks';
import { notify } from './Toasts';
import { formatAbsolute, formatAgo } from '../lib/format';
import { isSnoozed, issueValue, kindLabel } from '../lib/issues';

export function SeverityMark({ sev }: { sev: Issue['severity'] }): JSX.Element {
  return sev === 'crit'
    ? <span class="sevmark sev-fail"><Icon name="x" size={14} /> CRIT</span>
    : <span class="sevmark sev-warn"><Icon name="alert" size={14} /> WARN</span>;
}

export function canAdmin(me: Me | undefined): boolean {
  return me?.role === 'owner' || me?.role === 'admin';
}

/** Snooze controls for one issue kind on one host (audited by the manager). */
export function SnoozeActions({ issue, me, now }: { issue: Issue; me: Me | undefined; now: number }): JSX.Element {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const allowed = canAdmin(me);
  const snoozed = isSnoozed(issue, now);
  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    try {
      await fn();
      notify('ok', ok);
      setOpen(false);
    } catch (e) {
      notify('error', `Could not update the snooze: ${e instanceof Error ? e.message : 'unknown error'}`);
    } finally {
      setBusy(false);
    }
  };
  if (snoozed) {
    return (
      <Button small disabled={!allowed || busy} title={allowed ? undefined : 'Requires the admin role'}
        onClick={() => void act(() => mutate('DELETE', ep.snooze(issue.issue_id)), `Snooze removed for ${kindLabel(issue.kind)}`)}>
        Unsnooze
      </Button>
    );
  }
  const opts: ['1h' | '24h' | 'resolved', string][] = [['1h', '1 h'], ['24h', '24 h'], ['resolved', 'Until resolved']];
  return (
    <span class="snooze">
      <Button small aria-expanded={open} disabled={!allowed} title={allowed ? 'Hide this issue kind for this host' : 'Requires the admin role'} onClick={() => setOpen(!open)}>Snooze</Button>
      {open ? (
        <span class="snooze-opts" role="group" aria-label={`Snooze ${kindLabel(issue.kind)}`}>
          {opts.map(([v, l]) => (
            <Button key={v} small disabled={busy} onClick={() => void act(() => mutate('POST', ep.snooze(issue.issue_id), { for: v }), `Snoozed ${kindLabel(issue.kind)} (${l})`)}>{l}</Button>
          ))}
        </span>
      ) : null}
    </span>
  );
}

export function IssueRow({ issue, hostName, compact, me, now }: { issue: Issue; hostName: string; compact?: boolean; me?: Me; now: number }): JSX.Element {
  const val = issueValue(issue);
  return (
    <div class={`issue-row${compact ? ' issue-compact' : ''}`}>
      <SeverityMark sev={issue.severity} />
      <span class="issue-main">
        <Link to={issue.component_id ? `/hosts/${issue.host_id}/components/${issue.component_id}` : `/hosts/${issue.host_id}`} class="issue-host">{hostName}</Link>
        <span class="issue-detail">{issue.detail}</span>
      </span>
      {!compact ? <span class="issue-since" title={formatAbsolute(issue.opened_at)}>{formatAgo(issue.opened_at, now)}</span> : null}
      {val ? <span class="issue-val">{val}</span> : null}
      {!compact && me ? <SnoozeActions issue={issue} me={me} now={now} /> : null}
    </div>
  );
}
