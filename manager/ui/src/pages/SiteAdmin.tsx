// Site administration: create, edit, delete, alert settings (with write-only webhook URLs and "Send test").
import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { Alerts, AlertsConfig, AlertTestResult, Me, OrgSettings, SecretState, Site } from '../api/types';
import { mutate, useResource } from '../data/hooks';
import { Badge, Button, ConfirmDialog, Dialog, ErrorBanner, Panel, SkeletonBlock, StatusPill } from '../components/atoms';
import { CheckField, FormError, SelectField, SecretField, TextField, failText } from '../components/forms';
import { canAdmin } from '../components/Issues';
import { notify } from '../components/Toasts';
import { DASH } from '../lib/format';
import { RE, httpsProblem, intIn, slugProblem, slugify } from '../lib/validate';
import { navigate } from '../router';
import { ReleaseTargetDialog } from './ReleasesPage';

// ---- create / edit site -------------------------------------------------------------------------------------------

export function SiteDialog({ site, onClose }: { site?: Site; onClose: () => void }): JSX.Element {
  const settings = useResource<OrgSettings>(ep.settings);
  const def = settings.data?.default_retention;
  const [name, setName] = useState(site?.name ?? '');
  const [slug, setSlug] = useState(site?.site ?? '');
  const [slugTouched, setSlugTouched] = useState(false);
  const [tz, setTz] = useState(site?.timezone ?? 'UTC');
  const [edge, setEdge] = useState(site?.edge_label ?? '');
  const [override, setOverride] = useState(!!site?.retention);
  const [metrics, setMetrics] = useState(String(site?.retention?.metrics_days ?? def?.metrics_days ?? 30));
  const [records, setRecords] = useState(String(site?.retention?.records_days ?? def?.records_days ?? 7));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const slugVal = site ? site.site : slugTouched ? slug : slugify(name);
  const problems: Record<string, string | null> = {
    name: name.trim() === '' ? 'Enter a name.' : name.length > 128 ? 'At most 128 characters.' : null,
    slug: site ? null : slugProblem(slugVal, 'Slug'),
    tz: RE.timezone.test(tz) ? null : 'Use an IANA zone such as America/Chicago, or UTC.',
    edge: edge.length > 32 ? 'At most 32 characters.' : null,
    metrics: override && intIn(metrics, 1, 365) === null ? '1 to 365 days.' : null,
    records: override && intIn(records, 1, 365) === null ? '1 to 365 days.' : null,
  };
  const valid = Object.values(problems).every((p) => !p);

  const submit = async (e: Event) => {
    e.preventDefault();
    if (!valid || busy) return;
    setBusy(true);
    setError(null);
    try {
      const retention = override ? { metrics_days: Number(metrics), records_days: Number(records) } : undefined;
      if (site) {
        const patch: Record<string, unknown> = {};
        if (name.trim() !== site.name) patch['name'] = name.trim();
        if (tz !== site.timezone) patch['timezone'] = tz;
        if (edge !== site.edge_label) patch['edge_label'] = edge;
        if (retention && JSON.stringify(retention) !== JSON.stringify({ metrics_days: site.retention?.metrics_days, records_days: site.retention?.records_days })) patch['retention'] = retention;
        if (Object.keys(patch).length === 0) {
          onClose();
          return;
        }
        await mutate('PATCH', ep.site(site.site), patch);
        notify('ok', `Saved ${name.trim()}`);
        onClose();
      } else {
        await mutate('POST', ep.sites, { site: slugVal, name: name.trim(), timezone: tz, ...(edge ? { edge_label: edge } : {}), ...(retention ? { retention } : {}) });
        notify('ok', `Created site ${name.trim()}`);
        onClose();
        navigate(`/sites/${slugVal}`);
      }
    } catch (err) {
      setError(failText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog title={site ? `Edit ${site.name}` : 'Create a site'} onClose={onClose} wide>
      <form onSubmit={(e) => void submit(e)} noValidate aria-label={site ? 'Edit site' : 'Create site'}>
        <div class="form-grid">
          <TextField label="Name" value={name} onInput={setName} error={name ? problems['name'] : null} maxLength={128} />
          <TextField label="Slug" value={slugVal} onInput={(v) => { setSlug(v); setSlugTouched(true); }} disabled={!!site} error={slugVal ? problems['slug'] : null} hint={site ? 'The slug cannot change.' : 'Used in URLs and ids.'} />
          <TextField label="Time zone" value={tz} onInput={setTz} error={problems['tz']} hint="IANA name; charts and alert times use it." />
          <TextField label="Edge label" value={edge} onInput={setEdge} error={problems['edge']} hint="Short name for the site edge on the board, for example EC." maxLength={32} />
        </div>
        <CheckField label="Override the default retention for this site" checked={override} onChange={setOverride} />
        {override ? (
          <div class="form-grid">
            <TextField label="Metrics (days)" value={metrics} onInput={setMetrics} type="number" inputMode="numeric" error={problems['metrics']} />
            <TextField label="Records (days)" value={records} onInput={setRecords} type="number" inputMode="numeric" error={problems['records']} />
          </div>
        ) : null}
        <FormError error={error} />
        <div class="dialog-actions">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!valid || busy}>{busy ? 'Saving…' : site ? 'Save site' : 'Create site'}</Button>
        </div>
      </form>
    </Dialog>
  );
}

export function DeleteSiteButton({ site, allowed }: { site: Site; allowed: boolean }): JSX.Element {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const del = async () => {
    setBusy(true);
    setError(null);
    try {
      await mutate('DELETE', ep.site(site.site));
      notify('ok', `Deleted site ${site.name}`);
      setOpen(false);
      navigate('/sites');
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Button variant="danger" disabled={!allowed} onClick={() => setOpen(true)}>Delete site</Button>
      {open ? (
        <ConfirmDialog title={`Delete ${site.name}?`} body={<p>Only a site with no hosts can be deleted. Its alert settings and webhooks are removed with it.</p>}
          confirmText="Delete site" typeName={site.site} busy={busy} error={error} onConfirm={() => void del()} onCancel={() => { setOpen(false); setError(null); }} />
      ) : null}
    </>
  );
}

// ---- release target -----------------------------------------------------------------------------------------------

export function SiteReleasePanel({ site, me }: { site: Site; me: Me | undefined }): JSX.Element {
  const [dlg, setDlg] = useState<'set' | 'rollback' | null>(null);
  const allowed = canAdmin(me);
  const failed = site.canary_state === 'failed';
  const running = site.canary_state === 'pending' || site.canary_state === 'healthy_waiting';
  return (
    <Panel title="Release" id="sr">
      <dl class="facts">
        <div><dt>Target version</dt><dd data-testid="site-release">{site.release_version ?? DASH}</dd></div>
        <div><dt>Canary</dt><dd>{site.canary_state ? <Badge tone={failed ? 'fail' : site.canary_state === 'promoted' ? 'ok' : 'warn'}>{site.canary_state.replace('_', ' ')}</Badge> : 'none'}{site.canary_host_id ? <span class="dim"> on {site.canary_host_id}</span> : null}</dd></div>
      </dl>
      {failed ? <p class="banner banner-fail" role="alert"><span>The canary host failed its health checks, so the rollout is halted. Roll back, or fix the host and set the release again.</span></p> : null}
      {running ? <p class="banner banner-info" role="status"><span>A canary rollout is in progress. It is promoted automatically after the canary host has been healthy for 10 minutes.</span></p> : null}
      <div class="dialog-actions">
        <Button variant="primary" disabled={!allowed || running} onClick={() => setDlg('set')}>Set release…</Button>
        <Button disabled={!allowed || running || !site.release_version} onClick={() => setDlg('rollback')}>Roll back…</Button>
      </div>
      {dlg ? <ReleaseTargetDialog site={site} mode={dlg} onClose={() => setDlg(null)} /> : null}
    </Panel>
  );
}

// ---- probe heartbeat (CR-heartbeat-cadence) ------------------------------------------------------------------------

const HEARTBEATS = [
  { value: '10', label: 'Standard: every 10 s (default)' },
  { value: '5', label: 'Fast detection: every 5 s (about double the probe traffic)' },
];

export function SiteHeartbeatPanel({ site, me }: { site: Site; me: Me | undefined }): JSX.Element {
  const allowed = canAdmin(me);
  const [value, setValue] = useState('10');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await mutate<{ updated: number; interval_s: number }>('POST', ep.siteProbeHeartbeat(site.site), { interval_s: Number(value) });
      notify('ok', r.updated === 0 ? `Every probe in ${site.name} already beats every ${r.interval_s} s.`
        : `${r.updated} probe${r.updated === 1 ? '' : 's'} in ${site.name} now beat every ${r.interval_s} s; hosts apply it on their next poll.`);
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Panel title="Probe heartbeat" id="sh">
      <p class="dim">How often every probe in this site checks the gateway, DHCP, DNS and internet. Faster beats find a fault
        sooner but send and store about twice as many results. The board's state changes follow the collector's rules
        in seconds, so a faster heartbeat sharpens them; it never makes the board react faster than the data.
        A single probe can still be set on its own page (5 to 60 s).</p>
      <SelectField label="Heartbeat for every probe in this site" value={value} onChange={setValue} options={HEARTBEATS} disabled={!allowed || busy} />
      <FormError error={error} />
      <div class="dialog-actions">
        <Button variant="primary" disabled={!allowed || busy} onClick={() => void apply()}>{busy ? 'Applying…' : 'Apply to all probes'}</Button>
      </div>
    </Panel>
  );
}

// ---- alerts -------------------------------------------------------------------------------------------------------

interface HookRow { id?: string; format: 'slack' | 'teams' | 'json'; url: string; state?: SecretState }

function AlertsForm({ slug, data, allowed, onSaved }: { slug: string; data: Alerts; allowed: boolean; onSaved: (a: Alerts) => void }): JSX.Element {
  const c = data.config;
  const [enabled, setEnabled] = useState(c.enabled);
  const [board, setBoard] = useState(c.board_url ?? '');
  const [tz, setTz] = useState(c.timezone ?? '');
  const [voice, setVoice] = useState<'plain' | 'sysadmin'>(c.voice);
  const [hd, setHd] = useState(String(c.hold_down_s));
  const [hb, setHb] = useState(String(c.hold_back_s));
  const [ro, setRo] = useState(String(c.reopen_s));
  const [calm, setCalm] = useState(String(c.calm_s));
  const [rows, setRows] = useState<HookRow[]>(data.webhooks.map((w) => ({ id: w.id, format: w.format, url: '', state: w.url })));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [results, setResults] = useState<AlertTestResult['results'] | null>(null);
  const [dirty, setDirty] = useState(false);
  const touch = <T,>(set: (v: T) => void) => (v: T) => { setDirty(true); set(v); };

  const p: Record<string, string | null> = {
    board: board.trim() && httpsProblem(board.trim()),
    tz: tz.trim() && !RE.timezone.test(tz.trim()) ? 'Use an IANA zone such as America/Chicago, or UTC.' : null,
    hd: intIn(hd, 0, 3600) === null ? '0 to 3600 seconds.' : null,
    hb: intIn(hb, 0, 3600) === null ? '0 to 3600 seconds.' : null,
    ro: intIn(ro, 0, 86400) === null ? '0 to 86400 seconds.' : null,
    calm: intIn(calm, 0, 86400) === null ? '0 to 86400 seconds.' : null,
  };
  const rowProblem = (r: HookRow): string | null => {
    if (r.url.trim()) return httpsProblem(r.url.trim());
    return r.id ? null : 'A new webhook needs a URL.';
  };
  const valid = Object.values(p).every((x) => !x) && rows.every((r) => !rowProblem(r));

  const save = async () => {
    if (!valid || busy) return;
    setBusy(true);
    setError(null);
    try {
      const config: AlertsConfig = {
        enabled, board_url: board.trim() ? board.trim() : null, voice, hold_down_s: Number(hd), hold_back_s: Number(hb), reopen_s: Number(ro), calm_s: Number(calm),
        ...(tz.trim() ? { timezone: tz.trim() } : {}),
      };
      const webhooks = rows.map((r) => ({ ...(r.id ? { id: r.id } : {}), format: r.format, ...(r.url.trim() ? { url: r.url.trim() } : {}) }));
      const saved = await mutate<Alerts>('PUT', ep.siteAlerts(slug), { config, webhooks });
      notify('ok', 'Alert settings saved');
      setDirty(false);
      setResults(null);
      onSaved(saved);
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  const test = async () => {
    setTesting(true);
    setError(null);
    try {
      setResults((await mutate<AlertTestResult>('POST', ep.siteAlertsTest(slug))).results);
    } catch (e) {
      setError(failText(e));
    } finally {
      setTesting(false);
    }
  };
  const setRow = (i: number, patch: Partial<HookRow>) => { setDirty(true); setRows((cur) => cur.map((r, j) => (j === i ? { ...r, ...patch } : r))); };
  return (
    <form onSubmit={(e) => { e.preventDefault(); void save(); }} noValidate aria-label="Alert settings">
      <CheckField label="Experience alerts enabled for this site" checked={enabled} onChange={touch(setEnabled)} disabled={!allowed} />
      <div class="form-grid">
        <TextField label="Board URL" value={board} onInput={touch(setBoard)} type="url" error={p['board']} hint="Linked from alert messages." disabled={!allowed} />
        <TextField label="Time zone" value={tz} onInput={touch(setTz)} error={p['tz']} disabled={!allowed} />
        <SelectField label="Voice" value={voice} onChange={touch((v: string) => setVoice(v === 'plain' ? 'plain' : 'sysadmin'))} disabled={!allowed} options={[{ value: 'sysadmin', label: 'Sysadmin (technical)' }, { value: 'plain', label: 'Plain language' }]} />
      </div>
      <div class="form-grid form-grid-4">
        <TextField label="Hold down (s)" value={hd} onInput={touch(setHd)} type="number" inputMode="numeric" error={p['hd']} disabled={!allowed} />
        <TextField label="Hold back (s)" value={hb} onInput={touch(setHb)} type="number" inputMode="numeric" error={p['hb']} disabled={!allowed} />
        <TextField label="Reopen window (s)" value={ro} onInput={touch(setRo)} type="number" inputMode="numeric" error={p['ro']} disabled={!allowed} />
        <TextField label="Calm period (s)" value={calm} onInput={touch(setCalm)} type="number" inputMode="numeric" error={p['calm']} disabled={!allowed} />
      </div>
      <fieldset class="fieldset">
        <legend>Webhooks</legend>
        <p class="hint">Where alert messages go. A URL is a secret: it is never shown again after saving. Leave the field empty to keep the stored URL.</p>
        {rows.length === 0 ? <p class="dim">No webhooks configured.</p> : null}
        {rows.map((r, i) => (
          <div key={r.id ?? `new-${i}`} class="rowbox" role="group" aria-label={`Webhook ${i + 1}`}>
            <div class="form-grid">
              <SelectField label="Format" value={r.format} onChange={(v) => setRow(i, { format: v === 'teams' ? 'teams' : v === 'json' ? 'json' : 'slack' })} disabled={!allowed} options={[{ value: 'slack', label: 'Slack' }, { value: 'teams', label: 'Microsoft Teams' }, { value: 'json', label: 'Generic JSON' }]} />
              <SecretField label="Webhook URL" state={r.state} value={r.url} onInput={(v) => setRow(i, { url: v })} error={r.url ? rowProblem(r) : r.id ? null : rowProblem(r)} disabled={!allowed} />
            </div>
            <Button small disabled={!allowed} onClick={() => { setDirty(true); setRows((cur) => cur.filter((_, j) => j !== i)); }} aria-label={`Remove webhook ${i + 1}`}>Remove</Button>
          </div>
        ))}
        <Button small disabled={!allowed || rows.length >= 20} onClick={() => { setDirty(true); setRows((cur) => [...cur, { format: 'slack', url: '' }]); }}>Add webhook</Button>
      </fieldset>
      {results ? (
        <ul class="test-results" aria-label="Test results" data-testid="alert-test-results">
          {results.length === 0 ? <li class="dim">There are no webhooks to test.</li> : null}
          {results.map((r) => (
            <li key={r.webhook_id}><StatusPill state={r.ok ? 'ok' : 'fail'} label={r.ok ? 'delivered' : 'failed'} /> {r.webhook_id}{r.http_status ? ` · HTTP ${r.http_status}` : ''}{r.error ? ` · ${r.error}` : ''}</li>
          ))}
        </ul>
      ) : null}
      <FormError error={error} />
      <div class="dialog-actions">
        <Button onClick={() => void test()} disabled={!allowed || testing || dirty || data.webhooks.length === 0} title={dirty ? 'Save first: the test sends to the saved webhooks' : undefined}>{testing ? 'Sending…' : 'Send test'}</Button>
        <Button type="submit" variant="primary" disabled={!allowed || !valid || busy || !dirty}>{busy ? 'Saving…' : 'Save alert settings'}</Button>
      </div>
    </form>
  );
}

export function SiteAlertsPanel({ slug, me }: { slug: string; me: Me | undefined }): JSX.Element {
  const res = useResource<Alerts>(ep.siteAlerts(slug));
  const [saved, setSaved] = useState<Alerts | null>(null);
  const [rev, setRev] = useState(0);
  const data = saved ?? res.data;
  return (
    <Panel title="Alert settings" id="sa">
      {res.loading && !data ? <SkeletonBlock rows={4} label="Loading alert settings" /> : !data ? <ErrorBanner what="Could not load alert settings." message={res.error?.message} onRetry={res.refresh} /> : (
        <AlertsForm key={rev} slug={slug} data={data} allowed={canAdmin(me)} onSaved={(a) => { setSaved(a); setRev((n) => n + 1); }} />
      )}
    </Panel>
  );
}
