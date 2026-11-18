// Settings: organisation, admins (invite by email + role), drills switches, fleet thresholds, platform webhook.
import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { AdminEntry, FleetThresholds, Me, OrgSettings, PlatformWebhook, Role, WebhookTestResult } from '../api/types';
import { mutate, useResource } from '../data/hooks';
import { Badge, Button, ErrorBanner, Panel, SkeletonBlock, StatusPill } from '../components/atoms';
import { CheckField, FormError, SecretField, SelectField, TextField, failText } from '../components/forms';
import { notify } from '../components/Toasts';
import { PageHeader } from './common';
import { formatAbsolute } from '../lib/format';
import { RE, httpsProblem, intIn, numIn } from '../lib/validate';

const isOwner = (me: Me | undefined): boolean => me?.role === 'owner';
const isAdmin = (me: Me | undefined): boolean => me?.role === 'owner' || me?.role === 'admin';

function OwnerNote({ me }: { me: Me | undefined }): JSX.Element | null {
  return isOwner(me) ? null : <p class="banner banner-warn" role="status"><span>Only the owner can change these settings.</span></p>;
}

// ---- organisation -------------------------------------------------------------------------------------------------

function OrgForm({ s, me }: { s: OrgSettings; me: Me | undefined }): JSX.Element {
  const [name, setName] = useState(s.org_name);
  const [drills, setDrills] = useState(s.drills_enabled);
  const [two, setTwo] = useState(s.drills_two_person);
  const [metrics, setMetrics] = useState(String(s.default_retention.metrics_days));
  const [records, setRecords] = useState(String(s.default_retention.records_days));
  const [channel, setChannel] = useState(s.release_channel ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const allowed = isOwner(me);
  const p = {
    name: name.trim() === '' ? 'Enter an organisation name.' : name.length > 128 ? 'At most 128 characters.' : null,
    metrics: intIn(metrics, 1, 365) === null ? '1 to 365 days.' : null,
    records: intIn(records, 1, 365) === null ? '1 to 365 days.' : null,
    channel: channel.length > 32 ? 'At most 32 characters.' : null,
  };
  const patch: Record<string, unknown> = {};
  if (name.trim() !== s.org_name) patch['org_name'] = name.trim();
  if (drills !== s.drills_enabled) patch['drills_enabled'] = drills;
  if (two !== s.drills_two_person) patch['drills_two_person'] = two;
  if (Number(metrics) !== s.default_retention.metrics_days || Number(records) !== s.default_retention.records_days) patch['default_retention'] = { metrics_days: Number(metrics), records_days: Number(records) };
  if (channel !== (s.release_channel ?? '') && channel) patch['release_channel'] = channel;
  const dirty = Object.keys(patch).length > 0;
  const valid = Object.values(p).every((x) => !x);
  const save = async (e: Event) => {
    e.preventDefault();
    if (!dirty || !valid || busy) return;
    setBusy(true);
    setError(null);
    try {
      await mutate('PATCH', ep.settings, patch);
      notify('ok', 'Settings saved');
    } catch (err) {
      setError(failText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={(e) => void save(e)} aria-label="Organisation settings" noValidate>
      <OwnerNote me={me} />
      <div class="form-grid">
        <TextField label="Organisation name" value={name} onInput={setName} error={p.name} disabled={!allowed} maxLength={128} />
        <TextField label="Release channel" value={channel} onInput={setChannel} error={p.channel} hint="Which published releases this manager offers (for example stable)." disabled={!allowed} />
        <TextField label="Default metrics retention (days)" value={metrics} onInput={setMetrics} type="number" inputMode="numeric" error={p.metrics} hint="Sites and collectors can override it." disabled={!allowed} />
        <TextField label="Default records retention (days)" value={records} onInput={setRecords} type="number" inputMode="numeric" error={p.records} disabled={!allowed} />
      </div>
      <fieldset class="fieldset">
        <legend>Failure drills</legend>
        <CheckField label="Drills enabled" checked={drills} onChange={setDrills} disabled={!allowed} hint="Master switch. Drills themselves arrive in a later release." />
        <CheckField label="Two-person approval" checked={two} onChange={setTwo} disabled={!allowed} hint="A drill must be approved by a different admin than the one who created it." />
      </fieldset>
      <FormError error={error} />
      <div class="dialog-actions"><Button type="submit" variant="primary" disabled={!allowed || !dirty || !valid || busy}>{busy ? 'Saving…' : 'Save settings'}</Button></div>
    </form>
  );
}

// ---- admins -------------------------------------------------------------------------------------------------------

const ROLE_OPTS = [{ value: 'admin', label: 'Admin' }, { value: 'operator', label: 'Operator' }, { value: 'viewer', label: 'Viewer' }];
const asRole = (v: string): Role => (v === 'admin' ? 'admin' : v === 'operator' ? 'operator' : 'viewer');

function AdminsPanel({ s, me }: { s: OrgSettings; me: Me | undefined }): JSX.Element {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const allowed = isOwner(me);
  const emailLc = email.trim().toLowerCase();
  const emailBad = email !== '' && (!RE.email.test(email.trim()) || email.length > 254);
  const exists = s.admins.some((a) => a.email.toLowerCase() === emailLc);

  // The whole list is sent with one entry changed: an upsert and a replace give the same result.
  const send = async (next: AdminEntry[], okText: string) => {
    setBusy(true);
    setError(null);
    try {
      await mutate('PATCH', ep.settings, { admins: next.map((a) => ({ email: a.email, role: a.role, ...(a.disabled ? { disabled: true } : { disabled: false }) })) });
      notify('ok', okText);
      return true;
    } catch (e) {
      setError(failText(e));
      return false;
    } finally {
      setBusy(false);
    }
  };
  const invite = async (e: Event) => {
    e.preventDefault();
    if (!emailLc || emailBad || exists || busy) return;
    if (await send([...s.admins, { email: emailLc, role }], `Invited ${emailLc} as ${role}`)) setEmail('');
  };
  const change = (a: AdminEntry, patch: Partial<AdminEntry>, text: string) => void send(s.admins.map((x) => (x.email === a.email ? { ...x, ...patch } : x)), text);
  return (
    <Panel title="Admins" id="adm">
      <p class="dim">People who can sign in to this manager (through Cloudflare Access). Viewers can look, operators can also run drills, admins can change the fleet, the owner manages settings and admins.</p>
      <OwnerNote me={me} />
      <div class="table-scroll">
        <table class="plain" data-testid="admins-table">
          <caption class="sr-only">Admins</caption>
          <thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Last seen</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {s.admins.map((a) => {
              const owner = a.role === 'owner';
              return (
                <tr key={a.email}>
                  <th scope="row">{a.email}</th>
                  <td>
                    {owner ? <Badge tone="ok">owner</Badge> : (
                      <select aria-label={`Role of ${a.email}`} value={a.role} disabled={!allowed || busy} onChange={(e) => change(a, { role: asRole((e.currentTarget as HTMLSelectElement).value) }, `${a.email} is now ${(e.currentTarget as HTMLSelectElement).value}`)}>
                        {ROLE_OPTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                      </select>
                    )}
                  </td>
                  <td>{a.disabled ? <StatusPill state="stale" label="disabled" /> : <StatusPill state="ok" label="active" />}</td>
                  <td>{a.last_seen ? formatAbsolute(a.last_seen) : <span class="dim">never</span>}</td>
                  <td>{owner ? null : <Button small disabled={!allowed || busy} onClick={() => change(a, { disabled: !a.disabled }, a.disabled ? `Enabled ${a.email}` : `Disabled ${a.email}`)} aria-label={`${a.disabled ? 'Enable' : 'Disable'} ${a.email}`}>{a.disabled ? 'Enable' : 'Disable'}</Button>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <form onSubmit={(e) => void invite(e)} aria-label="Invite an admin" noValidate>
        <h3 class="h3">Invite someone</h3>
        <div class="form-grid">
          <TextField label="Email address" value={email} onInput={setEmail} type="email" error={emailBad ? 'Enter a valid email address.' : exists ? 'That person is already listed.' : null} disabled={!allowed} />
          <SelectField label="Role" value={role} onChange={(v) => setRole(asRole(v))} options={ROLE_OPTS} disabled={!allowed} />
        </div>
        <p class="hint">Also allow this address in the Cloudflare Access policy for the manager; the invitation here only grants the role.</p>
        <FormError error={error} />
        <div class="dialog-actions"><Button type="submit" variant="primary" disabled={!allowed || !emailLc || emailBad || exists || busy}>{busy ? 'Saving…' : 'Invite'}</Button></div>
      </form>
    </Panel>
  );
}

// ---- fleet thresholds ---------------------------------------------------------------------------------------------

interface Fld { k: string; label: string; unit: string; min: number; max?: number; int?: boolean; def: number }
interface Grp { key: string; label: string; fields: Fld[]; order?: [string, string, string] }
const GROUPS: Grp[] = [
  { key: 'disk_high', label: 'Disk usage', fields: [{ k: 'warn_pct', label: 'Warn at', unit: '%', min: 0, max: 100, def: 85 }, { k: 'crit_pct', label: 'Critical at', unit: '%', min: 0, max: 100, def: 95 }], order: ['warn_pct', 'crit_pct', 'up'] },
  { key: 'storage_runway', label: 'Collector storage runway', fields: [{ k: 'warn_days', label: 'Warn below', unit: 'days', min: 0, def: 7 }, { k: 'crit_days', label: 'Critical below', unit: 'days', min: 0, def: 2 }], order: ['crit_days', 'warn_days', 'down'] },
  { key: 'mem_low', label: 'Low memory', fields: [{ k: 'available_pct', label: 'Available below', unit: '%', min: 0, max: 100, def: 10 }, { k: 'for_min', label: 'For at least', unit: 'min', min: 1, max: 1440, int: true, def: 10 }] },
  { key: 'cpu_high', label: 'High CPU', fields: [{ k: 'pct', label: 'At or above', unit: '%', min: 0, max: 100, def: 90 }, { k: 'avg_min', label: 'Averaged over', unit: 'min', min: 1, max: 1440, int: true, def: 15 }] },
  { key: 'probe_push_lag', label: 'Probe push lag', fields: [{ k: 'warn_s', label: 'Warn above', unit: 's', min: 0, def: 120 }, { k: 'crit_s', label: 'Critical above', unit: 's', min: 0, def: 600 }], order: ['warn_s', 'crit_s', 'up'] },
  { key: 'probe_spool', label: 'Probe spool', fields: [{ k: 'pct', label: 'Warn above', unit: '% of limit', min: 0, max: 100, def: 50 }] },
  { key: 'crash_loop', label: 'Crash loop', fields: [{ k: 'restarts', label: 'Restarts', unit: '', min: 1, int: true, def: 3 }, { k: 'window_min', label: 'Within', unit: 'min', min: 1, int: true, def: 15 }] },
  { key: 'version_drift', label: 'Version drift', fields: [{ k: 'minutes', label: 'Warn after', unit: 'min', min: 1, int: true, def: 10 }] },
  { key: 'clock', label: 'Clock offset', fields: [{ k: 'offset_ms', label: 'Warn above', unit: 'ms', min: 0, def: 1000 }] },
  { key: 'iface_errors', label: 'Interface errors', fields: [{ k: 'pct', label: 'Errors and drops above', unit: '% of packets', min: 0, def: 0.1 }, { k: 'window_min', label: 'Over', unit: 'min', min: 1, int: true, def: 15 }] },
];

export function thresholdProblems(vals: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const g of GROUPS) {
    for (const f of g.fields) {
      const raw = vals[`${g.key}.${f.k}`] ?? '';
      const n = f.int ? intIn(raw, f.min, f.max ?? 1_000_000) : numIn(raw, f.min, f.max ?? 1_000_000_000);
      if (n === null) out[`${g.key}.${f.k}`] = `Enter ${f.int ? 'a whole number' : 'a number'} from ${f.min}${f.max !== undefined ? ` to ${f.max}` : ' up'}.`;
    }
    if (g.order) {
      const [lo, hi] = g.order;
      const a = Number(vals[`${g.key}.${lo}`]);
      const b = Number(vals[`${g.key}.${hi}`]);
      if (!out[`${g.key}.${lo}`] && !out[`${g.key}.${hi}`] && !(a <= b)) out[`${g.key}.${g.order[2] === 'up' ? hi : lo}`] = g.order[2] === 'up' ? 'The critical level must not be below the warning level.' : 'The critical level must not be above the warning level.';
    }
  }
  return out;
}

function ThresholdsForm({ cur }: { cur: FleetThresholds }): JSX.Element {
  const init: Record<string, string> = {};
  for (const g of GROUPS) for (const f of g.fields) init[`${g.key}.${f.k}`] = String(cur[g.key]?.[f.k] ?? f.def);
  const [vals, setVals] = useState(init);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const problems = thresholdProblems(vals);
  const dirty = GROUPS.some((g) => g.fields.some((f) => Number(vals[`${g.key}.${f.k}`]) !== Number(init[`${g.key}.${f.k}`])));
  const save = async (e: Event) => {
    e.preventDefault();
    if (Object.keys(problems).length || !dirty || busy) return;
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, Record<string, number>> = {};
      for (const g of GROUPS) {
        body[g.key] = {};
        for (const f of g.fields) (body[g.key] as Record<string, number>)[f.k] = Number(vals[`${g.key}.${f.k}`]);
      }
      await mutate('PUT', ep.thresholds, body);
      notify('ok', 'Fleet thresholds saved');
    } catch (err) {
      setError(failText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={(e) => void save(e)} aria-label="Fleet thresholds" noValidate>
      <div class="thr-grid">
        {GROUPS.map((g) => (
          <fieldset key={g.key} class="fieldset">
            <legend>{g.label}</legend>
            {g.fields.map((f) => (
              <TextField key={f.k} label={`${f.label}${f.unit ? ` (${f.unit})` : ''}`} value={vals[`${g.key}.${f.k}`] ?? ''} type="number" inputMode="decimal"
                onInput={(v) => setVals((c) => ({ ...c, [`${g.key}.${f.k}`]: v }))} error={problems[`${g.key}.${f.k}`] ?? null} />
            ))}
          </fieldset>
        ))}
      </div>
      <FormError error={error} />
      <div class="dialog-actions"><Button type="submit" variant="primary" disabled={!dirty || Object.keys(problems).length > 0 || busy}>{busy ? 'Saving…' : 'Save thresholds'}</Button></div>
    </form>
  );
}

// ---- platform webhook ---------------------------------------------------------------------------------------------

function PlatformWebhookForm({ cur }: { cur: PlatformWebhook }): JSX.Element {
  const [format, setFormat] = useState<'slack' | 'teams' | 'json'>(cur.format);
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<WebhookTestResult | null>(null);
  const bad = url.trim() ? httpsProblem(url.trim()) : null;
  const dirty = format !== cur.format || url.trim() !== '';
  const save = async (e: Event) => {
    e.preventDefault();
    if (!dirty || bad || busy) return;
    setBusy(true);
    setError(null);
    try {
      await mutate('PUT', ep.platformWebhook, { format, ...(url.trim() ? { url: url.trim() } : {}) });
      notify('ok', 'Platform webhook saved');
      setUrl('');
      setResult(null);
    } catch (err) {
      setError(failText(err));
    } finally {
      setBusy(false);
    }
  };
  const test = async () => {
    setTesting(true);
    setError(null);
    try {
      setResult(await mutate<WebhookTestResult>('POST', ep.platformWebhookTest));
    } catch (e) {
      setError(failText(e));
    } finally {
      setTesting(false);
    }
  };
  return (
    <form onSubmit={(e) => void save(e)} aria-label="Platform webhook" noValidate>
      <div class="form-grid">
        <SelectField label="Format" value={format} onChange={(v) => setFormat(v === 'teams' ? 'teams' : v === 'json' ? 'json' : 'slack')} options={[{ value: 'slack', label: 'Slack' }, { value: 'teams', label: 'Microsoft Teams' }, { value: 'json', label: 'Generic JSON' }]} />
        <SecretField label="Webhook URL" state={cur.url} value={url} onInput={setUrl} error={bad} hint="Write-only. Leave empty to keep the stored URL." />
      </div>
      {result ? <p role="status" data-testid="pw-test">{result.ok ? <StatusPill state="ok" label="delivered" /> : <StatusPill state="fail" label="failed" />} {result.http_status ? `HTTP ${result.http_status}` : ''} {result.error ?? ''}</p> : null}
      <FormError error={error} />
      <div class="dialog-actions">
        <Button onClick={() => void test()} disabled={testing || dirty || !cur.url.set} title={dirty ? 'Save first: the test uses the saved URL' : undefined}>{testing ? 'Sending…' : 'Send test'}</Button>
        <Button type="submit" variant="primary" disabled={!dirty || !!bad || busy}>{busy ? 'Saving…' : 'Save webhook'}</Button>
      </div>
    </form>
  );
}

// ---- page ---------------------------------------------------------------------------------------------------------

export function SettingsPage({ me }: { me: Me | undefined }): JSX.Element {
  const settings = useResource<OrgSettings>(ep.settings);
  const thr = useResource<FleetThresholds>(ep.thresholds);
  const pw = useResource<PlatformWebhook>(ep.platformWebhook);
  const admin = isAdmin(me);
  return (
    <>
      <PageHeader title="Settings" sub="Organisation, who can sign in, fleet health thresholds and where platform alerts go." />
      <Panel title="Organisation" id="org">
        {settings.loading ? <SkeletonBlock rows={4} label="Loading settings" /> : !settings.data ? <ErrorBanner what="Could not load settings." message={settings.error?.message} onRetry={settings.refresh} /> : <OrgForm key={settings.data.updated_at ?? 'org'} s={settings.data} me={me} />}
      </Panel>
      {settings.data ? <AdminsPanel s={settings.data} me={me} /> : null}
      <Panel title="Fleet thresholds" id="thr">
        <p class="dim">When the manager opens a fleet health issue. Defaults apply to anything you leave unchanged.</p>
        {!admin ? <p class="banner banner-warn" role="status"><span>Changing thresholds needs the admin role.</span></p> : null}
        {thr.loading ? <SkeletonBlock rows={4} label="Loading thresholds" /> : !thr.data ? <ErrorBanner what="Could not load thresholds." message={thr.error?.message} onRetry={thr.refresh} /> : (
          <fieldset class="bare" disabled={!admin}><ThresholdsForm key={JSON.stringify(thr.data)} cur={thr.data} /></fieldset>
        )}
      </Panel>
      <Panel title="Platform webhook" id="pwh">
        <p class="dim">Fleet health alerts (critical issues opening and resolving) go here, separately from each site's experience alerts.</p>
        {!admin ? <p class="banner banner-warn" role="status"><span>Changing the webhook needs the admin role.</span></p> : null}
        {pw.loading ? <SkeletonBlock rows={2} label="Loading webhook" /> : !pw.data ? <ErrorBanner what="Could not load the platform webhook." message={pw.error?.message} onRetry={pw.refresh} /> : (
          <fieldset class="bare" disabled={!admin}><PlatformWebhookForm key={`${pw.data.format}${pw.data.url.updated_at ?? ''}`} cur={pw.data} /></fieldset>
        )}
      </Panel>
    </>
  );
}
