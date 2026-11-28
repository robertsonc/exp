// Ops board: how many Mist and Central devices exist, and how many are online / offline. One card per platform,
// big numbers, readable from across the NOC. The manager polls the vendors read-only and caches 60 s; this page
// re-reads every 30 s like every other page. Connector setup (owner only) is a dialog on the card.
import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { IntegrationRead, IntegrationTestResult, Me, OpsDevices, OpsKind, OpsSource } from '../api/types';
import { mutate, useNow, useResource } from '../data/hooks';
import { Button, Dialog, ErrorBanner, SkeletonBlock, StatusPill } from '../components/atoms';
import { FormError, TextField, failText, secretSummary } from '../components/forms';
import { notify } from '../components/Toasts';
import { AsOf, PageHeader } from './common';
import { formatAgo } from '../lib/format';
import { httpsProblem } from '../lib/validate';

const isOwner = (me: Me | undefined): boolean => me?.role === 'owner';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CENTRAL_HOST = /^https:\/\/[a-z0-9-]{1,32}\.api\.central\.arubanetworks\.com(\.cn)?\/?$/i;
const TYPE_LABEL: Record<string, string> = { ap: 'APs', switch: 'Switches', gateway: 'Gateways', other: 'Other' };
const FIELD_LABEL: Record<string, string> = { api_base: 'API URL', org_id: 'org ID', token: 'API token', client_id: 'client ID', client_secret: 'client secret' };
const fmt = (n: number | null): string => (n === null ? '–' : n.toLocaleString());

function Card({ s, me, now, onSetup }: { s: OpsSource; me: Me | undefined; now: number; onSetup: () => void }): JSX.Element {
  const has = s.total !== null;
  const off = s.offline ?? 0;
  const pill = s.state === 'ok' ? <StatusPill state={off > 0 ? 'warn' : 'ok'} label={off > 0 ? `${off} offline` : 'all online'} />
    : s.state === 'error' ? <StatusPill state="fail" label="poll failing" />
    : s.state === 'pending' ? <StatusPill state="unknown" label="first poll…" />
    : <StatusPill state="unknown" label="not connected" />;
  const types = Object.entries(s.by_type).filter(([, v]) => v && v.total > 0);
  return (
    <section class={`ops-card${s.state === 'error' ? ' ops-card-error' : ''}`} aria-labelledby={`ops-${s.kind}-h`} data-testid={`ops-${s.kind}`}>
      <header class="ops-head">
        <h2 id={`ops-${s.kind}-h`}>{s.label}</h2>
        {pill}
      </header>
      {s.state === 'unconfigured' ? (
        <div class="ops-empty">
          <p>Not connected. Missing: {s.missing.map((m) => FIELD_LABEL[m] ?? m).join(', ')}.</p>
          {isOwner(me) ? <Button variant="primary" onClick={onSetup}>Connect {s.kind === 'mist' ? 'Mist' : 'Central'}</Button> : <p class="dim">Only the owner can connect it.</p>}
        </div>
      ) : (
        <>
          <dl class={`ops-nums${has ? '' : ' ops-nums-none'}${s.state === 'error' ? ' ops-stale' : ''}`}>
            <div><dt>Total</dt><dd data-k="total">{fmt(s.total)}</dd></div>
            <div class="ops-online"><dt>Online</dt><dd data-k="online">{fmt(s.online)}</dd></div>
            <div class={off > 0 ? 'ops-offline ops-bad' : 'ops-offline'}><dt>Offline</dt><dd data-k="offline">{fmt(s.offline)}</dd></div>
          </dl>
          {types.length ? <p class="ops-types">{types.map(([k, v]) => `${TYPE_LABEL[k] ?? k} ${v.online}/${v.total}`).join(' · ')}</p> : null}
          {s.error ? <p class="ops-error" role="status">{s.error}{has && s.counts_at ? ` Showing counts from ${formatAgo(s.counts_at, now)}.` : ''}</p> : null}
          <footer class="ops-foot">
            <span class="dim">{s.counts_at ? <AsOf ts={s.counts_at} now={now} label="Counted" /> : 'Waiting for the first poll'}</span>
            {isOwner(me) ? <Button small onClick={onSetup}>Connector</Button> : null}
          </footer>
        </>
      )}
    </section>
  );
}

function Totals({ list }: { list: OpsSource[] }): JSX.Element | null {
  const live = list.filter((s) => s.total !== null);
  if (live.length < 2) return null;
  const sum = (k: 'total' | 'online' | 'offline') => live.reduce((a, s) => a + (s[k] ?? 0), 0);
  const off = sum('offline');
  return (
    <p class="ops-sum" data-testid="ops-sum">
      All platforms: <strong>{sum('total').toLocaleString()}</strong> devices, <strong class="ops-online">{sum('online').toLocaleString()}</strong> online, <strong class={off > 0 ? 'ops-bad' : ''}>{off.toLocaleString()}</strong> offline
    </p>
  );
}

function SetupDialog({ kind, onClose }: { kind: OpsKind; onClose: () => void }): JSX.Element {
  const res = useResource<IntegrationRead>(ep.integration(kind));
  const d = res.data;
  const cfgStr = (k: string): string => (typeof d?.config[k] === 'string' ? (d.config[k] as string) : '');
  const [base, setBase] = useState<string | null>(null);
  const [org, setOrg] = useState<string | null>(null);
  const [s1, setS1] = useState('');
  const [s2, setS2] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tested, setTested] = useState<IntegrationTestResult | null>(null);
  const mist = kind === 'mist';
  const baseVal = base ?? (cfgStr('api_base') || cfgStr('url') || (mist ? 'https://api.mist.com' : ''));
  const orgVal = org ?? cfgStr('org_id');
  const baseErr = !baseVal.trim() ? 'Required.' : httpsProblem(baseVal.trim()) ?? (!mist && !CENTRAL_HOST.test(baseVal.trim()) ? 'Use your Central API gateway, e.g. https://us1.api.central.arubanetworks.com (Central: Menu > API Gateway).' : null);
  const orgErr = mist && !UUID.test(orgVal.trim()) ? 'The org ID is a UUID (Mist: Organization > Settings).' : null;
  const credSet = d?.credentials.set === true;
  // Central replaces both values together; Mist's token alone
  const credErr = mist ? (!credSet && !s1.trim() ? 'Required.' : null) : ((!credSet || s1.trim() || s2.trim()) && !(s1.trim() && s2.trim()) ? 'Enter both the client ID and the client secret.' : null);
  const invalid = !!(baseErr || orgErr || credErr);
  const save = async () => {
    if (invalid || busy) return;
    setBusy(true);
    setError(null);
    setTested(null);
    try {
      // keep config keys the runner uses (plain values only; masked secret-looking ones are never re-sent)
      const keep = Object.fromEntries(Object.entries(d?.config ?? {}).filter(([, v]) => typeof v !== 'object' || v === null));
      const config = mist ? { ...keep, api_base: baseVal.trim(), org_id: orgVal.trim().toLowerCase() } : { ...keep, api_base: baseVal.trim().replace(/\/+$/, '') };
      const credentials = mist ? (s1.trim() ? { token: s1.trim() } : undefined) : (s1.trim() ? { client_id: s1.trim(), client_secret: s2.trim() } : undefined);
      await mutate('PUT', ep.integration(kind), { config, ...(credentials ? { credentials } : {}) });
      setS1('');
      setS2('');
      const t = await mutate<IntegrationTestResult>('POST', ep.integrationTest(kind));
      setTested(t);
      notify(t.ok ? 'ok' : 'error', t.ok ? `${mist ? 'Mist' : 'Central'} connected: ${t.detail}` : `Saved, but the test failed: ${t.detail}`);
      if (t.ok) onClose();
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog title={mist ? 'Connect Juniper Mist' : 'Connect HPE Aruba Networking Central'} onClose={onClose}>
      {res.loading ? <SkeletonBlock rows={3} label="Loading connector" /> : (
        <div class="dialog-body">
          <p class="dim">
            The manager only reads device status. Use a <strong>read-only</strong> credential:
            {mist ? ' an org API token for an Observer (read-only) admin.' : ' a New Central API client (HPE GreenLake: Manage workspace > Personal API clients) with a read-only role.'}
            {' '}Credentials are stored encrypted and never shown again.{mist ? ' The runner uses the same Mist connector.' : ''}
          </p>
          <div class="form-grid">
            <TextField label={mist ? 'API URL' : 'API gateway URL'} value={baseVal} onInput={setBase} type="url" error={base !== null || d?.config.api_base ? baseErr : null}
              placeholder={mist ? 'https://api.mist.com' : 'https://us1.api.central.arubanetworks.com'} hint={mist ? 'Your Mist cloud, e.g. https://api.mist.com or https://api.eu.mist.com' : undefined} />
            {mist ? <TextField label="Org ID" value={orgVal} onInput={setOrg} error={org !== null ? orgErr : null} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" /> : null}
            <TextField label={mist ? 'API token' : 'Client ID'} value={s1} onInput={setS1} type={mist ? 'password' : 'text'} autoComplete={mist ? 'new-password' : 'off'}
              hint={credSet ? `Stored ${secretSummary(d?.credentials)}. Leave empty to keep it.` : undefined} />
            {!mist ? <TextField label="Client secret" value={s2} onInput={setS2} type="password" autoComplete="new-password" error={s1.trim() || s2.trim() ? credErr : null} /> : null}
          </div>
          {tested && !tested.ok ? <p class="form-error" role="alert">Test: {tested.detail}</p> : null}
          <FormError error={error} />
        </div>
      )}
      <div class="dialog-actions">
        <Button onClick={onClose}>{tested && !tested.ok ? 'Close' : 'Cancel'}</Button>
        <Button variant="primary" disabled={invalid || busy || res.loading} onClick={() => void save()}>{busy ? 'Saving and testing…' : 'Save and test'}</Button>
      </div>
    </Dialog>
  );
}

export function OpsPage({ me }: { me: Me | undefined }): JSX.Element {
  const now = useNow();
  const board = useResource<OpsDevices>(ep.opsDevices);
  const [setup, setSetup] = useState<OpsKind | null>(null);
  const list = board.data?.sources ?? [];
  return (
    <>
      <PageHeader title="Ops: device status" sub={`Juniper Mist and HPE Aruba Networking Central, read-only. The manager polls each platform at most every ${board.data?.ttl_s ?? 60} s; this page refreshes every 30 s.`} />
      {board.loading ? <SkeletonBlock rows={3} label="Loading device status" /> : board.error && !board.data ? (
        <ErrorBanner what="Could not load device status." message={board.error.message} onRetry={board.refresh} />
      ) : (
        <>
          <Totals list={list} />
          <div class="ops-grid">
            {list.map((s) => <Card key={s.kind} s={s} me={me} now={now} onSetup={() => setSetup(s.kind)} />)}
          </div>
          {board.data ? <p class="kpi-asof"><AsOf ts={board.data.as_of} now={now} label="Board as of" /></p> : null}
        </>
      )}
      {setup ? <SetupDialog kind={setup} onClose={() => { setSetup(null); board.refresh(); }} /> : null}
    </>
  );
}
