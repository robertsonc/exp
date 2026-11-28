// Component editors (05-manager.md section 10): probe, collector and dashboard. Each edits a copy of the component's
// intent, validates it as the admin types, and saves with PATCH components/{id} (a JSON body). Nothing secret is ever
// shown or sent from here: tokens and passwords have their own flows below.
import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { Component, DashboardTls, DashboardUser, Host, Me, NocToken, NocTokenCreated, Overview, Page } from '../api/types';
import { mutate, useNow, useResource } from '../data/hooks';
import { Badge, Button, ConfirmDialog, CopyField, Dialog, EmptyState, ErrorBanner, Panel, SkeletonBlock } from '../components/atoms';
import { CheckField, Fieldset, FormError, SelectField, TextArea, TextField, failText } from '../components/forms';
import { canAdmin } from '../components/Issues';
import { OpenDashboardButton } from '../components/OpenDashboard';
import { notify } from '../components/Toasts';
import { DASH, formatAbsolute } from '../lib/format';
import {
  applyCollectorForm, applyDashboardForm, applyProbeForm, collectorFormFrom, dashboardFormFrom, probeFormFrom, sameConfig,
  type AppRow, type Cfg, type CollectorForm, type DashboardForm, type LabelRow, type PeerRow, type ProbeForm, PROBE_M4_NOTE, WIFI_JOIN_NOTE, draftsFromPorts,
} from '../lib/intent';
import { PortPicker } from '../components/PortPicker';
import { nocUrl } from '../lib/sso';
import { MAX_CERT_PEM, MAX_KEY_PEM, certExpiry, fingerprintPending, tlsPemProblems } from '../lib/tls';
import { applyRunnerForm, runnerFormFrom, runnerProblems, type RunnerForm } from '../lib/runner';
import { MIN_PASSWORD_CHARS, hashPassword, passwordProblem } from '../lib/pbkdf2';
import { RE } from '../lib/validate';
import { safeHttpsUrl } from '../lib/redact';

function ReadOnlyNote({ me }: { me: Me | undefined }): JSX.Element | null {
  return canAdmin(me) ? null : <p class="banner banner-warn" role="status">Your role does not allow changes. Editing needs the admin role.</p>;
}

function SaveBar({ dirty, problems, busy, error, onSave, onReset, allowed }: { dirty: boolean; problems: number; busy: boolean; error: string | null; onSave: () => void; onReset: () => void; allowed: boolean }): JSX.Element {
  return (
    <div class="savebar">
      <FormError error={error} />
      {problems > 0 ? <span class="field-error" role="status">{problems} field{problems === 1 ? '' : 's'} need attention.</span> : null}
      <Button onClick={onReset} disabled={!dirty || busy}>Discard changes</Button>
      <Button variant="primary" onClick={onSave} disabled={!dirty || problems > 0 || busy || !allowed}>{busy ? 'Saving…' : 'Save configuration'}</Button>
    </div>
  );
}

function useSaver(comp: Component): { busy: boolean; error: string | null; save: (config: Cfg) => Promise<void> } {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const save = async (config: Cfg) => {
    setBusy(true);
    setError(null);
    try {
      const r = await mutate<{ desired_version?: number }>('PATCH', ep.component(comp.component_id), { config });
      notify('ok', `Saved ${comp.id}. The host applies it on its next poll${r?.desired_version != null ? ` (desired config v${r.desired_version})` : ''}.`);
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, save };
}

const patchAt = <T,>(list: T[], i: number, p: Partial<T>): T[] => list.map((x, j) => (j === i ? { ...x, ...p } : x));

// ---- probe --------------------------------------------------------------------------------------------------------

function TestHead({ title, on, onChange, interval, onInterval, error, disabled }: { title: string; on: boolean; onChange: (v: boolean) => void; interval: string; onInterval: (v: string) => void; error?: string | null; disabled?: boolean }): JSX.Element {
  return (
    <div class="test-head">
      <CheckField label={`${title} test`} checked={on} onChange={onChange} disabled={disabled} />
      {on ? <TextField label={`${title} interval (s)`} value={interval} onInput={onInterval} type="number" inputMode="numeric" error={error ?? null} disabled={disabled} /> : null}
    </div>
  );
}

export function ProbeEditor({ comp, me }: { comp: Component; me: Me | undefined }): JSX.Element {
  const [f, setF] = useState<ProbeForm>(() => probeFormFrom(comp.config));
  const { busy, error, save } = useSaver(comp);
  const res = applyProbeForm(comp.config, f);
  const dirty = !sameConfig(res.config, comp.config);
  const dirtyReal = dirty;
  const p = res.problems;
  const allowed = canAdmin(me);
  const set = (patch: Partial<ProbeForm>) => setF((cur) => ({ ...cur, ...patch }));
  const apps = f.app.targets;
  const peers = f.path.peers;
  return (
    <form class="editor" onSubmit={(e) => { e.preventDefault(); if (allowed && dirtyReal && !Object.keys(p).length) void save(res.config); }} aria-label={`Edit probe ${comp.id}`} noValidate>
      <ReadOnlyNote me={me} />
      <Panel title="Heartbeat" id="pe-hb">
        <p class="dim">Fast checks that run on every client port: gateway, DHCP lease, DNS and reachability.</p>
        <div class="form-grid">
          <TextField label="Interval (seconds)" value={f.hbInterval} onInput={(v) => set({ hbInterval: v })} type="number" inputMode="numeric" error={p['hbInterval']} hint="5 to 60" disabled={!allowed} />
          <TextField label="Alternate resolver" value={f.altResolver} onInput={(v) => set({ altResolver: v })} error={p['altResolver']} hint="Compared against the lease's DNS server." disabled={!allowed} />
          <TextField label="Traceroute target" value={f.traceTarget} onInput={(v) => set({ traceTarget: v })} error={p['traceTarget']} hint="Leave empty to skip the path trace." disabled={!allowed} />
        </div>
        <div class="check-row">
          <CheckField label="Gateway check" checked={f.hbGateway} onChange={(v) => set({ hbGateway: v })} disabled={!allowed} />
          <CheckField label="DHCP check" checked={f.hbDhcp} onChange={(v) => set({ hbDhcp: v })} disabled={!allowed} />
          <CheckField label="DNS check" checked={f.hbDns} onChange={(v) => set({ hbDns: v })} disabled={!allowed} />
        </div>
        <div class="form-grid">
          <TextArea label="Ping targets" value={f.ping} onInput={(v) => set({ ping: v })} error={p['ping']} hint="Hosts or IPv4 addresses, one per line (at most 16)." disabled={!allowed} />
          <TextArea label="Heartbeat DNS names" value={f.dnsNames} onInput={(v) => set({ dnsNames: v })} error={p['dnsNames']} hint="Names resolved on every beat (at most 32)." disabled={!allowed} />
        </div>
      </Panel>

      <Panel title="Tests and intervals" id="pe-tests">
        <p class="dim">Slower, deeper tests. Each runs on its own interval (10 s to 24 h); switch a test off to stop it.</p>
        <Fieldset legend="DHCP">
          <TestHead title="DHCP" on={f.dhcp.on} onChange={(on) => set({ dhcp: { ...f.dhcp, on } })} interval={f.dhcp.interval} onInterval={(interval) => set({ dhcp: { ...f.dhcp, interval } })} error={p['dhcpInterval']} disabled={!allowed} />
        </Fieldset>
        <Fieldset legend="DNS">
          <TestHead title="DNS" on={f.dns.on} onChange={(on) => set({ dns: { ...f.dns, on } })} interval={f.dns.interval} onInterval={(interval) => set({ dns: { ...f.dns, interval } })} error={p['dnsInterval']} disabled={!allowed} />
          {f.dns.on ? <TextArea label="DNS test names" value={f.dns.names} onInput={(names) => set({ dns: { ...f.dns, names } })} error={p['dnsTestNames']} hint="One name per line (at most 64)." disabled={!allowed} /> : null}
        </Fieldset>
        <Fieldset legend="Applications" hint="Each target is fetched over HTTP(S). Apdex T is the threshold: satisfied up to T, tolerating up to 4 T, frustrated beyond.">
          <TestHead title="App" on={f.app.on} onChange={(on) => set({ app: { ...f.app, on } })} interval={f.app.interval} onInterval={(interval) => set({ app: { ...f.app, interval } })} error={p['appInterval']} disabled={!allowed} />
          {f.app.on ? (
            <>
              {p['appTargets'] ? <p class="field-error" role="alert">{p['appTargets']}</p> : null}
              {apps.map((r: AppRow, i) => (
                <div key={i} class="rowbox" role="group" aria-label={`App target ${i + 1}`}>
                  <div class="form-grid form-grid-3">
                    <TextField label="App name" value={r.app} onInput={(app) => set({ app: { ...f.app, targets: patchAt(apps, i, { app }) } })} disabled={!allowed} />
                    <TextField label="URL" value={r.url} onInput={(url) => set({ app: { ...f.app, targets: patchAt(apps, i, { url }) } })} type="url" disabled={!allowed} />
                    <TextField label="Apdex T (ms)" value={r.apdex} onInput={(apdex) => set({ app: { ...f.app, targets: patchAt(apps, i, { apdex }) } })} type="number" inputMode="numeric" disabled={!allowed} />
                  </div>
                  {p[`app${i}`] ? <p class="field-error" role="alert">{p[`app${i}`]}</p> : null}
                  <Button small disabled={!allowed} onClick={() => set({ app: { ...f.app, targets: apps.filter((_, j) => j !== i) } })} aria-label={`Remove app target ${r.app || i + 1}`}>Remove</Button>
                </div>
              ))}
              <Button small disabled={!allowed || apps.length >= 64} onClick={() => set({ app: { ...f.app, targets: [...apps, { app: '', url: 'https://', apdex: '500' }] } })}>Add app target</Button>
            </>
          ) : null}
        </Fieldset>
        <Fieldset legend="Throughput">
          <p class="dim" data-testid="m4-throughput">{PROBE_M4_NOTE}</p>
          <TestHead title="Throughput" on={f.throughput.on} onChange={(on) => set({ throughput: { ...f.throughput, on } })} interval={f.throughput.interval} onInterval={(interval) => set({ throughput: { ...f.throughput, interval } })} error={p['throughputInterval']} disabled={!allowed || !f.throughput.on} />
          {f.throughput.on ? (
            <div class="check-row">
              <CheckField label="Cloudflare" checked={f.throughput.cloudflare} onChange={(cloudflare) => set({ throughput: { ...f.throughput, cloudflare } })} disabled={!allowed} />
              <CheckField label="iperf3 (collector)" checked={f.throughput.iperf3} onChange={(iperf3) => set({ throughput: { ...f.throughput, iperf3 } })} disabled={!allowed} />
              {p['throughputProviders'] ? <p class="field-error" role="alert">{p['throughputProviders']}</p> : null}
            </div>
          ) : null}
        </Fieldset>
        <Fieldset legend="Path peers" hint="Another probe's target port, measured for loss, jitter and delay with a short UDP/TCP stream.">
          <p class="dim" data-testid="m4-path">{PROBE_M4_NOTE}</p>
          <TestHead title="Path" on={f.path.on} onChange={(on) => set({ path: { ...f.path, on } })} interval={f.path.interval} onInterval={(interval) => set({ path: { ...f.path, interval } })} error={p['pathInterval']} disabled={!allowed || !f.path.on} />
          {f.path.on ? (
            <>
              {p['pathPeers'] ? <p class="field-error" role="alert">{p['pathPeers']}</p> : null}
              {peers.map((r: PeerRow, i) => (
                <div key={i} class="rowbox" role="group" aria-label={`Path peer ${i + 1}`}>
                  <div class="form-grid form-grid-3">
                    <TextField label="Peer name" value={r.peer} onInput={(peer) => set({ path: { ...f.path, peers: patchAt(peers, i, { peer }) } })} disabled={!allowed} />
                    <TextField label="Address" value={r.address} onInput={(address) => set({ path: { ...f.path, peers: patchAt(peers, i, { address }) } })} disabled={!allowed} />
                    <TextField label="Port" value={r.port} onInput={(port) => set({ path: { ...f.path, peers: patchAt(peers, i, { port }) } })} type="number" inputMode="numeric" disabled={!allowed} />
                    <TextField label="Duration (s)" value={r.duration} onInput={(duration) => set({ path: { ...f.path, peers: patchAt(peers, i, { duration }) } })} type="number" inputMode="decimal" disabled={!allowed} />
                    <TextField label="Rate (kbit/s)" value={r.rate} onInput={(rate) => set({ path: { ...f.path, peers: patchAt(peers, i, { rate }) } })} type="number" inputMode="numeric" disabled={!allowed} />
                  </div>
                  <div class="check-row">
                    <CheckField label="UDP" checked={r.udp} onChange={(udp) => set({ path: { ...f.path, peers: patchAt(peers, i, { udp }) } })} disabled={!allowed} />
                    <CheckField label="TCP" checked={r.tcp} onChange={(tcp) => set({ path: { ...f.path, peers: patchAt(peers, i, { tcp }) } })} disabled={!allowed} />
                  </div>
                  {p[`peer${i}`] ? <p class="field-error" role="alert">{p[`peer${i}`]}</p> : null}
                  <Button small disabled={!allowed} onClick={() => set({ path: { ...f.path, peers: peers.filter((_, j) => j !== i) } })} aria-label={`Remove path peer ${r.peer || i + 1}`}>Remove</Button>
                </div>
              ))}
              <Button small disabled={!allowed || peers.length >= 16} onClick={() => set({ path: { ...f.path, peers: [...peers, { peer: '', address: '', port: '8862', udp: true, tcp: true, duration: '10', rate: '256' }] } })}>Add path peer</Button>
            </>
          ) : null}
        </Fieldset>
        <Fieldset legend="Wi-Fi join test">
          <p class="dim" data-testid="wifi-join-note">{WIFI_JOIN_NOTE}</p>
          <TestHead title="Wi-Fi join" on={f.wifi.on} onChange={(on) => set({ wifi: { ...f.wifi, on } })} interval={f.wifi.interval} onInterval={(interval) => set({ wifi: { ...f.wifi, interval } })} error={p['wifiInterval']} disabled={!allowed} />
        </Fieldset>
      </Panel>

      <Panel title="Labels" id="pe-labels">
        <p class="dim">Low-cardinality tags added to every measurement from this probe (for example <code>area</code> = <code>keynote</code>). At most 20.</p>
        {p['labels'] ? <p class="field-error" role="alert">{p['labels']}</p> : null}
        {f.labels.map((l: LabelRow, i) => (
          <div key={i} class="rowbox" role="group" aria-label={`Label ${i + 1}`}>
            <div class="form-grid">
              <TextField label="Name" value={l.key} onInput={(key) => set({ labels: patchAt(f.labels, i, { key }) })} disabled={!allowed} />
              <TextField label="Value" value={l.value} onInput={(value) => set({ labels: patchAt(f.labels, i, { value }) })} disabled={!allowed} />
            </div>
            {p[`label${i}`] ? <p class="field-error" role="alert">{p[`label${i}`]}</p> : null}
            <Button small disabled={!allowed} onClick={() => set({ labels: f.labels.filter((_, j) => j !== i) })} aria-label={`Remove label ${l.key || i + 1}`}>Remove</Button>
          </div>
        ))}
        <Button small disabled={!allowed || f.labels.length >= 20} onClick={() => set({ labels: [...f.labels, { key: '', value: '' }] })}>Add label</Button>
      </Panel>
      <SaveBar dirty={dirty} problems={Object.keys(p).length} busy={busy} error={error} allowed={allowed} onSave={() => void save(res.config)} onReset={() => setF(probeFormFrom(comp.config))} />
    </form>
  );
}

// ---- collector ----------------------------------------------------------------------------------------------------

/** Test ports after enrolment (the wizard's step 3 picker, prefilled with what the probe has now). */
export function ProbePortsPanel({ comp, host, me }: { comp: Component; host: Host | undefined; me: Me | undefined }): JSX.Element {
  const allowed = canAdmin(me);
  const cfg = (comp.config ?? {}) as Cfg;
  return (
    <Panel title="Test ports" id="cp-ports">
      <p class="dim">Which interfaces this probe tests from. Saving replaces the probe's port list; the host applies it on its next poll.</p>
      {host ? (
        <PortPicker key={`${comp.component_id}:${comp.updated_at}`} hostName={host.name} ifaces={host.facts?.interfaces ?? []} ownProbe={comp.id}
          initial={draftsFromPorts(cfg['ports'])} applyLabel="Save ports" allowed={allowed}
          onApply={async (ports) => {
            const r = await mutate<{ desired_version?: number | null }>('PUT', ep.ports(comp.component_id), { ports });
            notify('ok', `Saved ${ports.length} port${ports.length === 1 ? '' : 's'} for ${comp.id}${r?.desired_version != null ? ` (desired config v${r.desired_version})` : ''}.`);
          }} />
      ) : <p class="dim">Loading the host's interfaces…</p>}
    </Panel>
  );
}

export function CollectorEditor({ comp, me }: { comp: Component; me: Me | undefined }): JSX.Element {
  const [f, setF] = useState<CollectorForm>(() => collectorFormFrom(comp.config));
  const { busy, error, save } = useSaver(comp);
  const res = applyCollectorForm(comp.config, f);
  const p = res.problems;
  const dirty = !sameConfig(res.config, comp.config);
  const allowed = canAdmin(me);
  const set = (patch: Partial<CollectorForm>) => setF((cur) => ({ ...cur, ...patch }));
  return (
    <form class="editor" onSubmit={(e) => { e.preventDefault(); if (allowed && dirty && !Object.keys(p).length) void save(res.config); }} aria-label={`Edit collector ${comp.id}`} noValidate>
      <ReadOnlyNote me={me} />
      <Panel title="Retention" id="ce-ret">
        <p class="dim">How long this collector keeps data. Shorter retention saves disk; the days-to-full projection on the status tab follows it.</p>
        <div class="form-grid">
          <TextField label="Metrics (days)" value={f.metricsDays} onInput={(v) => set({ metricsDays: v })} type="number" inputMode="numeric" error={p['metricsDays']} disabled={!allowed} />
          <TextField label="Records (days)" value={f.recordsDays} onInput={(v) => set({ recordsDays: v })} type="number" inputMode="numeric" error={p['recordsDays']} disabled={!allowed} />
        </div>
      </Panel>
      <Panel title="Alerts" id="ce-alerts">
        <p class="dim">Experience alerts this collector raises. Webhook destinations are set per site on the site page.</p>
        <CheckField label="Alerts enabled" checked={f.alertsOn} onChange={(v) => set({ alertsOn: v })} disabled={!allowed} />
        <div class="form-grid">
          <TextField label="Board URL" value={f.boardUrl} onInput={(v) => set({ boardUrl: v })} type="url" error={p['boardUrl']} hint="Linked from alert messages. Empty uses the dashboard's address." disabled={!allowed} />
          <TextField label="Time zone" value={f.timezone} onInput={(v) => set({ timezone: v })} error={p['timezone']} hint="IANA name, for example America/Chicago." disabled={!allowed} />
          <SelectField label="Voice" value={f.voice} onChange={(v) => set({ voice: v === 'plain' ? 'plain' : 'sysadmin' })} disabled={!allowed} options={[{ value: 'sysadmin', label: 'Sysadmin (technical)' }, { value: 'plain', label: 'Plain language' }]} />
        </div>
        <div class="form-grid form-grid-4">
          <TextField label="Hold down (s)" value={f.holdDown} onInput={(v) => set({ holdDown: v })} type="number" inputMode="numeric" error={p['holdDown']} hint="Condition must last this long to alert." disabled={!allowed} />
          <TextField label="Hold back (s)" value={f.holdBack} onInput={(v) => set({ holdBack: v })} type="number" inputMode="numeric" error={p['holdBack']} hint="Minimum time between messages." disabled={!allowed} />
          <TextField label="Reopen window (s)" value={f.reopen} onInput={(v) => set({ reopen: v })} type="number" inputMode="numeric" error={p['reopen']} hint="A relapse inside it reopens the incident." disabled={!allowed} />
          <TextField label="Calm period (s)" value={f.calm} onInput={(v) => set({ calm: v })} type="number" inputMode="numeric" error={p['calm']} hint="Quiet time before 'all clear'." disabled={!allowed} />
        </div>
      </Panel>
      <SaveBar dirty={dirty} problems={Object.keys(p).length} busy={busy} error={error} allowed={allowed} onSave={() => void save(res.config)} onReset={() => setF(collectorFormFrom(comp.config))} />
    </form>
  );
}

// ---- dashboard ----------------------------------------------------------------------------------------------------

function CollectorPicker({ selected, onChange, disabled }: { selected: string[]; onChange: (ids: string[]) => void; disabled: boolean }): JSX.Element {
  const ov = useResource<Overview>(ep.overview);
  const cols = (ov.data?.hosts ?? []).flatMap((h) => h.components.filter((c) => c.type === 'collector').map((c) => ({ id: c.id, host: h.name, site: h.site })));
  const known = new Set(cols.map((c) => c.id));
  const stale = selected.filter((id) => !known.has(id));
  if (ov.loading) return <SkeletonBlock rows={2} label="Loading collectors" />;
  return (
    <fieldset class="fieldset">
      <legend>Collectors this dashboard federates</legend>
      <p class="hint">The manager fills in each collector's address, certificate pin and access token. With none selected the dashboard uses every collector of its sites.</p>
      {cols.length === 0 ? <p class="dim">No collectors exist yet.</p> : null}
      {cols.map((c) => (
        <CheckField key={c.id} label={`${c.id} (${c.host}, ${c.site})`} checked={selected.includes(c.id)} disabled={disabled}
          onChange={(on) => onChange(on ? [...selected.filter((x) => x !== c.id), c.id] : selected.filter((x) => x !== c.id))} />
      ))}
      {stale.map((id) => <p key={id} class="field-error" role="status">{id} is selected but no longer exists.</p>)}
    </fieldset>
  );
}

function UsersPanel({ comp, allowed }: { comp: Component; allowed: boolean }): JSX.Element {
  const users = useResource<Page<DashboardUser>>(ep.dashUsers(comp.id), { paged: true });
  const [username, setUsername] = useState('');
  const [role, setRole] = useState<DashboardUser['role']>('viewer');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [del, setDel] = useState<DashboardUser | null>(null);
  const [delBusy, setDelBusy] = useState(false);
  const [delError, setDelError] = useState<string | null>(null);
  const userProblem = username && !RE.username.test(username) ? 'Letters, digits, dot, dash and underscore only (at most 64).' : null;
  const pwProblem = pw ? passwordProblem(pw) : null;
  const mismatch = pw2 && pw !== pw2 ? 'The passwords do not match.' : null;
  const ready = username !== '' && !userProblem && pw !== '' && !pwProblem && pw === pw2;

  const add = async (e: Event) => {
    e.preventDefault();
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      // Hashed here, in the browser: the plaintext password never leaves this page.
      const hash = await hashPassword(pw);
      await mutate('POST', ep.dashUsers(comp.id), { username, role, hash });
      notify('ok', `Added dashboard user ${username}. They can sign in once the dashboard has applied the change.`);
      setUsername('');
      setPw('');
      setPw2('');
    } catch (err) {
      setError(failText(err));
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!del) return;
    setDelBusy(true);
    setDelError(null);
    try {
      await mutate('DELETE', ep.dashUser(comp.id, del.usr_id));
      notify('ok', `Removed dashboard user ${del.username}`);
      setDel(null);
    } catch (e) {
      setDelError(failText(e));
    } finally {
      setDelBusy(false);
    }
  };
  return (
    <Panel title="Local users" id="du">
      <p class="dim">People who sign in to this dashboard with a password instead of the manager's single sign-on. The password is hashed in your browser (PBKDF2-SHA256, 600,000 rounds); the manager only ever sees the hash.</p>
      {users.loading ? <SkeletonBlock rows={2} label="Loading users" /> : users.error && !users.data ? <ErrorBanner what="Could not load users." message={users.error.message} onRetry={users.refresh} /> : (users.data?.items.length ?? 0) === 0 ? <EmptyState title="No local users">Add one below, or rely on single sign-on from the manager.</EmptyState> : (
        <div class="table-scroll">
          <table class="plain">
            <caption class="sr-only">Dashboard local users</caption>
            <thead><tr><th scope="col">Username</th><th scope="col">Role</th><th scope="col">Created</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {users.data?.items.map((u) => (
                <tr key={u.usr_id}>
                  <th scope="row">{u.username}</th><td>{u.role}</td><td>{formatAbsolute(u.created_at)}</td>
                  <td><Button small disabled={!allowed} onClick={() => setDel(u)} aria-label={`Delete user ${u.username}`}>Delete</Button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <form onSubmit={(e) => void add(e)} aria-label="Add a local user" noValidate autocomplete="off">
        <h3 class="h3">Add a user</h3>
        <div class="form-grid form-grid-4">
          <TextField label="Username" value={username} onInput={setUsername} error={userProblem} disabled={!allowed} name="new-username" />
          <SelectField label="Role" value={role} onChange={(v) => setRole(v === 'admin' ? 'admin' : v === 'operator' ? 'operator' : 'viewer')} disabled={!allowed}
            options={[{ value: 'viewer', label: 'Viewer' }, { value: 'operator', label: 'Operator' }, { value: 'admin', label: 'Admin' }]} />
          <TextField label="Password" value={pw} onInput={setPw} type="password" autoComplete="new-password" error={pwProblem} hint={`At least ${MIN_PASSWORD_CHARS} characters.`} disabled={!allowed} name="new-password" />
          <TextField label="Repeat password" value={pw2} onInput={setPw2} type="password" autoComplete="new-password" error={mismatch} disabled={!allowed} name="new-password-repeat" />
        </div>
        <FormError error={error} />
        <div class="dialog-actions"><Button type="submit" variant="primary" disabled={!ready || busy || !allowed}>{busy ? 'Hashing in your browser…' : 'Add user'}</Button></div>
      </form>
      {del ? (
        <ConfirmDialog title={`Delete ${del.username}?`} body={<p>{del.username} can no longer sign in to <strong>{comp.id}</strong>. Their open sessions end when the dashboard applies the change.</p>}
          confirmText="Delete user" typeName={del.username} busy={delBusy} error={delError} onConfirm={() => void remove()} onCancel={() => { setDel(null); setDelError(null); }} />
      ) : null}
    </Panel>
  );
}

function nocStatus(t: NocToken, now: number): string {
  if (t.revoked_at) return 'revoked';
  if (t.expires_at && Date.parse(t.expires_at) <= now) return 'expired';
  return 'active';
}

function NocPanel({ comp, allowed, dashUrl }: { comp: Component; allowed: boolean; dashUrl: string | null }): JSX.Element {
  const now = useNow(30000);
  const list = useResource<Page<NocToken>>(ep.nocTokens(comp.id), { paged: true });
  const [label, setLabel] = useState('');
  const [hours, setHours] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shown, setShown] = useState<NocTokenCreated | null>(null);
  const [revoke, setRevoke] = useState<NocToken | null>(null);
  const [revBusy, setRevBusy] = useState(false);
  const [revError, setRevError] = useState<string | null>(null);
  const hoursOk = hours === '' || (/^\d+$/.test(hours) && Number(hours) >= 1 && Number(hours) <= 8760);
  const labelOk = label.trim().length > 0 && label.length <= 128;

  const create = async (e: Event) => {
    e.preventDefault();
    if (!labelOk || !hoursOk || busy) return;
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = { label: label.trim() };
      if (hours !== '') body['expires_in_h'] = Number(hours);
      setShown(await mutate<NocTokenCreated>('POST', ep.nocTokens(comp.id), body));
      setLabel('');
      setHours('');
    } catch (err) {
      setError(failText(err));
    } finally {
      setBusy(false);
    }
  };
  const doRevoke = async () => {
    if (!revoke) return;
    setRevBusy(true);
    setRevError(null);
    try {
      await mutate('DELETE', ep.nocToken(comp.id, revoke.noc_id));
      notify('ok', `Revoked NOC token ${revoke.label}`);
      setRevoke(null);
    } catch (e) {
      setRevError(failText(e));
    } finally {
      setRevBusy(false);
    }
  };
  const url = shown ? nocUrl(dashUrl ?? shown.url ?? null, shown.token) : null;
  return (
    <Panel title="NOC tokens" id="nt">
      <p class="dim">A NOC token opens a read-only wall-display view at the dashboard's <code>/noc</code> address without signing in. The token is shown once, when it is created; only a hash is kept.</p>
      {list.loading ? <SkeletonBlock rows={2} label="Loading NOC tokens" /> : list.error && !list.data ? <ErrorBanner what="Could not load NOC tokens." message={list.error.message} onRetry={list.refresh} /> : (list.data?.items.length ?? 0) === 0 ? <EmptyState title="No NOC tokens" /> : (
        <div class="table-scroll">
          <table class="plain">
            <caption class="sr-only">NOC tokens</caption>
            <thead><tr><th scope="col">Label</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {list.data?.items.map((t) => {
                const st = nocStatus(t, now);
                return (
                  <tr key={t.noc_id}>
                    <th scope="row">{t.label}</th>
                    <td><Badge tone={st === 'active' ? 'ok' : 'neutral'}>{st}</Badge></td>
                    <td>{formatAbsolute(t.created_at)}</td>
                    <td>{t.expires_at ? formatAbsolute(t.expires_at) : 'never'}</td>
                    <td>{st === 'active' ? <Button small disabled={!allowed} onClick={() => setRevoke(t)} aria-label={`Revoke NOC token ${t.label}`}>Revoke</Button> : null}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <form onSubmit={(e) => void create(e)} aria-label="Create a NOC token" noValidate>
        <h3 class="h3">Create a NOC token</h3>
        <div class="form-grid">
          <TextField label="Label" value={label} onInput={setLabel} hint="Where it will be used, for example Hall B wall display." disabled={!allowed} maxLength={128} />
          <TextField label="Expires after (hours)" value={hours} onInput={setHours} type="number" inputMode="numeric" hint="Empty means it never expires. At most 8760." error={hoursOk ? null : 'Enter 1 to 8760 hours, or leave empty.'} disabled={!allowed} />
        </div>
        <FormError error={error} />
        <div class="dialog-actions"><Button type="submit" variant="primary" disabled={!labelOk || !hoursOk || busy || !allowed}>{busy ? 'Creating…' : 'Create NOC token'}</Button></div>
      </form>
      {shown ? (
        <Dialog title="Your new NOC token" onClose={() => setShown(null)} wide>
          <div class="banner banner-warn" role="status"><span>This is the only time the token is shown. Copy it now; closing this window discards it from the page.</span></div>
          {url ? (<><p>NOC address (open this on the wall display):</p><CopyField value={url} label="NOC URL" /></>) : <p class="hint">This dashboard has no address yet, so there is no NOC URL. Set the address above and the URL is <code>https://&lt;dashboard&gt;/noc#t=&lt;token&gt;</code>.</p>}
          <p>Token:</p>
          <CopyField value={shown.token} label="NOC token" />
          <div class="dialog-actions"><Button variant="primary" onClick={() => setShown(null)}>I have copied it</Button></div>
        </Dialog>
      ) : null}
      {revoke ? (
        <ConfirmDialog title={`Revoke ${revoke.label}?`} body={<p>Displays using this token lose access the next time the dashboard checks it. This cannot be undone.</p>}
          confirmText="Revoke token" busy={revBusy} error={revError} onConfirm={() => void doRevoke()} onCancel={() => { setRevoke(null); setRevError(null); }} />
      ) : null}
    </Panel>
  );
}

const PEM_FILE_MAX = 64 * 1024;

/** Chooses a PEM file and hands its text to `onText` (the text only ever goes into the textarea next to it). */
function PemFile({ label, onText, disabled }: { label: string; onText: (t: string) => void; disabled: boolean }): JSX.Element {
  const [err, setErr] = useState<string | null>(null);
  return (
    <div class="field">
      <label>{label}<input type="file" accept=".pem,.crt,.cer,.key,text/plain" disabled={disabled} onChange={(e) => {
        const input = e.currentTarget as HTMLInputElement;
        const file = input.files?.[0];
        input.value = '';
        if (!file) return;
        if (file.size > PEM_FILE_MAX) { setErr('That file is too large to be a certificate or key.'); return; }
        setErr(null);
        void file.text().then(onText, () => setErr('The file could not be read.'));
      }} /></label>
      {err ? <p class="hint" role="alert">{err}</p> : null}
    </div>
  );
}

function TlsPanel({ comp, allowed, reportedFp, dashUrl }: { comp: Component; allowed: boolean; reportedFp: string | null; dashUrl: string | null }): JSX.Element {
  const now = useNow(60000);
  const res = useResource<DashboardTls>(ep.dashTls(comp.id));
  const [mode, setMode] = useState<'self_signed' | 'provided'>('provided');
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const cur = res.data;
  const probs = tlsPemProblems(certPem, keyPem);
  const bad = !!(probs.cert || probs.key);
  const cert = cur?.cert ?? null;
  const exp = cert ? certExpiry(cert.not_after, now) : null;

  const put = async (body: Record<string, unknown>): Promise<boolean> => {
    setBusy(true);
    setError(null);
    try {
      await mutate<DashboardTls>('PUT', ep.dashTls(comp.id), body);
      // never keep the key (or the certificate text) in the page once it was accepted
      setCertPem('');
      setKeyPem('');
      setTouched(false);
      res.refresh();
      notify('ok', body['mode'] === 'provided' ? 'Certificate saved. The dashboard picks it up on its next sync.' : 'Switched to a self-signed certificate.');
      return true;
    } catch (e) {
      setError(failText(e));
      return false;
    } finally {
      setBusy(false);
    }
  };
  const save = (e: Event) => {
    e.preventDefault();
    setTouched(true);
    if (!allowed || busy) return;
    if (mode === 'self_signed') { setConfirm(true); return; }
    if (bad) return;
    void put({ mode: 'provided', cert_pem: certPem, key_pem: keyPem });
  };
  return (
    <Panel title="TLS" id="de-tls">
      <dl class="facts">
        <div><dt>Certificate fingerprint reported by the dashboard (SHA-256)</dt><dd class="mono" data-testid="tls-fp">{reportedFp ?? DASH}</dd></div>
        <div><dt>Reported address</dt><dd>{dashUrl ?? DASH}</dd></div>
        <div><dt>Certificate source</dt><dd data-testid="tls-mode">{res.loading ? 'Loading…' : cur?.mode === 'provided' ? 'Provided certificate' : 'Self-signed (generated on the host)'}</dd></div>
      </dl>
      {res.error && !cur ? <ErrorBanner what="Could not load the certificate state." message={res.error.message} onRetry={res.refresh} /> : null}
      {cur?.mode === 'provided' && cert ? (
        <>
          {exp?.state === 'expired' ? <div class="banner banner-fail" role="alert" data-testid="tls-expiry"><span>This certificate expired on {formatAbsolute(cert.not_after)}. Browsers will refuse the dashboard until a new one is uploaded.</span></div> : null}
          {exp?.state === 'soon' ? <div class="banner banner-warn" role="status" data-testid="tls-expiry"><span>This certificate expires in {exp.days} day{exp.days === 1 ? '' : 's'} ({formatAbsolute(cert.not_after)}). Upload a renewed one before then.</span></div> : null}
          {fingerprintPending(cert.sha256, reportedFp) ? <div class="banner banner-info" role="status"><span>The dashboard still reports a different fingerprint; it switches to this certificate on its next sync.</span></div> : null}
          <h3 class="h3">Stored certificate</h3>
          <dl class="facts" data-testid="tls-cert">
            <div><dt>Subject</dt><dd>{cert.subject}</dd></div>
            <div><dt>Issuer</dt><dd>{cert.issuer}</dd></div>
            <div><dt>Valid from</dt><dd>{formatAbsolute(cert.not_before)}</dd></div>
            <div><dt>Valid until</dt><dd>{formatAbsolute(cert.not_after)}</dd></div>
            <div><dt>Fingerprint (SHA-256)</dt><dd class="mono" data-testid="tls-provided-fp">{cert.sha256}</dd></div>
            <div><dt>Names (SAN)</dt><dd>{cert.san.length ? cert.san.join(', ') : DASH}</dd></div>
            <div><dt>Private key</dt><dd>Stored encrypted. It is never shown again.</dd></div>
          </dl>
        </>
      ) : null}
      <form onSubmit={save} aria-label="Dashboard certificate" noValidate>
        <h3 class="h3">Change the certificate</h3>
        <SelectField label="Certificate mode" value={mode} onChange={(v) => { setMode(v === 'self_signed' ? 'self_signed' : 'provided'); setTouched(false); setError(null); }} disabled={!allowed}
          options={[{ value: 'self_signed', label: 'Self-signed (generated on the host)' }, { value: 'provided', label: 'Provided certificate' }]}
          hint="Collectors and probes pin the dashboard's fingerprint, so a certificate change is announced here first." />
        {mode === 'provided' ? (
          <>
            <TextArea label="Certificate (PEM, leaf first, then any chain)" value={certPem} onInput={setCertPem} rows={6} wide disabled={!allowed} error={touched ? probs.cert : undefined} hint={`At most ${MAX_CERT_PEM / 1024} KiB.`} />
            <PemFile label="Or choose a certificate file" onText={setCertPem} disabled={!allowed} />
            <TextArea label="Private key (PEM, not passphrase-protected)" value={keyPem} onInput={setKeyPem} rows={6} wide disabled={!allowed} error={touched ? probs.key : undefined} hint={`Write-only: sent once over TLS, stored encrypted, never displayed again. At most ${MAX_KEY_PEM / 1024} KiB.`} />
            <PemFile label="Or choose a key file" onText={setKeyPem} disabled={!allowed} />
          </>
        ) : <p class="dim">The dashboard host generates its own self-signed certificate. Any stored provided certificate and key are deleted.</p>}
        <FormError error={error} />
        <div class="dialog-actions">
          <Button type="submit" variant="primary" disabled={!allowed || busy || (mode === 'self_signed' && cur?.mode !== 'provided')}>{busy ? 'Saving…' : mode === 'provided' ? 'Save certificate' : 'Switch to self-signed'}</Button>
        </div>
      </form>
      {confirm ? (
        <ConfirmDialog title="Switch to a self-signed certificate?" body={<p>The stored certificate and key are deleted and the dashboard generates its own certificate, which changes its fingerprint. Browsers that trusted the provided certificate will warn.</p>}
          confirmText="Switch to self-signed" busy={busy} error={error} onConfirm={() => void put({ mode: 'self_signed' }).then((ok) => { if (ok) setConfirm(false); })} onCancel={() => { setConfirm(false); setError(null); }} />
      ) : null}
    </Panel>
  );
}

export function DashboardEditor({ comp, me, tlsFingerprint, factsUrl }: { comp: Component; me: Me | undefined; tlsFingerprint: string | null; factsUrl: string | null }): JSX.Element {
  const [f, setF] = useState<DashboardForm>(() => dashboardFormFrom(comp.config));
  const { busy, error, save } = useSaver(comp);
  const res = applyDashboardForm(comp.config, f);
  const p = res.problems;
  const dirty = !sameConfig(res.config, comp.config);
  const allowed = canAdmin(me);
  const set = (patch: Partial<DashboardForm>) => setF((cur) => ({ ...cur, ...patch }));
  const dashUrl = safeHttpsUrl(factsUrl ?? comp.config['url']);
  return (
    <>
      <form class="editor" onSubmit={(e) => { e.preventDefault(); if (allowed && dirty && !Object.keys(p).length) void save(res.config); }} aria-label={`Edit dashboard ${comp.id}`} noValidate>
        <ReadOnlyNote me={me} />
        <Panel title="Dashboard" id="de-main" actions={<OpenDashboardButton dashId={comp.id} primary />}>
          <div class="form-grid">
            <TextField label="Title" value={f.title} onInput={(v) => set({ title: v })} error={p['title']} disabled={!allowed} maxLength={128} />
            <TextField label="Address operators use" value={f.url} onInput={(v) => set({ url: v })} type="url" error={p['url']} hint="Where people open the dashboard. Used for single sign-on and alert links." disabled={!allowed} />
            <TextField label="Session length (hours)" value={f.sessionHours} onInput={(v) => set({ sessionHours: v })} type="number" inputMode="numeric" error={p['sessionHours']} disabled={!allowed} />
          </div>
          <div class="check-row">
            <CheckField label="Allow local users" checked={f.localUsers} onChange={(v) => set({ localUsers: v })} disabled={!allowed} />
            <CheckField label="Allow NOC tokens" checked={f.nocTokens} onChange={(v) => set({ nocTokens: v })} disabled={!allowed} />
          </div>
          <CollectorPicker selected={f.collectorIds} onChange={(ids) => set({ collectorIds: ids })} disabled={!allowed} />
        </Panel>
        <SaveBar dirty={dirty} problems={Object.keys(p).length} busy={busy} error={error} allowed={allowed} onSave={() => void save(res.config)} onReset={() => setF(dashboardFormFrom(comp.config))} />
      </form>
      <TlsPanel comp={comp} allowed={allowed} reportedFp={tlsFingerprint} dashUrl={dashUrl} />
      <UsersPanel comp={comp} allowed={allowed} />
      <NocPanel comp={comp} allowed={allowed} dashUrl={dashUrl} />
    </>
  );
}

// ---- runner (M6 correlation sources) ----------------------------------------------------------------------------------

export function RunnerEditor({ comp, me }: { comp: Component; me: Me | undefined }): JSX.Element {
  const [f, setF] = useState<RunnerForm>(() => runnerFormFrom(comp.config));
  const { busy, error, save } = useSaver(comp);
  const p = runnerProblems(f);
  const config = applyRunnerForm(comp.config, f);
  const dirty = !sameConfig(config, comp.config);
  const allowed = canAdmin(me);
  const set = (patch: Partial<RunnerForm>) => setF((cur) => ({ ...cur, ...patch }));
  return (
    <form class="editor" onSubmit={(e) => { e.preventDefault(); if (allowed && dirty && !Object.keys(p).length) void save(config); }} aria-label={`Edit runner ${comp.id}`} noValidate>
      <ReadOnlyNote me={me} />
      <Panel title="Correlation" id="re-main">
        <p class="dim">After each speedtest the runner looks up the client's access point, flows and WAN path and attaches them as evidence. Connector addresses and credentials are the organisation-wide integrations; here you choose what the runner reads. HPE Aruba SSE has no API connector, but its logs can arrive by syslog.</p>
        <CheckField label="Correlate speedtests" checked={f.enabled} onChange={(v) => set({ enabled: v })} disabled={!allowed} />
        <Fieldset legend="Juniper Mist" hint="Which Mist sites to search, and how an access point maps to a zone (first matching rule wins; without a rule the zone stays at the subnet fallback).">
          <TextArea label="Mist site ids (one per line)" value={f.mistSites} onInput={(v) => set({ mistSites: v })} rows={2} error={p['mistSites']} disabled={!allowed} />
          {f.zoneMap.map((z, i) => (
            <div class="rowbox" key={i} role="group" aria-label={`Zone rule ${i + 1}`}>
              <div class="form-grid form-grid-3">
                <TextField label="Zone id" value={z.zone} onInput={(v) => set({ zoneMap: patchAt(f.zoneMap, i, { zone: v }) })} error={p[`zone-${i}`]} disabled={!allowed} />
                <TextField label="AP name starts with" value={z.prefix} onInput={(v) => set({ zoneMap: patchAt(f.zoneMap, i, { prefix: v }) })} error={p[`prefix-${i}`]} disabled={!allowed} />
                <TextField label="AP MAC addresses" value={z.macs} onInput={(v) => set({ zoneMap: patchAt(f.zoneMap, i, { macs: v }) })} error={p[`macs-${i}`]} disabled={!allowed} hint="Comma-separated, lower-case." />
              </div>
              <Button small disabled={!allowed} onClick={() => set({ zoneMap: f.zoneMap.filter((_, j) => j !== i) })} aria-label={`Remove zone rule ${i + 1}`}>Remove</Button>
            </div>
          ))}
          <Button small disabled={!allowed || f.zoneMap.length >= 256} onClick={() => set({ zoneMap: [...f.zoneMap, { zone: '', prefix: '', macs: '' }] })}>Add zone rule</Button>
        </Fieldset>
        <Fieldset legend="HPE EdgeConnect" hint="Appliances whose flows and WAN utilisation the runner reads.">
          {f.appliances.map((a, i) => (
            <div class="rowbox" key={i} role="group" aria-label={`Appliance ${i + 1}`}>
              <div class="form-grid">
                <TextField label="Appliance id (nePk)" value={a.nePk} onInput={(v) => set({ appliances: patchAt(f.appliances, i, { nePk: v }) })} error={p[`ne-${i}`]} disabled={!allowed} />
                <TextField label="WAN interfaces" value={a.wan} onInput={(v) => set({ appliances: patchAt(f.appliances, i, { wan: v }) })} error={p[`wan-${i}`]} disabled={!allowed} hint="Comma-separated." />
              </div>
              <Button small disabled={!allowed} onClick={() => set({ appliances: f.appliances.filter((_, j) => j !== i) })} aria-label={`Remove appliance ${i + 1}`}>Remove</Button>
            </div>
          ))}
          <Button small disabled={!allowed || f.appliances.length >= 8} onClick={() => set({ appliances: [...f.appliances, { nePk: '', wan: '' }] })}>Add appliance</Button>
          <CheckField label="Poll WAN utilisation (pauses the internet leg while the uplink is busy)" checked={f.wanUtil} onChange={(v) => set({ wanUtil: v })} disabled={!allowed} />
        </Fieldset>
        <Fieldset legend="Syslog" hint="The runner listens on UDP/TCP 5514 and TLS 6514 and keeps lines for the last hour only.">
          <div class="form-grid">
            <TextField label="Accept from (CIDR)" value={f.syslogAllow} onInput={(v) => set({ syslogAllow: v })} error={p['syslogAllow']} disabled={!allowed} hint="Comma-separated. Empty accepts nothing." />
            <TextField label="Keep lines (minutes)" value={f.ringMinutes} onInput={(v) => set({ ringMinutes: v })} type="number" inputMode="numeric" placeholder="60" error={p['ringMinutes']} disabled={!allowed} />
          </div>
        </Fieldset>
      </Panel>
      <SaveBar dirty={dirty} problems={Object.keys(p).length} busy={busy} error={error} allowed={allowed} onSave={() => void save(config)} onReset={() => setF(runnerFormFrom(comp.config))} />
    </form>
  );
}
