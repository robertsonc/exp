// Add-host wizard (05-manager.md section 10, 11-manager-ui.md section 4.7):
//   1 name, site and shapes -> 2 the one-liner with a copy button, a 1-hour countdown and live "waiting for the host" ->
//   3 the host's facts and, for a probe, the interface picker -> 4 apply, then progress until every component is healthy.
// The wizard survives a reload: the host id and the step live in the URL, and the one-liner (shown once) can be reissued.
import type { JSX } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { Component, EnrolToken, Host, HostCreated, Me, Page, Shape, Site } from '../api/types';
import { mutate, useNow, useResource } from '../data/hooks';
import { Badge, Button, CopyField, Countdown, ErrorBanner, Panel, ShapeBadges, SkeletonBlock, StatusPill, healthPill } from '../components/atoms';
import { CheckField, FormError, SelectField, TextField, failText } from '../components/forms';
import { canAdmin } from '../components/Issues';
import { Link } from '../components/viz';
import { PageHeader } from './common';
import { DASH, formatMiB, formatVersion } from '../lib/format';
import { defaultComponentId, defaultIntent } from '../lib/intent';
import { PortPicker } from '../components/PortPicker';
import { slugProblem, slugify } from '../lib/validate';
import { navigate, useLocation } from '../router';

const SHAPES: { id: Shape; label: string; hint: string }[] = [
  { id: 'probe', label: 'Probe', hint: 'Measures the network as a client and serves test targets.' },
  { id: 'collector', label: 'Collector', hint: 'Receives probe data and evaluates alerts.' },
  { id: 'dashboard', label: 'Dashboard', hint: 'The live experience board and NOC view.' },
  { id: 'runner', label: 'Runner', hint: 'Correlates speedtest results with Wi-Fi, WAN and syslog evidence (drills arrive later).' },
  { id: 'speedtest', label: 'Speedtest', hint: 'The branded speedtest page. One box at the venue core or data centre, together with a collector and a runner.' },
];

type StepId = 'name' | 'enrol' | 'interfaces' | 'apply';
const STEPS: { id: StepId; label: string }[] = [
  { id: 'name', label: 'Name and shapes' }, { id: 'enrol', label: 'Enrol the host' }, { id: 'interfaces', label: 'Facts and interfaces' }, { id: 'apply', label: 'Apply' },
];

function Stepper({ step }: { step: StepId }): JSX.Element {
  const at = STEPS.findIndex((s) => s.id === step);
  return (
    <ol class="steps" aria-label="Add host progress">
      {STEPS.map((s, i) => (
        <li key={s.id} class={`step${i === at ? ' step-now' : i < at ? ' step-done' : ''}`} aria-current={i === at ? 'step' : undefined}>
          <span class="step-n" aria-hidden="true">{i < at ? '✓' : i + 1}</span>
          <span class="step-l">{s.label}</span>
        </li>
      ))}
    </ol>
  );
}

// ---- step 1 -------------------------------------------------------------------------------------------------------

interface Created { hostId: string; shapes: Set<Shape> }

function NameStep({ onCreated, allowed }: { onCreated: (hostId: string, enrol: EnrolToken) => void; allowed: boolean }): JSX.Element {
  const sites = useResource<Page<Site>>(ep.sites, { paged: true });
  const [name, setName] = useState('');
  const [site, setSite] = useState('');
  const [shapes, setShapes] = useState<Shape[]>(['probe']);
  const [ids, setIds] = useState<Partial<Record<Shape, string>>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const created = useRef<Created | null>(null);
  const enrol = useRef<EnrolToken | null>(null);
  const siteList = sites.data?.items ?? [];
  const siteVal = site || siteList[0]?.site || '';
  const hostSlug = slugify(name);
  const idOf = (s: Shape): string => ids[s] ?? defaultComponentId(s, hostSlug);

  const nameProblem = name.trim().length === 0 ? 'Enter a host name.' : name.length > 128 ? 'At most 128 characters.' : null;
  const idProblems: Partial<Record<Shape, string | null>> = {};
  for (const s of shapes) idProblems[s] = slugProblem(idOf(s), `${s} id`);
  const valid = !nameProblem && siteVal !== '' && shapes.length > 0 && shapes.every((s) => !idProblems[s]);

  const toggle = (s: Shape, on: boolean) => setShapes((cur) => (on ? [...cur.filter((x) => x !== s), s] : cur.filter((x) => x !== s)));

  const submit = async (e: Event) => {
    e.preventDefault();
    if (!valid || busy) return;
    setBusy(true);
    setError(null);
    try {
      if (!created.current) {
        const r = await mutate<HostCreated>('POST', ep.hostCreate, { name: name.trim(), site: siteVal, shapes });
        created.current = { hostId: r.host.host_id, shapes: new Set() };
        enrol.current = r.enrol;
      }
      const c = created.current;
      // One component per shape, created now so the host's first desired state already contains them. A probe's ports
      // are assigned in step 3, once the host has reported its interfaces.
      for (const s of shapes) {
        if (c.shapes.has(s)) continue;
        await mutate<Component>('POST', ep.hostComponents(c.hostId), { type: s, id: idOf(s), config: defaultIntent(s, name.trim()) });
        c.shapes.add(s);
      }
      if (enrol.current) onCreated(c.hostId, enrol.current);
    } catch (err) {
      setError(`${failText(err)}${created.current ? ' The host was created; submit again to finish adding its components.' : ''}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} noValidate aria-label="Name and shapes">
      <Panel title="1. Name the host and choose what it runs" id="w1">
        {!allowed ? <p class="banner banner-warn" role="status">Your role does not allow adding hosts. It needs the admin role.</p> : null}
        <div class="form-grid">
          <TextField label="Host name" value={name} onInput={setName} hint="Shown in the fleet views; it need not match the machine's hostname." error={name && nameProblem ? nameProblem : null} maxLength={128} />
          <SelectField label="Site" value={siteVal} onChange={setSite} disabled={siteList.length === 0}
            options={siteList.length ? siteList.map((s) => ({ value: s.site, label: `${s.name} (${s.site})` })) : [{ value: '', label: sites.loading ? 'Loading sites…' : 'No sites yet' }]}
            hint={siteList.length === 0 && !sites.loading ? <>Create a site first on the <Link to="/sites">Sites page</Link>.</> : undefined} />
        </div>
        <fieldset class="fieldset">
          <legend>Shapes</legend>
          <p class="hint">What this host will run. A host can have several shapes.</p>
          <div class="shape-grid">
            {SHAPES.map((s) => (
              <div key={s.id} class="shape-opt">
                <CheckField label={s.label} hint={s.hint} checked={shapes.includes(s.id)} onChange={(on) => toggle(s.id, on)} />
                {shapes.includes(s.id) ? <TextField label={`${s.label} id`} value={idOf(s.id)} onInput={(v) => setIds((cur) => ({ ...cur, [s.id]: v }))} error={idProblems[s.id] ?? null} /> : null}
              </div>
            ))}
          </div>
          {shapes.length === 0 ? <p class="field-error" role="alert">Choose at least one shape.</p> : null}
        </fieldset>
        <FormError error={error} />
        <div class="dialog-actions"><Button type="submit" variant="primary" disabled={!valid || busy || !allowed}>{busy ? 'Creating…' : 'Create host and get the install command'}</Button></div>
      </Panel>
    </form>
  );
}

// ---- step 2 -------------------------------------------------------------------------------------------------------

function EnrolStep({ host, enrol, onNewToken }: { host: Host; enrol: EnrolToken | null; onNewToken: (t: EnrolToken) => void }): JSX.Element {
  const now = useNow();
  const hostRes = useResource<Host>(ep.host(host.host_id));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const t = setInterval(() => hostRes.refresh(), 3000);
    return () => clearInterval(t);
  }, [hostRes.refresh]);
  const expired = enrol ? Date.parse(enrol.expires_at) <= now : true;
  const fresh = async () => {
    setBusy(true);
    setError(null);
    try {
      onNewToken(await mutate<EnrolToken>('POST', ep.enrolToken(host.host_id)));
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Panel title="2. Run the install command on the host" id="w2">
      <p>Open a root shell on <strong>{host.name}</strong> (Ubuntu 22.04 or 24.04, or Debian 12 incl. 64-bit Raspberry Pi OS) and run this one-liner. It installs the agent and enrols the host with this manager.</p>
      {enrol && !expired ? (
        <>
          <CopyField value={enrol.command} label="install command" />
          <p class="dim">The command contains a one-time token. It expires in <Countdown until={enrol.expires_at} now={now} /> and is shown only now; it is never stored in readable form.</p>
        </>
      ) : (
        <div class="banner banner-warn" role="status">
          <span>{enrol ? 'The enrol token has expired.' : 'The install command is shown only once, when it is created.'} Create a new one-hour token to continue.</span>
        </div>
      )}
      <div class="wait" role="status" aria-live="polite" data-testid="waiting">
        <span class="spinner" aria-hidden="true" />
        <span>Waiting for the host… <span class="dim">checking every 3 seconds</span></span>
      </div>
      <FormError error={error} />
      <div class="dialog-actions">
        <Button onClick={() => void fresh()} disabled={busy}>{busy ? 'Working…' : 'Create a new token'}</Button>
        <Link to={`/hosts/${host.host_id}`} class="btn">Skip to the host page</Link>
      </div>
    </Panel>
  );
}

// ---- step 3 -------------------------------------------------------------------------------------------------------

function Facts({ host }: { host: Host }): JSX.Element {
  const f = host.facts;
  return (
    <dl class="facts" data-testid="host-facts">
      <div><dt>Hostname</dt><dd>{f?.hostname ?? DASH}</dd></div>
      <div><dt>Management IP</dt><dd>{host.mgmt_ip ?? DASH}</dd></div>
      <div><dt>OS</dt><dd>{f?.os ? `${f.os.id ?? ''} ${f.os.version ?? ''}` : DASH}</dd></div>
      <div><dt>Kernel</dt><dd>{f?.kernel ?? DASH}</dd></div>
      <div><dt>Architecture</dt><dd>{f?.arch ?? DASH}</dd></div>
      <div><dt>CPUs / memory</dt><dd>{f?.cpus ?? DASH} / {f?.mem_mb ? formatMiB(f.mem_mb) : DASH}</dd></div>
      <div><dt>Agent</dt><dd>{host.agent_version ?? DASH}</dd></div>
      <div><dt>Time sync</dt><dd>{f?.time ? (f.time.synced ? 'synced' : 'NOT synced') : DASH}</dd></div>
    </dl>
  );
}

function InterfaceStep({ host, comps, onApplied }: { host: Host; comps: Component[]; onApplied: () => void }): JSX.Element {
  const ifaces = host.facts?.interfaces ?? [];
  const probe = comps.find((c) => c.type === 'probe');
  return (
    <>
      <Panel title="3. The host has enrolled" id="w3a">
        <p class="banner banner-info" role="status"><Badge tone="ok">enrolled</Badge><span>{host.name} reported its facts. Check them, then choose how its interfaces are used.</span></p>
        <Facts host={host} />
      </Panel>
      <Panel title={probe ? 'Choose the probe interfaces' : 'Interfaces'} id="w3b">
        {probe ? (
          <PortPicker hostName={host.name} ifaces={ifaces} ownProbe={probe.id}
            onApply={async (ports) => { await mutate('PUT', ep.ports(probe.component_id), { ports }); onApplied(); }} />
        ) : (
          <>
            <p class="dim">This host has no probe, so there are no test interfaces to assign.</p>
            <div class="dialog-actions"><Button variant="primary" onClick={onApplied}>Continue</Button></div>
          </>
        )}
      </Panel>
    </>
  );
}

// ---- step 4 -------------------------------------------------------------------------------------------------------

function ApplyStep({ host }: { host: Host }): JSX.Element {
  const hostRes = useResource<Host>(ep.host(host.host_id));
  const comps = useResource<Page<Component>>(ep.hostComponents(host.host_id), { paged: true });
  useEffect(() => {
    const t = setInterval(() => { hostRes.refresh(); comps.refresh(); }, 3000);
    return () => clearInterval(t);
  }, [hostRes.refresh, comps.refresh]);
  const list = (comps.data?.items ?? []).filter((c) => c.enabled);
  const healthy = list.filter((c) => c.health === 'ok').length;
  const done = list.length > 0 && healthy === list.length;
  const h = hostRes.data ?? host;
  return (
    <Panel title="4. Applying the configuration" id="w4">
      <div class="wait" role="status" aria-live="polite" data-testid="apply-status">
        {done ? <StatusPill state="ok" label="done" /> : <span class="spinner" aria-hidden="true" />}
        <span data-testid="apply-progress">{done ? `All ${list.length} components are healthy.` : `Applying… ${healthy} of ${list.length} components healthy`}</span>
        <span class="dim">desired {formatVersion(h.desired_version)}, applied {formatVersion(h.applied_version)}</span>
      </div>
      <ul class="apply-list" aria-label="Components">
        {list.map((c) => (
          <li key={c.component_id}>
            <span class="apply-name">{c.id} <span class="dim">({c.type})</span></span>
            <StatusPill state={healthPill(c.health)} label={c.health === 'degraded' ? 'warn' : c.health === 'unknown' ? 'waiting' : c.health} />
          </li>
        ))}
      </ul>
      {comps.error ? <ErrorBanner what="Could not read the components." message={comps.error.message} onRetry={comps.refresh} /> : null}
      <div class="dialog-actions">
        <Link to="/hosts/new" class="btn">Add another host</Link>
        <Link to={`/hosts/${host.host_id}`} class={`btn${done ? ' btn-primary' : ''}`}>Open host</Link>
      </div>
    </Panel>
  );
}

// ---- page ---------------------------------------------------------------------------------------------------------

export function AddHostPage({ me }: { me: Me | undefined }): JSX.Element {
  const { query } = useLocation();
  const hostId = query.get('host');
  const applying = query.get('step') === 'apply';
  const [enrol, setEnrol] = useState<EnrolToken | null>(null);
  const host = useResource<Host>(hostId ? ep.host(hostId) : null);
  const comps = useResource<Page<Component>>(hostId ? ep.hostComponents(hostId) : null, { paged: true });
  const h = host.data;

  let step: StepId = 'name';
  if (hostId) step = applying ? 'apply' : h && h.state !== 'pending' ? 'interfaces' : 'enrol';

  let body: JSX.Element;
  if (!hostId) {
    body = <NameStep allowed={canAdmin(me)} onCreated={(id, tok) => { setEnrol(tok); navigate(`/hosts/new?host=${encodeURIComponent(id)}`, { replace: true }); }} />;
  } else if (host.loading || !h) {
    body = host.error ? <ErrorBanner what="Could not load this host." message={host.error.message} onRetry={host.refresh} /> : <SkeletonBlock rows={4} label="Loading host" />;
  } else if (step === 'enrol') {
    body = <EnrolStep host={h} enrol={enrol} onNewToken={setEnrol} />;
  } else if (step === 'interfaces') {
    body = <InterfaceStep host={h} comps={comps.data?.items ?? []} onApplied={() => navigate(`/hosts/new?host=${encodeURIComponent(h.host_id)}&step=apply`)} />;
  } else {
    body = <ApplyStep host={h} />;
  }
  return (
    <>
      <PageHeader title="Add host" crumbs={[{ to: '/hosts', label: 'Hosts' }]} sub={h ? <>{h.name} · <Link to={`/sites/${h.site}`}>{h.site}</Link> · <ShapeBadges shapes={h.shapes} /></> : 'Enrol a new machine in four steps.'} />
      <Stepper step={step} />
      {body}
    </>
  );
}
