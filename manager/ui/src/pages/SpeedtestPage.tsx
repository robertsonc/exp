// Speedtest settings of a site (12-speedtest-analytics.md section 8; admin.yaml tag speedtest): branding with a live
// preview, versioned consent text, zones and subnet labels, serve/TLS/DNS leg, limits and targets, privacy, internet-leg
// pause, per-zone QR signage, connectors and the per-org device_key. INTENT only: the manager never receives or shows
// a test result or evidence (SR-20). Everything typed by an admin or read from the network is rendered as text.
import type { JSX } from 'preact';
import { useEffect, useMemo, useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { Me, Page, Site, SpeedtestConsentHistory, SpeedtestDeviceKeyState, SpeedtestLogo, SpeedtestQr, SpeedtestSettings, SpeedtestTls } from '../api/types';
import { mutate, mutateBytes, useResource } from '../data/hooks';
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, ErrorBanner, Panel, SkeletonBlock, StatusPill } from '../components/atoms';
import { CheckField, FormError, SelectField, TextArea, TextField, failText, secretSummary } from '../components/forms';
import { canAdmin } from '../components/Issues';
import { notify } from '../components/Toasts';
import { Link } from '../components/viz';
import { Loadable, PageHeader } from './common';
import { formatAbsolute } from '../lib/format';
import { qrPath } from '../lib/qr';
import { LIMIT_KEYS, LIMIT_META, LOGO_MAX_BYTES, contrastRatio, draftFrom, logoProblem, problems, safeColor, toBody, type Draft } from '../lib/speedtest';
import { MAX_CERT_PEM, MAX_KEY_PEM, tlsPemProblems } from '../lib/tls';
import { httpsProblem } from '../lib/validate';
import { navigate } from '../router';

const isOwner = (me: Me | undefined): boolean => me?.role === 'owner';
const canOperate = (me: Me | undefined): boolean => me?.role === 'owner' || me?.role === 'admin' || me?.role === 'operator';
const kib = (n: number): string => `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KiB`;

// ---- index: pick the site -------------------------------------------------------------------------------------------

export function SpeedtestIndex(): JSX.Element {
  const sites = useResource<Page<Site>>(ep.sites, { paged: true });
  const items = sites.data?.items ?? [];
  useEffect(() => {
    if (items.length === 1 && items[0]) navigate(`/sites/${items[0].site}/speedtest`, { replace: true });
  }, [items.length]);
  return (
    <>
      <PageHeader title="Speedtest" sub="The branded speedtest page that attendees open on the event network. Settings are per site." />
      <Loadable loading={sites.loading} error={sites.data ? null : sites.error} onRetry={sites.refresh} what="sites">
        {items.length === 0 ? <EmptyState title="No sites yet">Create a site first, then add a host with the Speedtest shape.</EmptyState> : (
          <ul class="site-list">
            {items.map((s) => (
              <li key={s.site} class="panel site-row"><h2 class="h2"><Link to={`/sites/${s.site}/speedtest`}>{s.name}</Link></h2><span class="dim">{s.site}</span></li>
            ))}
          </ul>
        )}
      </Loadable>
    </>
  );
}

// ---- live preview of the page header -------------------------------------------------------------------------------

function Preview({ d, logoUrl, hasLogo }: { d: Draft; logoUrl: string | null; hasLogo: boolean }): JSX.Element {
  const bg = safeColor(d.background, '#0b1320');
  const fg = safeColor(d.text, '#f7f7f7');
  const primary = safeColor(d.primary, '#01a982');
  const accent = safeColor(d.accent, '#7630ea');
  return (
    <div class="st-preview" data-testid="st-preview" role="img" aria-label={`Preview of the page header: ${d.title || 'Speed check'}`} style={{ background: bg, color: fg }}>
      <div class="st-preview-head">
        {logoUrl ? <img class="st-preview-logo" src={logoUrl} alt="" /> : <span class="st-preview-logo st-preview-logo-ph" aria-hidden="true">{hasLogo && !d.removeLogo ? 'logo' : ''}</span>}
        <span class="st-preview-title" data-testid="st-preview-title">{d.title || 'Speed check'}</span>
      </div>
      <div class="st-preview-body">
        <span class="st-preview-btn" style={{ background: primary, color: bg }}>Start</span>
        <span class="st-preview-accent" style={{ borderColor: accent, color: fg }}>result</span>
      </div>
    </div>
  );
}

// ---- logo ---------------------------------------------------------------------------------------------------------

function LogoField({ site, allowed, hasLogo, removed, onRemoved, onPreview }: { site: string; allowed: boolean; hasLogo: boolean; removed: boolean; onRemoved: (v: boolean) => void; onPreview: (url: string | null) => void }): JSX.Element {
  const [file, setFile] = useState<File | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const choose = async (e: Event) => {
    const f = (e.currentTarget as HTMLInputElement).files?.[0] ?? null;
    setError(null);
    onPreview(null);
    if (!f) { setFile(null); setProblem(null); return; }
    const head = new Uint8Array(await f.slice(0, 512).arrayBuffer());
    const why = logoProblem(f.type, f.size, head);
    setProblem(why);
    setFile(why ? null : f);
    // the preview is a data: URL (the page's CSP allows img-src 'self' data:, not blob:); an <img> never runs SVG scripts
    if (!why) onPreview(await new Promise<string | null>((res) => { const r = new FileReader(); r.onload = () => res(typeof r.result === 'string' ? r.result : null); r.onerror = () => res(null); r.readAsDataURL(f); }));
  };
  const upload = async () => {
    if (!file || busy) return;
    setBusy(true);
    setError(null);
    try {
      await mutateBytes<SpeedtestLogo>(ep.speedtestLogo(site), file, file.type);
      notify('ok', 'Logo uploaded. The speedtest box fetches it on its next poll.');
      setFile(null);
    } catch (err) {
      setError(failText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <fieldset class="fieldset">
      <legend>Logo</legend>
      <p class="hint">PNG, SVG or JPEG, at most {kib(LOGO_MAX_BYTES)}. An SVG with scripts or outside references is refused. It is stored as an artifact and installed on the speedtest box.</p>
      <p data-testid="logo-state">{hasLogo ? <Badge tone="ok">logo set</Badge> : <Badge>no logo</Badge>}{removed ? ' (will be removed when you save)' : ''}</p>
      <div class="form-row">
        <label class="btn btn-secondary file-btn">
          <span>Choose image…</span>
          <input type="file" accept="image/png,image/svg+xml,image/jpeg" disabled={!allowed} onChange={(e) => void choose(e)} aria-label="Logo image file" />
        </label>
        <Button variant="primary" disabled={!allowed || !file || busy} onClick={() => void upload()}>{busy ? 'Uploading…' : 'Upload logo'}</Button>
        {hasLogo ? <CheckField label="Remove the logo on save" checked={removed} onChange={onRemoved} disabled={!allowed} /> : null}
      </div>
      {file ? <p class="dim" data-testid="logo-chosen">{file.name} · {kib(file.size)}</p> : null}
      {problem ? <p class="field-error" role="alert">{problem}</p> : null}
      <FormError error={error} />
    </fieldset>
  );
}

// ---- consent ------------------------------------------------------------------------------------------------------

function ConsentHistory({ site, version, current }: { site: string; version: number; current: string }): JSX.Element {
  const [open, setOpen] = useState(false);
  const h = useResource<SpeedtestConsentHistory>(open ? ep.speedtestConsentHistory(site) : null);
  return (
    <div class="consent-history">
      <Button small onClick={() => setOpen((o) => !o)} aria-expanded={open}>{open ? 'Hide history' : `Show history (version ${version} is current)`}</Button>
      {open ? (
        h.loading ? <SkeletonBlock rows={2} label="Loading history" /> : h.error ? <ErrorBanner what="Could not load the consent history." message={h.error.message} onRetry={h.refresh} /> : (
          <ol class="plain-list" data-testid="consent-history" aria-label="Consent versions, newest first">
            {(h.data?.items ?? []).map((i) => (
              <li key={i.version}><strong>Version {i.version}</strong> <span class="dim">{formatAbsolute(i.created_at)} · {i.changed_by}</span><p class="consent-text">{i.text}</p>{i.text === current ? <Badge tone="ok">current</Badge> : null}</li>
            ))}
          </ol>
        )
      ) : null}
    </div>
  );
}

// ---- zones, signage -----------------------------------------------------------------------------------------------

function Qr({ text }: { text: string }): JSX.Element {
  const p = useMemo(() => qrPath(text), [text]);
  return (
    <svg class="qr" viewBox={`0 0 ${p.side} ${p.side}`} role="img" aria-label={`QR code for ${text}`} shape-rendering="crispEdges">
      <rect width={p.side} height={p.side} fill="#fff" />
      <path d={p.d} fill="#000" />
    </svg>
  );
}

function SignagePanel({ site, title }: { site: string; title: string }): JSX.Element {
  const [open, setOpen] = useState(false);
  const qr = useResource<SpeedtestQr>(ep.speedtestQr(site));
  const items = qr.data?.items ?? [];
  return (
    <Panel title="QR signage" id="st-qr">
      <p class="dim">One QR code per zone for posters and table tents. A zone QR only <em>hints</em> where someone is (it stamps a zone when the Wi-Fi controller cannot resolve one); the test works without it.</p>
      {qr.loading ? <SkeletonBlock rows={1} label="Loading signage" /> : items.length === 0 ? (
        <p class="dim" data-testid="qr-empty">No signage yet: save a host name and at least one zone first.</p>
      ) : (
        <>
          <Button variant="primary" onClick={() => setOpen(true)}>Open printable signage ({items.length} zone{items.length === 1 ? '' : 's'})</Button>
          {open ? (
            <Dialog title="Printable signage" onClose={() => setOpen(false)} wide>
              <div class="signage" data-testid="signage">
                {items.map((i) => (
                  <figure key={i.zone} class="signage-card">
                    <figcaption class="signage-title">{title || 'Speed check'}</figcaption>
                    <Qr text={i.url} />
                    <p class="signage-zone">{i.name}</p>
                    <p class="signage-url mono">{i.url}</p>
                  </figure>
                ))}
              </div>
              <div class="dialog-actions"><Button onClick={() => setOpen(false)}>Close</Button><Button variant="primary" onClick={() => window.print()}>Print</Button></div>
            </Dialog>
          ) : null}
        </>
      )}
    </Panel>
  );
}

// ---- provided TLS pair -----------------------------------------------------------------------------------------------

function TlsPair({ site, allowed }: { site: string; allowed: boolean }): JSX.Element {
  const cur = useResource<SpeedtestTls>(allowed ? ep.speedtestTls(site) : null);
  const [cert, setCert] = useState('');
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const problems2 = tlsPemProblems(cert, key);
  const save = async () => {
    if (busy || problems2.cert || problems2.key || !cert || !key) return;
    setBusy(true);
    setError(null);
    try {
      await mutate('PUT', ep.speedtestTls(site), { cert_pem: cert, key_pem: key });
      notify('ok', 'Certificate stored. Set TLS to "provided" and save to use it.');
      setCert('');
      setKey('');
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  if (!allowed) return <p class="dim">Only admins manage the certificate.</p>;
  const c = cur.data;
  return (
    <div data-testid="st-tls">
      <p class="dim">{c?.set ? `A certificate is stored (${c.cert?.subject ?? 'unknown subject'}, expires ${c.cert ? formatAbsolute(c.cert.not_after) : 'unknown'}).` : 'No certificate stored.'} The key is never shown again.</p>
      <TextArea label="Certificate (PEM, leaf first)" value={cert} onInput={setCert} rows={4} error={cert ? problems2.cert : null} hint={`At most ${MAX_CERT_PEM / 1024} KiB.`} />
      <TextArea label="Private key (PEM)" value={key} onInput={setKey} rows={3} error={key ? problems2.key : null} hint={`At most ${MAX_KEY_PEM / 1024} KiB. Stored encrypted; delivered only to the speedtest box.`} />
      <FormError error={error} />
      <Button onClick={() => void save()} disabled={busy || !cert || !key || !!problems2.cert || !!problems2.key}>{busy ? 'Storing…' : 'Store certificate'}</Button>
    </div>
  );
}

// ---- connectors (existing integrations settings) ----------------------------------------------------------------------

interface IntegrationState { kind: 'ec' | 'mist'; config: Record<string, unknown>; credentials: { set: boolean; updated_at: string | null }; updated_at: string | null }

function Connector({ kind, label, urlKey, secretKey, secretLabel, me }: { kind: 'ec' | 'mist'; label: string; urlKey: 'url' | 'api_base'; secretKey: 'api_key' | 'token'; secretLabel: string; me: Me | undefined }): JSX.Element {
  const res = useResource<IntegrationState>(ep.integration(kind));
  const [url, setUrl] = useState<string | null>(null);
  const [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const allowed = isOwner(me);
  const d = res.data;
  const cur = typeof d?.config[urlKey] === 'string' ? (d.config[urlKey] as string) : '';
  const val = url ?? cur;
  const bad = val.trim() ? httpsProblem(val.trim()) : null;
  const dirty = (url !== null && url.trim() !== cur) || secret.trim() !== '';
  const save = async () => {
    if (!allowed || busy || bad || !dirty || !val.trim()) return;
    setBusy(true);
    setError(null);
    try {
      // keep the stored config keys the manager returned as plain values; secret-looking ones come back masked and are never re-sent
      const keep = Object.fromEntries(Object.entries(d?.config ?? {}).filter(([, v]) => typeof v !== 'object' || v === null));
      await mutate('PUT', ep.integration(kind), { config: { ...keep, [urlKey]: val.trim() }, ...(secret.trim() ? { credentials: { [secretKey]: secret.trim() } } : {}) });
      notify('ok', `${label} saved`);
      setUrl(null);
      setSecret('');
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <fieldset class="fieldset" data-testid={`connector-${kind}`}>
      <legend>{label}</legend>
      {res.loading ? <SkeletonBlock rows={2} label={`Loading ${label}`} /> : (
        <>
          <p class="dim">Credentials: {d ? secretSummary(d.credentials) : 'unknown'}{d?.credentials.set ? <> <StatusPill state="ok" label="configured" /></> : null}</p>
          <div class="form-grid">
            <TextField label={kind === 'mist' ? 'API base URL' : 'Orchestrator URL'} value={val} onInput={setUrl} type="url" error={bad} disabled={!allowed} />
            <TextField label={secretLabel} value={secret} onInput={setSecret} type="password" autoComplete="new-password" disabled={!allowed} hint={d?.credentials.set ? 'Leave empty to keep the stored value.' : undefined} />
          </div>
          <FormError error={error} />
          <Button onClick={() => void save()} disabled={!allowed || !dirty || !!bad || busy}>{busy ? 'Saving…' : `Save ${label}`}</Button>
        </>
      )}
    </fieldset>
  );
}

function ConnectorsPanel({ me }: { me: Me | undefined }): JSX.Element {
  return (
    <Panel title="Connectors" id="st-conn">
      <p class="dim">The runner uses these to correlate each test with the client's access point, flows and WAN path. They are the same organisation-wide integrations the rest of the manager uses; only the owner can change them, and credentials are never shown again.</p>
      {isOwner(me) ? null : <p class="banner banner-warn" role="status"><span>Only the owner can change connector settings.</span></p>}
      <Connector kind="mist" label="Juniper Mist" urlKey="api_base" secretKey="token" secretLabel="API token" me={me} />
      <Connector kind="ec" label="HPE EdgeConnect Orchestrator" urlKey="url" secretKey="api_key" secretLabel="API key" me={me} />
      <p class="dim">HPE Aruba SSE has no API connector: its logs can still reach the runner by syslog. Which Wi-Fi sites, appliances and syslog sources the runner reads is set on the runner component of the box.</p>
    </Panel>
  );
}

// ---- the form ------------------------------------------------------------------------------------------------------

function StatusStrip({ site, s, me }: { site: string; s: SpeedtestSettings; me: Me | undefined }): JSX.Element {
  const paused = s.internet_leg?.paused === true;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keyOpen, setKeyOpen] = useState(false);
  const [keyBusy, setKeyBusy] = useState(false);
  const [keyErr, setKeyErr] = useState<string | null>(null);
  const toggle = async () => {
    setBusy(true);
    setError(null);
    try {
      await mutate('POST', ep.speedtestPause(site), { paused: !paused });
      notify('ok', paused ? 'Internet leg resumed' : 'Internet leg paused: tests now measure the on-network leg only.');
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  const rotate = async () => {
    setKeyBusy(true);
    setKeyErr(null);
    try {
      const r = await mutate<SpeedtestDeviceKeyState>('POST', ep.speedtestDeviceKey);
      notify('ok', `Device key ${r.key_id} is in place.`);
      setKeyOpen(false);
    } catch (e) {
      setKeyErr(failText(e));
    } finally {
      setKeyBusy(false);
    }
  };
  const dk = s.device_key;
  return (
    <Panel title="Status" id="st-status">
      <div class="st-status">
        <div>
          <p><strong>Internet leg</strong> {paused ? <StatusPill state="warn" label="paused" /> : <StatusPill state="ok" label="running" />}</p>
          <p class="dim">Pause it during a keynote so the venue uplink is left alone. The box also pauses it by itself while the WAN is busy.</p>
          <Button variant={paused ? 'primary' : 'secondary'} disabled={!canOperate(me) || busy} onClick={() => void toggle()} title={canOperate(me) ? undefined : 'Requires the operator role'}>{busy ? 'Working…' : paused ? 'Resume internet leg' : 'Pause internet leg'}</Button>
          <FormError error={error} />
        </div>
        <div>
          <p><strong>Device key</strong> {dk?.set ? <Badge tone="ok">set</Badge> : <Badge tone="warn">not created</Badge>}{dk?.updated_at ? <span class="dim"> · changed {formatAbsolute(dk.updated_at)}</span> : null}</p>
          <p class="dim">A secret per organisation that turns a device address into an opaque device key, so tests of the same device can be compared without storing who it is. It is never shown. Rotating it breaks that continuity for older tests.</p>
          <Button disabled={!isOwner(me)} onClick={() => setKeyOpen(true)} title={isOwner(me) ? undefined : 'Requires the owner role'}>{dk?.set ? 'Rotate device key…' : 'Create device key…'}</Button>
        </div>
      </div>
      {keyOpen ? (
        <ConfirmDialog title={dk?.set ? 'Rotate the device key?' : 'Create the device key?'} confirmText={dk?.set ? 'Rotate key' : 'Create key'} busy={keyBusy} error={keyErr}
          body={<p>{dk?.set ? 'Tests after the rotation can no longer be matched to the same device as tests before it.' : 'The key is generated here, stored encrypted and delivered only to the runner and the collector.'}</p>}
          onConfirm={() => void rotate()} onCancel={() => { setKeyOpen(false); setKeyErr(null); }} />
      ) : null}
    </Panel>
  );
}

function ListRows<T>({ rows, render, onAdd, addLabel, allowed, max, remove }: { rows: T[]; render: (r: T, i: number) => JSX.Element; onAdd: () => void; addLabel: string; allowed: boolean; max: number; remove: (i: number) => void }): JSX.Element {
  return (
    <>
      {rows.map((r, i) => (
        <div class="rowbox" key={i} role="group" aria-label={`${addLabel.replace('Add ', '')} ${i + 1}`}>
          {render(r, i)}
          <Button small disabled={!allowed} onClick={() => remove(i)} aria-label={`Remove ${addLabel.replace('Add ', '')} ${i + 1}`}>Remove</Button>
        </div>
      ))}
      <Button small disabled={!allowed || rows.length >= max} onClick={onAdd}>{addLabel}</Button>
    </>
  );
}

function SettingsForm({ site, s, me }: { site: string; s: SpeedtestSettings; me: Me | undefined }): JSX.Element {
  const [d, setD] = useState<Draft>(() => draftFrom(s));
  const [preview, setPreview] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const allowed = canAdmin(me);
  const initial = useMemo(() => draftFrom(s), [s]);
  const p = problems(d);
  const set = (patch: Partial<Draft>) => setD((cur) => ({ ...cur, ...patch }));
  const body = Object.keys(p).length === 0 ? toBody(d, s.branding?.logo_artifact) : null;
  const dirty = JSON.stringify(d) !== JSON.stringify(initial);
  const version = s.consent.version ?? 1;
  const consentChanged = d.consent !== s.consent.text;
  const save = async (e?: Event) => {
    e?.preventDefault();
    if (!allowed || !body || !dirty || busy) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await mutate<SpeedtestSettings>('PUT', ep.speedtest(site), body);
      setD(draftFrom(saved));
      setPreview(null);
      notify('ok', consentChanged ? `Settings saved. The consent text is now version ${version + 1}.` : 'Speedtest settings saved. The box applies them on its next poll.');
    } catch (err) {
      setError(failText(err));
    } finally {
      setBusy(false);
    }
  };
  const lim = (k: (typeof LIMIT_KEYS)[number]) => {
    const m = LIMIT_META[k];
    return <TextField key={k} label={m.label} value={d.limits[k]} onInput={(v) => set({ limits: { ...d.limits, [k]: v } })} type="number" inputMode="numeric" placeholder={String(m.def)} error={p[`limit-${k}`] ?? null} disabled={!allowed} />;
  };
  const zoneOptions = [{ value: '', label: 'Choose a zone' }, ...d.zones.filter((z) => z.id).map((z) => ({ value: z.id, label: `${z.name || z.id} (${z.id})` }))];
  return (
    <form onSubmit={(e) => void save(e)} noValidate aria-label="Speedtest settings" class="editor">
      {allowed ? null : <p class="banner banner-warn" role="status"><span>Your role does not allow changes. Editing needs the admin role.</span></p>}

      <Panel title="Branding" id="st-brand">
        <Preview d={d} logoUrl={preview} hasLogo={!!s.branding?.logo_artifact} />
        {(() => {
          const text = contrastRatio(safeColor(d.text, '#f7f7f7'), safeColor(d.background, '#0b1320'));
          const btn = contrastRatio(safeColor(d.background, '#0b1320'), safeColor(d.primary, '#01a982'));
          const low = [text !== null && text < 4.5 ? `Text on background is ${text}:1` : '', btn !== null && btn < 3 ? `The button label on the primary colour is ${btn}:1` : ''].filter(Boolean);
          return low.length ? <p class="banner banner-warn" role="status" data-testid="contrast-warning"><span>{low.join('. ')}. Contrast of 4.5:1 (3:1 for large text) or more is easier to read.</span></p> : null;
        })()}
        <div class="form-grid">
          <TextField label="Page title" value={d.title} onInput={(v) => set({ title: v })} error={p['title'] ?? null} maxLength={80} disabled={!allowed} />
          <TextField label="Languages" value={d.languages} onInput={(v) => set({ languages: v })} error={p['languages'] ?? null} hint="Language tags, the first is the default (for example en, de)." disabled={!allowed} />
        </div>
        <div class="form-grid form-grid-4">
          {(['primary', 'accent', 'background', 'text'] as const).map((k) => (
            <TextField key={k} label={`${k[0]?.toUpperCase()}${k.slice(1)} colour`} value={d[k]} onInput={(v) => set({ [k]: v } as Partial<Draft>)} error={p[k] ?? null} placeholder="#01a982" disabled={!allowed} maxLength={7} />
          ))}
        </div>
        <TextArea label="Page text overrides" value={d.copy} onInput={(v) => set({ copy: v })} rows={3} error={p['copy'] ?? null} hint="One per line as key=text, for example start_button=Start. Up to 40, 280 characters each." disabled={!allowed} />
        <CheckField label="Show the access point and channel to the user" checked={d.showNetwork} onChange={(v) => set({ showNetwork: v })} disabled={!allowed} />
        <LogoField site={site} allowed={allowed} hasLogo={!!s.branding?.logo_artifact} removed={d.removeLogo} onRemoved={(v) => set({ removeLogo: v })} onPreview={setPreview} />
      </Panel>

      <Panel title="Consent" id="st-consent">
        <p class="dim">Shown before the first test: what is measured and that device and traffic metadata are recorded for diagnostics. Each test stores the version it was taken under. Editing the text publishes a new version; every version is kept.</p>
        <TextArea label="Consent text" value={d.consent} onInput={(v) => set({ consent: v })} rows={5} error={p['consent'] ?? null} disabled={!allowed} hint={`${d.consent.length} of 2000 characters.`} />
        <p data-testid="consent-version" class="dim">Current version <strong>{version}</strong>{consentChanged && !p['consent'] ? <> · saving publishes <strong>version {version + 1}</strong></> : null}</p>
        {canAdmin(me) ? <ConsentHistory site={site} version={version} current={s.consent.text} /> : null}
      </Panel>

      <Panel title="Zones and subnets" id="st-zones">
        <p class="dim">Where a test came from is worked out from the Wi-Fi controller and the flow data. These labels name the zones, and the subnet table is the fallback when nothing else can place a device. Leave both empty if you do not need them.</p>
        <fieldset class="fieldset"><legend>Zones</legend>
          <ListRows rows={d.zones} allowed={allowed} max={256} addLabel="Add zone" onAdd={() => set({ zones: [...d.zones, { id: '', name: '' }] })} remove={(i) => set({ zones: d.zones.filter((_, j) => j !== i) })}
            render={(z, i) => (
              <div class="form-grid">
                <TextField label="Zone id" value={z.id} onInput={(v) => set({ zones: d.zones.map((x, j) => (j === i ? { ...x, id: v } : x)) })} error={p[`zone-id-${i}`] ?? null} disabled={!allowed} />
                <TextField label="Zone name" value={z.name} onInput={(v) => set({ zones: d.zones.map((x, j) => (j === i ? { ...x, name: v } : x)) })} error={p[`zone-name-${i}`] ?? null} disabled={!allowed} maxLength={64} />
              </div>
            )} />
        </fieldset>
        <fieldset class="fieldset"><legend>Subnet to zone</legend>
          <ListRows rows={d.subnets} allowed={allowed} max={256} addLabel="Add subnet" onAdd={() => set({ subnets: [...d.subnets, { cidr: '', zone: '' }] })} remove={(i) => set({ subnets: d.subnets.filter((_, j) => j !== i) })}
            render={(n, i) => (
              <div class="form-grid">
                <TextField label="Subnet" value={n.cidr} onInput={(v) => set({ subnets: d.subnets.map((x, j) => (j === i ? { ...x, cidr: v } : x)) })} placeholder="10.60.0.0/16" error={p[`subnet-cidr-${i}`] ?? null} disabled={!allowed} />
                {d.zones.length > 0
                  ? <SelectField label="Zone" value={n.zone} onChange={(v) => set({ subnets: d.subnets.map((x, j) => (j === i ? { ...x, zone: v } : x)) })} options={zoneOptions} error={p[`subnet-zone-${i}`] ?? null} disabled={!allowed} />
                  : <TextField label="Zone id" value={n.zone} onInput={(v) => set({ subnets: d.subnets.map((x, j) => (j === i ? { ...x, zone: v } : x)) })} error={p[`subnet-zone-${i}`] ?? null} disabled={!allowed} />}
              </div>
            )} />
        </fieldset>
      </Panel>

      <Panel title="Where the box serves" id="st-serve">
        <p class="dim">One box at the venue core or data centre, reached by the attendee networks routed and without address translation. Plain HTTP is the default; HTTPS needs a certificate.</p>
        <div class="form-grid">
          <TextField label="Host name" value={d.hostname} onInput={(v) => set({ hostname: v })} error={p['hostname'] ?? p['serve'] ?? null} placeholder="speed.summit.example" disabled={!allowed} hint="The name people open (and the QR codes use)." />
          <TextField label="Listen address" value={d.listenIp} onInput={(v) => set({ listenIp: v })} error={p['listenIp'] ?? null} placeholder="10.0.0.9" disabled={!allowed} hint="An address of the speedtest box's routed interface." />
          <SelectField label="Placement" value={d.placement} onChange={(v) => set({ placement: v === 'core' || v === 'dc' || v === 'other' ? v : '' })} disabled={!allowed} options={[{ value: '', label: 'Not stated' }, { value: 'core', label: 'Venue core' }, { value: 'dc', label: 'Data centre' }, { value: 'other', label: 'Other' }]} />
          <SelectField label="Transport" value={d.tlsMode} onChange={(v) => set({ tlsMode: v === 'provided' ? 'provided' : 'none' })} disabled={!allowed} hint={d.tlsMode === 'provided' ? 'HTTPS on 443 with HTTP redirected to it.' : 'Plain HTTP on port 80.'} options={[{ value: 'none', label: 'Plain HTTP (default)' }, { value: 'provided', label: 'HTTPS with my certificate' }]} />
        </div>
        <CheckField label="Require the real client address" checked={d.requireReal} onChange={(v) => set({ requireReal: v })} disabled={!allowed} hint="If a client appears to come from outside the attendee subnets (address translation in the path), the test is not bound to a device." />
        <div class="form-grid">
          <TextField label="Attendee subnets" value={d.clientSubnets} onInput={(v) => set({ clientSubnets: v })} error={p['clientSubnets'] ?? null} disabled={!allowed} hint="Comma-separated. Empty uses the subnets above." />
          <TextField label="Translated or edge addresses" value={d.translated} onInput={(v) => set({ translated: v })} error={p['translated'] ?? null} disabled={!allowed} hint="A client seen at one of these is never bound to a device." />
        </div>
        <fieldset class="fieldset"><legend>DNS leg</legend>
          <CheckField label="Answer DNS test queries on this box" checked={d.dnsEnabled} onChange={(v) => set({ dnsEnabled: v })} disabled={!allowed} hint="Needs an NS delegation of the zone to this box; without it the page falls back to the probe's DNS line." />
          <TextField label="DNS zone" value={d.dnsZone} onInput={(v) => set({ dnsZone: v })} error={p['dnsZone'] ?? null} placeholder="t.speed.summit.example" disabled={!allowed} />
        </fieldset>
        {d.tlsMode === 'provided' ? <fieldset class="fieldset"><legend>Certificate</legend><TlsPair site={site} allowed={allowed} /></fieldset> : null}
      </Panel>

      <Panel title="Targets, limits and the internet leg" id="st-limits">
        <div class="form-grid">
          <TextField label="Download target (Mb/s)" value={d.down} onInput={(v) => set({ down: v })} type="number" inputMode="decimal" placeholder="25" error={p['down'] ?? null} disabled={!allowed} />
          <TextField label="Upload target (Mb/s)" value={d.up} onInput={(v) => set({ up: v })} type="number" inputMode="decimal" placeholder="10" error={p['up'] ?? null} disabled={!allowed} />
        </div>
        <div class="form-grid form-grid-4">{LIMIT_KEYS.map(lim)}</div>
        <div class="check-row">
          <CheckField label="Measure the internet leg" checked={d.internetEnabled} onChange={(v) => set({ internetEnabled: v })} disabled={!allowed} hint="Browser to Cloudflare's public speed-test servers." />
          <TextField label="Auto-pause above WAN utilisation (%)" value={d.autoPause} onInput={(v) => set({ autoPause: v })} type="number" inputMode="numeric" placeholder="80" error={p['autoPause'] ?? null} disabled={!allowed} />
        </div>
        <fieldset class="fieldset"><legend>Core protection</legend>
          <p class="hint">While the core-facing interface is busy the on-network transfer shrinks, so the test never hurts the event.</p>
          <div class="form-grid form-grid-3">
            <TextField label="Interface" value={d.guardIface} onInput={(v) => set({ guardIface: v })} error={p['guardIface'] ?? null} disabled={!allowed} />
            <TextField label="Shrink above utilisation (%)" value={d.guardUtil} onInput={(v) => set({ guardUtil: v })} type="number" inputMode="numeric" placeholder="70" error={p['guardUtil'] ?? null} disabled={!allowed} />
            <TextField label="Smallest transfer (bytes)" value={d.guardMin} onInput={(v) => set({ guardMin: v })} type="number" inputMode="numeric" placeholder="5000000" error={p['guardMin'] ?? null} disabled={!allowed} />
          </div>
        </fieldset>
        <fieldset class="fieldset"><legend>Path hops the box times</legend>
          <p class="hint">Venue infrastructure context shown beside results, not a per-person measurement.</p>
          <div class="form-grid form-grid-4">
            <TextField label="Gateway" value={d.gateway} onInput={(v) => set({ gateway: v })} placeholder="auto" error={p['gateway'] ?? null} disabled={!allowed} />
            <TextField label="Edge" value={d.edge} onInput={(v) => set({ edge: v })} error={p['edge'] ?? null} disabled={!allowed} />
            <TextField label="Edge + 1" value={d.edge1} onInput={(v) => set({ edge1: v })} placeholder="auto" error={p['edge1'] ?? null} disabled={!allowed} />
            <TextField label="Note" value={d.pathNote} onInput={(v) => set({ pathNote: v })} error={p['pathNote'] ?? null} disabled={!allowed} maxLength={200} />
          </div>
        </fieldset>
      </Panel>

      <Panel title="Privacy and retention" id="st-privacy">
        <p class="dim">No name or email is ever collected. Tests, device details and evidence are kept for the retention period; the aggregate charts are kept for good.</p>
        <div class="form-grid">
          <TextField label="Keep tests and evidence (days)" value={d.retention} onInput={(v) => set({ retention: v })} type="number" inputMode="numeric" placeholder="30" error={p['retention'] ?? null} disabled={!allowed} />
        </div>
        <CheckField label="Drop raw addresses and names after the final diagnosis" checked={d.scrub} onChange={(v) => set({ scrub: v })} disabled={!allowed} hint="Removes the raw IP, MAC, user name and host name once the diagnosis is final and keeps only the opaque device key. Off by default; your privacy sign-off decides." />
      </Panel>

      <div class="savebar">
        <FormError error={error} />
        {Object.keys(p).length > 0 ? <span class="field-error" role="status">{Object.keys(p).length} field{Object.keys(p).length === 1 ? '' : 's'} need attention.</span> : null}
        <Button onClick={() => { setD(initial); setPreview(null); }} disabled={!dirty || busy}>Discard changes</Button>
        <Button type="submit" variant="primary" disabled={!allowed || !dirty || !!Object.keys(p).length || busy}>{busy ? 'Saving…' : 'Save settings'}</Button>
      </div>
    </form>
  );
}

export function SpeedtestPage({ slug, me }: { slug: string; me: Me | undefined }): JSX.Element {
  const site = useResource<Site>(ep.site(slug));
  const st = useResource<SpeedtestSettings>(ep.speedtest(slug));
  const crumbs = [{ to: '/sites', label: 'Sites' }, { to: `/sites/${slug}`, label: site.data?.name ?? slug }];
  if (st.loading && !st.data) return <><PageHeader title="Speedtest" crumbs={crumbs} /><SkeletonBlock rows={6} label="Loading speedtest settings" /></>;
  if (!st.data) {
    return (
      <>
        <PageHeader title="Speedtest" crumbs={crumbs} />
        {st.error?.status === 404 ? <EmptyState title="Site not found" action={<Link to="/sites" class="btn">Back to sites</Link>} /> : <ErrorBanner what="Could not load the speedtest settings." message={st.error?.message} onRetry={st.refresh} />}
      </>
    );
  }
  const s = st.data;
  const title = s.branding?.title ?? '';
  return (
    <>
      <PageHeader title="Speedtest" crumbs={crumbs} sub={<>{site.data?.name ?? slug} · one speedtest box at the venue core, no accounts, no names.{s.updated_at ? <> Settings changed {formatAbsolute(s.updated_at)}.</> : ' Not configured yet: the defaults apply.'}</>} />
      <StatusStrip site={slug} s={s} me={me} />
      <SettingsForm key={slug} site={slug} s={s} me={me} />
      <SignagePanel site={slug} title={title} />
      <ConnectorsPanel me={me} />
    </>
  );
}
