// Releases: imported versions, import by version, upload manifest + signature + artifacts, per-site target with canary
// status, and rollback (05-manager.md section 9).
import type { JSX } from 'preact';
import { useRef, useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { FleetHostRow, Me, Page, Release, Site } from '../api/types';
import { mutate, mutateForm, useResource } from '../data/hooks';
import { Badge, Button, Dialog, EmptyState, Panel, SkeletonBlock } from '../components/atoms';
import { FormError, SelectField, TextField, failText } from '../components/forms';
import { canAdmin } from '../components/Issues';
import { notify } from '../components/Toasts';
import { Link } from '../components/viz';
import { Loadable, PageHeader } from './common';
import { DASH, formatAbsolute, formatBytes } from '../lib/format';
import { safeHttpsUrl } from '../lib/redact';
import { RE, versionLess } from '../lib/validate';

const MAX_MANIFEST = 1024 * 1024;
const MAX_SIGNATURE = 8 * 1024;
const MAX_ARTIFACT = 200 * 1024 * 1024;

export function canaryTone(state: string | null | undefined): 'ok' | 'warn' | 'fail' | 'neutral' {
  return state === 'failed' ? 'fail' : state === 'promoted' ? 'ok' : state ? 'warn' : 'neutral';
}

/** Set a site's target release (optionally behind a canary host) or roll it back to an older version. */
export function ReleaseTargetDialog({ site, mode, onClose }: { site: Site; mode: 'set' | 'rollback'; onClose: () => void }): JSX.Element {
  const rels = useResource<Page<Release>>(ep.releases, { paged: true });
  const hosts = useResource<Page<FleetHostRow>>(ep.hosts, { paged: true });
  const all = rels.data?.items ?? [];
  const current = site.release_version;
  const options = mode === 'rollback'
    ? all.filter((r) => current && versionLess(r.version, current)).sort((a, b) => (versionLess(a.version, b.version) ? 1 : -1))
    : all.filter((r) => r.version !== current).sort((a, b) => (versionLess(a.version, b.version) ? 1 : -1));
  const [version, setVersion] = useState('');
  const [canary, setCanary] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const chosen = version || options[0]?.version || '';
  const candidates = (hosts.data?.items ?? []).filter((h) => h.site === site.site && (h.state === 'enrolled' || h.state === 'stale'));

  const submit = async (e: Event) => {
    e.preventDefault();
    if (!chosen || busy) return;
    setBusy(true);
    setError(null);
    try {
      await mutate('PATCH', ep.siteRelease(site.site), { version: chosen, canary_host_id: mode === 'set' && canary ? canary : null });
      notify('ok', mode === 'rollback' ? `Rolled ${site.name} back to ${chosen}` : canary ? `Canary rollout of ${chosen} started on ${site.name}` : `${site.name} now targets ${chosen}`);
      onClose();
    } catch (err) {
      setError(failText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog title={mode === 'rollback' ? `Roll back ${site.name}` : `Set the release for ${site.name}`} onClose={onClose}>
      <form onSubmit={(e) => void submit(e)} noValidate aria-label={mode === 'rollback' ? 'Roll back release' : 'Set release'}>
        <p class="dim">{mode === 'rollback' ? `Every host in the site returns to the chosen version (currently ${current ?? DASH}). Agents also roll back by themselves when a new version fails its health checks.` : `Currently ${current ?? 'no release'}. Hosts update on their next poll.`}</p>
        {rels.loading ? <SkeletonBlock rows={2} label="Loading releases" /> : options.length === 0 ? (
          <p class="banner banner-warn" role="status"><span>{mode === 'rollback' ? 'There is no older imported release to roll back to.' : 'There is no other imported release. Import one first.'}</span></p>
        ) : (
          <>
            <SelectField label={mode === 'rollback' ? 'Roll back to' : 'Release'} value={chosen} onChange={setVersion} options={options.map((r) => ({ value: r.version, label: r.version }))} />
            {mode === 'set' ? (
              <SelectField label="Canary host" value={canary} onChange={setCanary} hint="The canary compiles first and the rest follow after it has been healthy for 10 minutes."
                options={[{ value: '', label: 'No canary: update every host now' }, ...candidates.map((h) => ({ value: h.host_id, label: h.name }))]} />
            ) : null}
          </>
        )}
        <FormError error={error} />
        <div class="dialog-actions">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant={mode === 'rollback' ? 'danger' : 'primary'} disabled={!chosen || busy}>{busy ? 'Working…' : mode === 'rollback' ? 'Roll back' : canary ? 'Start canary' : 'Set release'}</Button>
        </div>
      </form>
    </Dialog>
  );
}

const IMPORT_HINTS: Record<string, string> = {
  signature_invalid: 'The release signature does not verify against the manager’s release key. Nothing was stored.',
  artifact_hash_mismatch: 'An artifact does not match the hash in the signed manifest. Nothing was stored.',
  manifest_invalid: 'The manifest is not valid. Nothing was stored.',
  release_exists: 'This version is already imported.',
  release_not_found: 'That version was not found in the releases repository.',
};

function ImportPanel({ allowed }: { allowed: boolean }): JSX.Element {
  const [version, setVersion] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bad = version !== '' && !RE.semver.test(version.trim());
  const submit = async (e: Event) => {
    e.preventDefault();
    if (!version.trim() || bad || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await mutate<Release>('POST', ep.releaseImport, { version: version.trim(), source: 'github' });
      notify('ok', `Imported and verified release ${r?.version ?? version.trim()}`);
      setVersion('');
    } catch (err) {
      const code = (err as { code?: string }).code ?? '';
      setError(`${IMPORT_HINTS[code] ?? ''} ${failText(err)}`.trim());
    } finally {
      setBusy(false);
    }
  };
  return (
    <Panel title="Import a release" id="ri">
      <p class="dim">Fetches the signed manifest and artifacts of a published release, verifies the signature and every hash, and only then stores it.</p>
      <form onSubmit={(e) => void submit(e)} aria-label="Import a release" noValidate>
        <div class="form-grid">
          <TextField label="Version" value={version} onInput={setVersion} placeholder="0.2.0" error={bad ? 'Use a version like 1.2.3.' : null} disabled={!allowed} />
        </div>
        <FormError error={error} />
        <div class="dialog-actions"><Button type="submit" variant="primary" disabled={!allowed || !version.trim() || bad || busy}>{busy ? 'Importing and verifying…' : 'Import from GitHub'}</Button></div>
      </form>
    </Panel>
  );
}

function UploadPanel({ allowed }: { allowed: boolean }): JSX.Element {
  const [manifest, setManifest] = useState<File | null>(null);
  const [sig, setSig] = useState<File | null>(null);
  const [arts, setArts] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const form = useRef<HTMLFormElement>(null);
  const problem = manifest && manifest.size > MAX_MANIFEST ? 'The manifest is larger than 1 MiB.' : sig && sig.size > MAX_SIGNATURE ? 'The signature file is larger than 8 KiB.'
    : arts.length > 64 ? 'At most 64 artifacts.' : arts.some((a) => a.size > MAX_ARTIFACT) ? 'An artifact is larger than 200 MiB.' : null;
  const ready = !!manifest && !!sig && arts.length > 0 && !problem;
  const submit = async (e: Event) => {
    e.preventDefault();
    if (!ready || busy || !manifest || !sig) return;
    setBusy(true);
    setError(null);
    try {
      const fd = new FormData();
      fd.append('manifest', manifest, manifest.name);
      fd.append('signature', sig, sig.name);
      for (const a of arts) fd.append('artifacts', a, a.name);
      const r = await mutateForm<Release>(ep.releaseUpload, fd);
      notify('ok', `Uploaded and verified release ${r?.version ?? ''}`.trim());
      form.current?.reset();
      setManifest(null);
      setSig(null);
      setArts([]);
    } catch (err) {
      const code = (err as { code?: string }).code ?? '';
      setError(`${IMPORT_HINTS[code] ?? ''} ${failText(err)}`.trim());
    } finally {
      setBusy(false);
    }
  };
  const pick = (fn: (f: File | null) => void) => (e: Event) => fn((e.currentTarget as HTMLInputElement).files?.[0] ?? null);
  return (
    <Panel title="Upload a release" id="ru">
      <p class="dim">For private or air-gapped builds: upload the manifest, its detached signature and every artifact it lists. They are verified exactly like an import.</p>
      <form ref={form} onSubmit={(e) => void submit(e)} aria-label="Upload a release" noValidate>
        <div class="form-grid form-grid-3">
          <div class="field"><label for="up-manifest">Manifest (JSON)</label><input id="up-manifest" type="file" accept="application/json,.json" disabled={!allowed} onChange={pick(setManifest)} /></div>
          <div class="field"><label for="up-sig">Signature</label><input id="up-sig" type="file" disabled={!allowed} onChange={pick(setSig)} /></div>
          <div class="field"><label for="up-arts">Artifacts (tarballs)</label><input id="up-arts" type="file" multiple accept=".tar.gz,.tgz,application/gzip" disabled={!allowed} onChange={(e) => setArts([...((e.currentTarget as HTMLInputElement).files ?? [])])} /></div>
        </div>
        {problem ? <p class="field-error" role="alert">{problem}</p> : null}
        <FormError error={error} />
        <div class="dialog-actions"><Button type="submit" variant="primary" disabled={!allowed || !ready || busy}>{busy ? 'Uploading and verifying…' : 'Upload and verify'}</Button></div>
      </form>
    </Panel>
  );
}

function ReleaseTable({ rels }: { rels: Release[] }): JSX.Element {
  if (rels.length === 0) return <EmptyState title="No releases imported yet">Import one below to start rolling out the agent and components.</EmptyState>;
  return (
    <div class="table-scroll">
      <table class="plain" data-testid="release-table">
        <caption class="sr-only">Imported releases</caption>
        <thead><tr><th scope="col">Version</th><th scope="col">Source</th><th scope="col">Verified</th><th scope="col">Minimum agent</th><th scope="col">Artifacts</th><th scope="col">Targeted by</th></tr></thead>
        <tbody>
          {rels.map((r) => {
            const notes = safeHttpsUrl(r.notes_url);
            return (
              <tr key={r.rel_id}>
                <th scope="row">{r.version}{notes ? <> <a href={notes} target="_blank" rel="noopener noreferrer">notes</a></> : null}</th>
                <td>{r.source}</td>
                <td title={formatAbsolute(r.verified_at)}>{formatAbsolute(r.verified_at)}</td>
                <td>{r.min_agent_version}</td>
                <td>{r.artifacts.length} <span class="dim">({formatBytes(r.artifacts.reduce((n, a) => n + a.size, 0))})</span></td>
                <td>{(r.sites ?? []).length ? (r.sites ?? []).map((s) => <Link key={s} to={`/sites/${s}`} class="chip-link">{s}</Link>) : <span class="dim">no site</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function SiteTargets({ sites, allowed }: { sites: Site[]; allowed: boolean }): JSX.Element {
  const [dlg, setDlg] = useState<{ site: Site; mode: 'set' | 'rollback' } | null>(null);
  if (sites.length === 0) return <EmptyState title="No sites yet" action={<Link to="/sites" class="btn">Go to sites</Link>} />;
  return (
    <>
      <div class="table-scroll">
        <table class="plain" data-testid="site-targets">
          <caption class="sr-only">Release target per site</caption>
          <thead><tr><th scope="col">Site</th><th scope="col">Target version</th><th scope="col">Canary</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {sites.map((s) => {
              const running = s.canary_state === 'pending' || s.canary_state === 'healthy_waiting';
              return (
                <tr key={s.site} data-site={s.site}>
                  <th scope="row"><Link to={`/sites/${s.site}`}>{s.name}</Link></th>
                  <td>{s.release_version ?? DASH}</td>
                  <td>{s.canary_state ? <Badge tone={canaryTone(s.canary_state)}>{s.canary_state.replace('_', ' ')}</Badge> : <span class="dim">none</span>}{s.canary_host_id && running ? <span class="dim"> on {s.canary_host_id}</span> : null}</td>
                  <td class="row-btns">
                    <Button small disabled={!allowed || running} onClick={() => setDlg({ site: s, mode: 'set' })} aria-label={`Set release for ${s.name}`}>Set release</Button>
                    <Button small disabled={!allowed || running || !s.release_version} onClick={() => setDlg({ site: s, mode: 'rollback' })} aria-label={`Roll back ${s.name}`}>Roll back</Button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {sites.some((s) => s.canary_state === 'failed') ? <p class="banner banner-fail" role="alert"><span>A canary failed its health checks and halted a rollout. Roll that site back, or fix the canary host and set the release again.</span></p> : null}
      {dlg ? <ReleaseTargetDialog site={dlg.site} mode={dlg.mode} onClose={() => setDlg(null)} /> : null}
    </>
  );
}

export function ReleasesPage({ me }: { me: Me | undefined }): JSX.Element {
  const rels = useResource<Page<Release>>(ep.releases, { paged: true });
  const sites = useResource<Page<Site>>(ep.sites, { paged: true });
  const allowed = canAdmin(me);
  return (
    <>
      <PageHeader title="Releases" sub="Signed releases the manager can roll out, and which version each site targets." />
      {!allowed ? <p class="banner banner-warn" role="status">Your role does not allow changes. Importing and rolling out need the admin role.</p> : null}
      <Panel title="Imported versions" id="rv">
        <Loadable loading={rels.loading} error={rels.data ? null : rels.error} onRetry={rels.refresh} what="releases"><ReleaseTable rels={rels.data?.items ?? []} /></Loadable>
      </Panel>
      <Panel title="Per-site target" id="rt">
        <Loadable loading={sites.loading} error={sites.data ? null : sites.error} onRetry={sites.refresh} what="sites"><SiteTargets sites={sites.data?.items ?? []} allowed={allowed} /></Loadable>
      </Panel>
      <div class="grid-2">
        <ImportPanel allowed={allowed} />
        <UploadPanel allowed={allowed} />
      </div>
    </>
  );
}
