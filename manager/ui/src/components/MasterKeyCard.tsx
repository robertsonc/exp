// Settings -> Master key: read-only progress of an EXP_MASTER_KEY rotation (05-manager.md section 6). Self-contained: it owns
// its fetch and renders nothing for roles that may not read it. Key ids are public identifiers, never key material.
import type { JSX } from 'preact';
import { ep } from '../api/endpoints';
import { useResource } from '../data/hooks';
import { Button, ErrorBanner, Panel, SkeletonBlock, StatusPill } from './atoms';

export interface MasterKeyStatus {
  current_key_id: string;
  previous_key_id: string | null;
  remaining_previous: number;
  unknown_key_rows?: number;
  safe_to_remove_previous: boolean;
}

export function MasterKeyView({ s }: { s: MasterKeyStatus }): JSX.Element {
  const unknown = s.unknown_key_rows ?? 0;
  const rotating = s.previous_key_id !== null;
  return (
    <>
      <p class="dim">Stored secrets are encrypted with EXP_MASTER_KEY. After a rotation the manager re-encrypts everything under the new key in the background (every 5 minutes).</p>
      <dl class="kv" data-testid="master-key-status">
        <dt>Current key id</dt>
        <dd><code>{s.current_key_id}</code></dd>
        <dt>Previous key id</dt>
        <dd>{s.previous_key_id ? <code>{s.previous_key_id}</code> : <span class="dim">none (no rotation in progress)</span>}</dd>
        <dt>Still sealed by the previous key</dt>
        <dd data-testid="master-key-remaining">{s.remaining_previous}</dd>
        {unknown > 0 ? (<><dt>Sealed by an unknown key</dt><dd>{unknown}</dd></>) : null}
      </dl>
      {unknown > 0 ? (
        <p class="banner banner-warn" role="status"><span>{unknown} stored value(s) were sealed by a key this manager does not have. Set EXP_MASTER_KEY_PREVIOUS to that key.</span></p>
      ) : null}
      {s.safe_to_remove_previous ? (
        <p><StatusPill state="ok" label={rotating ? 'Safe to remove EXP_MASTER_KEY_PREVIOUS' : 'Fully re-encrypted'} /></p>
      ) : (
        <p><StatusPill state="warn" label="Do not remove EXP_MASTER_KEY_PREVIOUS yet" /></p>
      )}
    </>
  );
}

export function MasterKeyCard({ admin }: { admin: boolean }): JSX.Element | null {
  const r = useResource<MasterKeyStatus>(admin ? `${ep.settings}/master-key` : null);
  if (!admin) return null;
  return (
    <Panel title="Master key" id="master-key">
      {r.loading && !r.data ? <SkeletonBlock rows={3} label="Loading master key status" /> : !r.data ? <ErrorBanner what="Could not load the master key status." message={r.error?.message} onRetry={r.refresh} /> : <MasterKeyView s={r.data} />}
      <p><Button onClick={r.refresh}>Refresh</Button></p>
    </Panel>
  );
}
