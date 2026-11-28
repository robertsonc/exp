// The probe test-port picker, shared by the Add host wizard (step 3) and the probe's component page, so ports can be
// changed after enrolment without re-running the wizard. Writes the whole list with PUT /components/{id}/ports.
import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import type { Iface } from '../api/types';
import { DASH } from '../lib/format';
import { PROBE_M4_ROLE_NOTE, buildPorts, emptyDraft, ifaceBlockReason, type Cfg, type PortDraft, type PortRole, type WifiBand, type WifiSecurity } from '../lib/intent';
import { Button, EmptyState, StatusPill } from './atoms';
import { FormError, failText } from './forms';

// Target ports are M4 (probe/README.md): the probe cannot serve them yet, so they are shown but not offered.
const ROLES: { v: PortRole; l: string; m4?: boolean }[] = [
  { v: 'none', l: 'Not used' }, { v: 'client', l: 'Client (DHCP)' },
  { v: 'target', l: `Target (serves tests), ${PROBE_M4_ROLE_NOTE}`, m4: true }, { v: 'wifi', l: 'Wi-Fi (open / OWE network)' },
];
const BAND_OPTS: { v: WifiBand; l: string }[] = [{ v: 'any', l: 'Any band' }, { v: '2.4', l: '2.4 GHz' }, { v: '5', l: '5 GHz' }, { v: '6', l: '6 GHz' }];
const SEC_OPTS: { v: WifiSecurity; l: string }[] = [{ v: 'auto', l: 'OWE, else open' }, { v: 'owe', l: 'OWE only' }, { v: 'open', l: 'Open only' }];

function IfaceRow({ i, d, ownProbe, onChange, disabled }: { i: Iface; d: PortDraft; ownProbe?: string | undefined; onChange: (d: PortDraft) => void; disabled?: boolean }): JSX.Element {
  const block = ifaceBlockReason(i, ownProbe);
  const label = `Test role for ${i.name}`;
  return (
    <tr class={block ? 'iface-blocked' : ''} data-iface={i.name} data-blocked={block ? 'true' : 'false'}>
      <th scope="row">{i.name}</th>
      <td class="mono">{i.mac ?? DASH}</td>
      <td><StatusPill state={i.state === 'up' ? 'ok' : i.state === 'down' ? 'fail' : 'unknown'} label={`link ${i.state}`} /></td>
      <td>{i.speed_mbps ? `${i.speed_mbps} Mb/s` : DASH}</td>
      <td>{(i.addrs ?? []).join(', ') || DASH}</td>
      <td class="iface-role">
        <select aria-label={label} value={block ? 'none' : d.role} disabled={!!block || disabled} onChange={(e) => onChange({ ...d, role: (e.currentTarget as HTMLSelectElement).value as PortRole })}>
          {/* an M4 role stays selectable only on a port that already has it, so it can be seen and changed away */}
          {ROLES.map((o) => <option key={o.v} value={o.v} disabled={!!o.m4 && d.role !== o.v}>{o.l}</option>)}
        </select>
        {block ? <span class="iface-reason" data-testid="iface-reason">{block}</span> : null}
        {!block && (d.role === 'client' || d.role === 'wifi') ? (
          <span class="iface-extra">
            <input type="text" aria-label={`Network for ${i.name}`} placeholder="network, e.g. hall-a (site board)" value={d.network} autocomplete="off" maxLength={64} disabled={disabled}
              onInput={(e) => onChange({ ...d, network: (e.currentTarget as HTMLInputElement).value })} />
            <label class="inline-check"><input type="checkbox" checked={d.reference} disabled={disabled} onChange={(e) => onChange({ ...d, reference: (e.currentTarget as HTMLInputElement).checked })} /> Out-of-band reference</label>
          </span>
        ) : null}
        {!block && d.role === 'target' ? (
          <span class="iface-extra">
            <input type="text" aria-label={`Target address for ${i.name}`} placeholder="10.1.0.250/24" value={d.address} autocomplete="off" disabled={disabled} onInput={(e) => onChange({ ...d, address: (e.currentTarget as HTMLInputElement).value })} />
            <input type="text" aria-label={`Gateway for ${i.name}`} placeholder="gateway 10.1.0.1" value={d.gateway} autocomplete="off" disabled={disabled} onInput={(e) => onChange({ ...d, gateway: (e.currentTarget as HTMLInputElement).value })} />
          </span>
        ) : null}
        {!block && d.role === 'wifi' ? (
          <span class="iface-extra">
            <input type="text" aria-label={`SSID for ${i.name}`} placeholder="SSID (required)" value={d.ssid} autocomplete="off" maxLength={32} required disabled={disabled} onInput={(e) => onChange({ ...d, ssid: (e.currentTarget as HTMLInputElement).value })} />
            <select aria-label={`Band for ${i.name}`} value={d.band} disabled={disabled} onChange={(e) => onChange({ ...d, band: (e.currentTarget as HTMLSelectElement).value as WifiBand })}>
              {BAND_OPTS.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}
            </select>
            <select aria-label={`Security for ${i.name}`} value={d.security} disabled={disabled} onChange={(e) => onChange({ ...d, security: (e.currentTarget as HTMLSelectElement).value as WifiSecurity })}>
              {SEC_OPTS.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}
            </select>
            <input type="text" aria-label={`Country for ${i.name}`} placeholder="country (e.g. NL)" value={d.country} autocomplete="off" maxLength={2} size={4} disabled={disabled} onInput={(e) => onChange({ ...d, country: (e.currentTarget as HTMLInputElement).value })} />
          </span>
        ) : null}
      </td>
    </tr>
  );
}

export function PortPicker({ hostName, ifaces, ownProbe, initial, applyLabel = 'Apply', allowed = true, requireOne = true, onApply }: {
  hostName: string; ifaces: Iface[]; ownProbe?: string | undefined; initial?: Record<string, PortDraft>; applyLabel?: string;
  allowed?: boolean; requireOne?: boolean; onApply: (ports: Cfg[]) => Promise<void>;
}): JSX.Element {
  const [drafts, setDrafts] = useState<Record<string, PortDraft>>(initial ?? {});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const built = buildPorts(ifaces, drafts, ownProbe);
  const problems = Object.entries(built.errors);
  const hasAny = built.ports.length > 0;
  const canApply = allowed && problems.length === 0 && (hasAny || !requireOne);
  const apply = async () => {
    if (!canApply || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onApply(built.ports);
    } catch (e) {
      setError(failText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      {ifaces.length === 0 ? <EmptyState title="No interfaces reported yet">The agent has not sent its interface list.</EmptyState> : (
        <div class="table-scroll">
          <table class="plain iface-table" data-testid="iface-picker">
            <caption class="sr-only">Network interfaces of {hostName}</caption>
            <thead><tr><th scope="col">Interface</th><th scope="col">MAC</th><th scope="col">Link</th><th scope="col">Speed</th><th scope="col">Addresses</th><th scope="col">Test role</th></tr></thead>
            <tbody>
              {ifaces.map((i) => (
                <IfaceRow key={i.name} i={i} d={drafts[i.name] ?? emptyDraft()} ownProbe={ownProbe} disabled={!allowed || busy} onChange={(d) => setDrafts((cur) => ({ ...cur, [i.name]: d }))} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p class="dim">A client port asks for an address by DHCP and measures like an attendee's device. Its <strong>network</strong> places it on the site lines board, one line per network; mark the port of an out-of-band path (its own DHCP, DNS and internet) as the <strong>reference</strong>, so an outside fault can be told from ours. The management interface is never available.</p>
      {problems.length ? <ul class="form-error" role="alert">{problems.map(([n, m]) => <li key={n}>{n}: {m}</li>)}</ul> : null}
      {requireOne && !hasAny && problems.length === 0 ? <p class="hint">Assign at least one interface to the probe.</p> : null}
      <FormError error={error} />
      <div class="dialog-actions"><Button variant="primary" disabled={!canApply || busy} onClick={() => void apply()}>{busy ? 'Applying…' : applyLabel}</Button></div>
    </>
  );
}
