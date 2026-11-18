import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import { mutate } from '../data/hooks';
import { Button } from './atoms';
import { failText } from './forms';
import { notify } from './Toasts';
import { openSsoWindow } from '../lib/sso';

/**
 * "Open dashboard": asks the manager for a short-lived launch URL (POST dashboards/{id}/sso/launch) and navigates a new
 * window to it; the manager's page there POSTs the signed token to the dashboard. The token only ever travels in a POST body.
 */
export function OpenDashboardButton({ dashId, primary, label = 'Open dashboard' }: { dashId: string; primary?: boolean; label?: string }): JSX.Element {
  const [busy, setBusy] = useState(false);
  const click = async () => {
    const win = openSsoWindow();
    setBusy(true);
    try {
      const r = await mutate<{ url?: unknown }>('POST', ep.ssoLaunch(dashId));
      if (!win.go(String(r?.url))) {
        win.cancel();
        notify('error', 'The manager sent an unexpected launch link, so the dashboard was not opened.');
      }
    } catch (e) {
      win.cancel();
      notify('error', `Could not open ${dashId}: ${failText(e)}`);
    } finally {
      setBusy(false);
    }
  };
  return <Button variant={primary ? 'primary' : 'secondary'} disabled={busy} onClick={() => void click()} aria-label={`${label}: ${dashId}`}>{busy ? 'Opening…' : label}</Button>;
}
