import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import { mutateText } from '../data/hooks';
import { Button } from './atoms';
import { failText } from './forms';
import { notify } from './Toasts';
import { openSsoWindow, parseSsoForm } from '../lib/sso';

/**
 * "Open dashboard": asks the manager for a signed handoff (POST dashboards/{id}/sso) and submits the returned form to
 * the dashboard in a new window. The token only ever travels in a POST body.
 */
export function OpenDashboardButton({ dashId, primary, label = 'Open dashboard' }: { dashId: string; primary?: boolean; label?: string }): JSX.Element {
  const [busy, setBusy] = useState(false);
  const click = async () => {
    const win = openSsoWindow();
    setBusy(true);
    try {
      const html = await mutateText('POST', ep.sso(dashId));
      const handoff = parseSsoForm(html);
      if (!handoff) {
        win.cancel();
        notify('error', 'The manager sent an unexpected sign-in form, so the dashboard was not opened.');
        return;
      }
      win.submit(handoff);
    } catch (e) {
      win.cancel();
      notify('error', `Could not open ${dashId}: ${failText(e)}`);
    } finally {
      setBusy(false);
    }
  };
  return <Button variant={primary ? 'primary' : 'secondary'} disabled={busy} onClick={() => void click()} aria-label={`${label}: ${dashId}`}>{busy ? 'Opening…' : label}</Button>;
}
