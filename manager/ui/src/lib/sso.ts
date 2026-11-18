// SSO handoff (01-contracts.md section 12, 05-manager.md section 10). The SPA's CSP pins form-action to 'self', so the UI
// never builds or submits the token form. It asks the manager for a short-lived same-origin launch URL (POST
// dashboards/{id}/sso/launch, with the CSRF header) and navigates a new window to it; the manager answers that GET with the
// auto-submitting form page under its own CSP (form-action pinned to the dashboard origin). The token never touches a URL.

/** A launch URL is only ever followed when it is a same-origin path under the admin API's dashboards. */
export function isLaunchUrl(u: unknown): u is string {
  return typeof u === 'string' && /^\/api\/admin\/v1\/dashboards\/[A-Za-z0-9._~%-]{1,128}\/sso\/page\?n=\d{10}\.[A-Za-z0-9_-]{43}$/.test(u);
}

/**
 * Open the dashboard in a new window. The window is opened synchronously from the click (so popup blockers allow it),
 * detached from this page, and navigated once the manager has issued the launch URL.
 */
export function openSsoWindow(): { go: (launchUrl: string) => boolean; cancel: () => void } {
  const w = window.open('about:blank', `exp-sso-${Math.random().toString(36).slice(2)}`);
  if (w) w.opener = null;
  return {
    go(launchUrl: string) {
      if (!isLaunchUrl(launchUrl)) return false;
      if (w) w.location.href = launchUrl;
      else window.open(launchUrl, '_blank', 'noopener');
      return true;
    },
    cancel() {
      w?.close();
    },
  };
}

/** The NOC URL an operator pastes onto a wall display: the token travels in the fragment, never in a query string. */
export function nocUrl(dashUrl: string | null | undefined, token: string): string | null {
  if (!dashUrl) return null;
  try {
    const u = new URL(dashUrl);
    if (u.protocol !== 'https:') return null;
    return `${u.origin}/noc#t=${token}`;
  } catch {
    return null;
  }
}
