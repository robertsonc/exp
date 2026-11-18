// SSO handoff (01-contracts.md section 12). The manager answers with a self-contained HTML document holding an
// auto-submitting form that POSTs `token` to https://<dashboard>/auth/sso. The UI never injects that HTML: it reads the
// two values out of it with strict patterns, validates them, and submits a form it builds itself. No HTML sink is used,
// the token is never placed in a URL, and an unexpected document cannot make the browser POST anywhere else.

export interface SsoHandoff { action: string; token: string }

const ENTITIES: Record<string, string> = { '&amp;': '&', '&quot;': '"', '&#x27;': "'", '&#39;': "'", '&lt;': '<', '&gt;': '>' };
const unescapeAttr = (v: string): string => v.replace(/&(?:amp|quot|#x27|#39|lt|gt);/g, (m) => ENTITIES[m] ?? m);

export function parseSsoForm(html: string): SsoHandoff | null {
  if (html.length > 16384) return null;
  const form = /<form\b[^>]*>/i.exec(html)?.[0];
  if (!form) return null;
  const method = /\smethod="([^"]*)"/i.exec(form)?.[1];
  const rawAction = /\saction="([^"]*)"/i.exec(form)?.[1];
  if (method?.toLowerCase() !== 'post' || rawAction === undefined) return null;
  const tokenInput = /<input\b[^>]*\sname="token"[^>]*>/i.exec(html)?.[0];
  const token = tokenInput ? /\svalue="([^"]*)"/i.exec(tokenInput)?.[1] : undefined;
  if (token === undefined || !/^[A-Za-z0-9_-]{4,2048}\.[A-Za-z0-9_-]{4,2048}\.[A-Za-z0-9_-]{4,2048}$/.test(token)) return null;
  let url: URL;
  try {
    url = new URL(unescapeAttr(rawAction));
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.pathname !== '/auth/sso' || url.search || url.hash || url.username || url.password) return null;
  return { action: url.toString(), token };
}

/**
 * Open the dashboard in a new window with a real form POST. The window is opened synchronously from the click (so
 * popup blockers allow it) and detached from this page before anything is sent to it.
 */
export function openSsoWindow(): { submit: (h: SsoHandoff) => void; cancel: () => void } {
  const name = `exp-sso-${Math.random().toString(36).slice(2)}`;
  const w = window.open('about:blank', name);
  if (w) w.opener = null;
  return {
    submit(h: SsoHandoff) {
      const form = document.createElement('form');
      form.method = 'post';
      form.action = h.action;
      form.target = w ? name : '_blank';
      form.style.display = 'none';
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'token';
      input.value = h.token;
      form.appendChild(input);
      document.body.appendChild(form);
      form.submit();
      document.body.removeChild(form);
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
