// Outbound webhooks (alerts test, platform issue webhook). SR-15: https only, never private / loopback /
// link-local hosts, redirects are not followed, every call has a timeout, errors never echo the URL.
import { invalidRequest } from "../errors";

export type WebhookFormat = "slack" | "teams" | "json";

function privateV4(h: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  const c = Number(m[3]);
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

/** Webhook URL: https only, never private/loopback/link-local (SR-15). The WHATWG parser already
 *  normalises decimal / hex / octal IPv4 spellings to dotted form, so the checks below see the real address. */
export function validateWebhookUrl(raw: unknown): URL {
  if (typeof raw !== "string" || raw.length > 512) throw invalidRequest("webhook URL must be a string of at most 512 characters");
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw invalidRequest("webhook URL is not a valid URL");
  }
  if (u.protocol !== "https:") throw invalidRequest("webhook URL must be https");
  if (u.username || u.password) throw invalidRequest("webhook URL must not embed credentials");
  const h = u.hostname.toLowerCase().replace(/\.$/, "");
  const bad =
    h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".lan") ||
    h.includes(":") || // IPv6 literals are refused outright
    !h.includes(".") ||
    privateV4(h);
  if (bad) throw invalidRequest("webhook URL must not point at a private, loopback or link-local address");
  return u;
}

export interface SendResult {
  ok: boolean;
  http_status: number | null;
  error: string | null;
}

export function payloadFor(format: WebhookFormat, text: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  if (format === "slack") return { text };
  if (format === "teams") return { "@type": "MessageCard", "@context": "https://schema.org/extensions", summary: text.slice(0, 120), themeColor: "01A982", text };
  return { text, source: "exp-manager", ...extra };
}

export async function postWebhook(url: string, body: Record<string, unknown>, timeoutMs = 5000): Promise<SendResult> {
  try {
    validateWebhookUrl(url); // re-validated at send time (stored values predate rule changes)
  } catch {
    return { ok: false, http_status: null, error: "webhook URL is not allowed" };
  }
  try {
    const res = await fetch(url, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/json", "user-agent": "exp-manager" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    await res.body?.cancel().catch(() => undefined);
    const ok = res.status >= 200 && res.status < 300;
    return { ok, http_status: res.status, error: ok ? null : res.status >= 300 && res.status < 400 ? "redirect not followed" : `http ${res.status}` };
  } catch (e) {
    return { ok: false, http_status: null, error: e instanceof Error && e.name === "TimeoutError" ? "timeout" : "network error" };
  }
}
