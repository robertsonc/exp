// Agent bearer authentication (05-manager.md section 8): current secret, or the previous one within its
// rotation grace; constant-time hash comparison; per-agent rate limit; failures throttled per IP.
import type { MiddlewareHandler } from "hono";
import type { AppBindings } from "../env";
import { invalidToken, rateLimited } from "../errors";
import { allowed, enforce } from "../ratelimit";
import { TOKEN_RE, hashesEqual, tokenHash } from "../secrets/tokens";
import { nowMs } from "../util/time";

interface CredRow {
  host_id: string;
  secret_hash: string;
  previous_hash: string | null;
  previous_valid_until: string | null;
  revoked_at: string | null;
  dv: number | null;
}

function bearer(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer ([^\s]+)$/.exec(header.trim());
  return m ? (m[1] as string) : null;
}

export const agentAuth: MiddlewareHandler<AppBindings> = async (c, next) => {
  const token = bearer(c.req.header("Authorization"));
  let host: { hostId: string; desiredVersion: number | null } | null = null;
  if (token && TOKEN_RE.expa.test(token)) {
    const h = await tokenHash(token);
    // ONE indexed read: credentials + the current desired version (the 304 hot path needs nothing else)
    const row = await c.env.DB.prepare(
      `SELECT c.host_id, c.secret_hash, c.previous_hash, c.previous_valid_until, c.revoked_at, d.version AS dv
         FROM agent_creds c LEFT JOIN desired_docs d ON d.host_id = c.host_id
        WHERE c.secret_hash = ?1 OR c.previous_hash = ?1`,
    )
      .bind(h)
      .first<CredRow>();
    if (row && !row.revoked_at) {
      const isCurrent = hashesEqual(row.secret_hash, h);
      const isPrev =
        !!row.previous_hash &&
        hashesEqual(row.previous_hash, h) &&
        !!row.previous_valid_until &&
        Date.parse(row.previous_valid_until) > nowMs();
      if (isCurrent || isPrev) host = { hostId: row.host_id, desiredVersion: row.dv };
    }
  }
  if (!host) {
    // repeated auth failures from one IP are throttled (shares the per-IP enrol budget, separate key)
    if (!(await allowed(c.env.RL_ENROL, `authfail:${c.get("ip")}`))) throw rateLimited(60);
    throw invalidToken();
  }
  await enforce(c.env.RL_AGENT, `agent:${host.hostId}`);
  c.set("agent", host);
  await next();
};
