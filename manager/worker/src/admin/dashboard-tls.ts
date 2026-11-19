// Provided dashboard TLS (05-manager.md section 8, 01-contracts.md section 9.3): PUT/GET /dashboards/{id}/tls.
// The certificate + key are stored as ONE encrypted secret (kind dashboard_tls, owner = the dashboard component,
// JSON {cert_pem, key_pem}); the API never returns the key (nor the PEM). The mode is derived from the secret's
// existence: no secret = self_signed. The compiler then emits tls.mode = provided and creds tls.crt / tls.key for
// that dashboard's host only.
import { z } from "zod";
import { auditStmt } from "../audit/audit";
import { recompile } from "../compile/recompile";
import { TLS_KIND } from "../compile/wiring";
import type { Env } from "../env";
import { ApiError, invalidRequest } from "../errors";
import { getSecretByOwner, prepareCreateSecret, prepareSetSecret, readSecret } from "../secrets/store";
import { MAX_CERT_PEM, MAX_KEY_PEM, TlsError, parseCertDer, pemBlocks, validateProvidedTls } from "../tls/cert";
import type { Actor } from "./service";

export const DashboardTlsPut = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("self_signed") }).strict(),
  // length caps here are slightly above the real limits so oversize is reported by the 422 check, not a generic 400
  z.object({ mode: z.literal("provided"), cert_pem: z.string().min(1).max(MAX_CERT_PEM * 2), key_pem: z.string().min(1).max(MAX_KEY_PEM * 2) }).strict(),
]);

const secretId = (componentId: string): string => `sec_${TLS_KIND}_${componentId}`;

export async function getDashboardTls(env: Env, dash: { component_id: string }) {
  const row = await getSecretByOwner(env, dash.component_id, TLS_KIND);
  if (!row) return { mode: "self_signed" as const, set: false, updated_at: null, cert: null };
  const j = JSON.parse(await readSecret(env, row)) as { cert_pem: string };
  const first = pemBlocks(j.cert_pem, "CERTIFICATE")[0];
  const info = first ? await parseCertDer(first) : null;
  return {
    mode: "provided" as const,
    set: true,
    updated_at: row.updated_at ?? null,
    cert: info ? { subject: info.subject, issuer: info.issuer, not_before: info.not_before, not_after: info.not_after, sha256: info.sha256, san: info.san } : null,
  };
}

export async function putDashboardTls(env: Env, actor: Actor, dash: { slug: string; component_id: string }, body: unknown) {
  const p = DashboardTlsPut.safeParse(body);
  if (!p.success) throw invalidRequest("request failed validation", { errors: p.error.issues.slice(0, 5).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })) });
  const host = await env.DB.prepare("SELECT host_id FROM components WHERE component_id = ?1").bind(dash.component_id).first<{ host_id: string }>();
  const stmts: D1PreparedStatement[] = [];
  const cur = await getSecretByOwner(env, dash.component_id, TLS_KIND);
  let details: Record<string, unknown>;
  if (p.data.mode === "provided") {
    let v;
    try {
      v = await validateProvidedTls(p.data.cert_pem, p.data.key_pem);
    } catch (e) {
      if (e instanceof TlsError) throw new ApiError(422, "invalid_config", e.message);
      throw e;
    }
    const plaintext = JSON.stringify({ cert_pem: p.data.cert_pem, key_pem: p.data.key_pem });
    if (cur) stmts.push(await prepareSetSecret(env, cur, plaintext));
    else stmts.push((await prepareCreateSecret(env, { ownerRef: dash.component_id, kind: TLS_KIND, plaintext, secretId: secretId(dash.component_id) })).stmt);
    details = { mode: "provided", sha256: v.info.sha256, not_after: v.info.not_after, subject: v.info.subject, chain: v.chain, secret_set: true };
  } else {
    if (cur) stmts.push(env.DB.prepare("DELETE FROM secrets WHERE secret_id = ?1").bind(cur.secret_id));
    details = { mode: "self_signed", secret_set: false };
  }
  stmts.push(auditStmt(env.DB, { actor: actor.email, action: "dashboard.tls", resource: `dashboard:${dash.slug}`, details, ip: actor.ip }));
  await env.DB.batch(stmts);
  if (host) await recompile(env, { hostIds: [host.host_id] });
  return getDashboardTls(env, dash);
}
