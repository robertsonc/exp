// GET /install.sh: public, static, no secrets. The bundled agent bootstrap with three placeholders
// substituted at serve time. Every substituted value is validated first: this script is piped to a shell.
import { INSTALL_SH } from "../../.generated/install-sh";
import type { Env } from "../env";
import { ApiError } from "../errors";
import { SEMVER_RE } from "../util/ids";

const PEM_RE = /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----\n?$/;

function managerUrl(req: Request): string {
  const u = new URL(req.url);
  const host = u.hostname;
  const local = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  if (u.protocol !== "https:" && !(local && u.protocol === "http:")) throw new ApiError(503, "unavailable", "manager URL is not https");
  if (!/^[A-Za-z0-9.-]+$/.test(host) && !local) throw new ApiError(503, "unavailable", "unsupported manager host name");
  return u.origin;
}

export async function latestVersion(env: Env): Promise<string> {
  const rows = await env.DB.prepare("SELECT version FROM releases").all<{ version: string }>();
  const parse = (v: string): number[] => v.split("-")[0]!.split(".").map(Number);
  const versions = (rows.results ?? []).map((r) => r.version).filter((v) => SEMVER_RE.test(v));
  versions.sort((a, b) => {
    const x = parse(a);
    const y = parse(b);
    for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
    return a.includes("-") === b.includes("-") ? 0 : a.includes("-") ? -1 : 1; // 1.0.0 > 1.0.0-rc1
  });
  return versions[versions.length - 1] ?? "";
}

export async function renderInstallSh(env: Env, req: Request): Promise<string> {
  const url = managerUrl(req);
  const version = await latestVersion(env);
  if (version && !SEMVER_RE.test(version)) throw new ApiError(503, "unavailable", "invalid release version");
  const pem = (env.RELEASE_PUBKEY_PEM ?? "").replace(/\r\n/g, "\n").trim();
  if (pem && !PEM_RE.test(pem + "\n")) throw new ApiError(503, "unavailable", "RELEASE_PUBKEY_PEM is not a public key PEM");
  // function replacers: the values are never interpreted as replacement patterns
  return INSTALL_SH.replaceAll("@@MANAGER_URL@@", () => url)
    .replaceAll("@@AGENT_VERSION@@", () => version)
    .replaceAll("@@RELEASE_PUBKEY_PEM@@", () => pem);
}
