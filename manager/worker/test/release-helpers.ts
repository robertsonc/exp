// Throwaway Ed25519 release keys + signed manifests for the release tests (never real keys, never on disk).
import { bytesToB64, sha256Hex } from "../src/util/encoding";

export interface TestRelease {
  version: string;
  manifest: Uint8Array;
  sig: string;
  artifacts: Array<{ name: string; component: string; arch: string; bytes: Uint8Array }>;
}

export interface ReleaseKey {
  pem: string;
  sign: (data: Uint8Array) => Promise<string>;
}

export async function makeReleaseKey(): Promise<ReleaseKey> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer);
  const b64 = bytesToB64(spki).replace(/(.{64})/g, "$1\n").trim();
  return {
    pem: `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`,
    sign: async (data) => bytesToB64(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, data))),
  };
}

export async function buildRelease(
  key: ReleaseKey,
  version: string,
  parts: Array<{ component: string; arch: string }> = [{ component: "agent", arch: "noarch" }, { component: "probe", arch: "noarch" }],
  over: Record<string, unknown> = {},
): Promise<TestRelease> {
  const artifacts = parts.map((p) => ({
    name: `exp-${p.component}-${version}-${p.arch}.tar.gz`,
    component: p.component,
    arch: p.arch,
    bytes: new TextEncoder().encode(`tarball bytes of ${p.component} ${p.arch} ${version}\n`.repeat(50)),
  }));
  const body = {
    schema: "exp.manifest/1",
    version,
    created: "2026-11-18T20:00:00Z",
    min_agent_version: "0.1.0",
    artifacts: await Promise.all(artifacts.map(async (a) => ({ name: a.name, component: a.component, arch: a.arch, sha256: await sha256Hex(a.bytes), size: a.bytes.length }))),
    notes_url: `https://github.com/acme/exp/releases/tag/v${version}`,
    ...over,
  };
  const manifest = new TextEncoder().encode(JSON.stringify(body, null, 2) + "\n");
  return { version, manifest, sig: await key.sign(manifest), artifacts };
}

const GH_REPO = "acme/exp";
export const GH_ASSET = (n: number): string => `https://api.github.com/repos/${GH_REPO}/releases/assets/${n}`;

/** A fetch handler that serves `rel` the way the GitHub API does (asset downloads redirect to a CDN host). */
export function githubHandler(rel: TestRelease, tweak: { manifest?: Uint8Array; sig?: string; artifacts?: Record<string, Uint8Array> } = {}) {
  const files = new Map<number, Uint8Array>();
  const assets: Array<{ name: string; url: string }> = [];
  let n = 100;
  const add = (name: string, bytes: Uint8Array): void => {
    files.set(++n, bytes);
    assets.push({ name, url: GH_ASSET(n) });
  };
  add(`exp-${rel.version}-manifest.json`, tweak.manifest ?? rel.manifest);
  add(`exp-${rel.version}-manifest.json.sig`, new TextEncoder().encode(tweak.sig ?? rel.sig));
  for (const a of rel.artifacts) add(a.name, tweak.artifacts?.[a.name] ?? a.bytes);
  return (url: string): Response | undefined => {
    if (url === `https://api.github.com/repos/${GH_REPO}/releases/tags/v${rel.version}`) return new Response(JSON.stringify({ tag_name: `v${rel.version}`, assets }), { headers: { "content-type": "application/json" } });
    if (url.startsWith("https://api.github.com/repos/") && url.includes("/releases/tags/")) return new Response("{}", { status: 404 });
    const m = /\/releases\/assets\/(\d+)$/.exec(url);
    if (m && url.startsWith("https://api.github.com/")) return new Response(null, { status: 302, headers: { location: `https://objects.githubusercontent.com/blob/${m[1]}` } });
    const c = /^https:\/\/objects\.githubusercontent\.com\/blob\/(\d+)$/.exec(url);
    if (c) {
      const f = files.get(Number(c[1]));
      return f ? new Response(f, { status: 200 }) : new Response("gone", { status: 404 });
    }
    return undefined;
  };
}
