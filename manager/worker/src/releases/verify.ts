// Release verification and import (05-manager.md section 9, 01-contracts.md section 10, SR-8).
//  1. Ed25519 signature over the EXACT manifest bytes against RELEASE_PUBKEY_PEM (WebCrypto)
//  2. manifest schema + consistency (artifact name <-> component/version/arch)
//  3. every artifact streamed to R2 while its sha256 and size are computed; compared with the manifest
//  4. only then rows are written, in one batch. ANY failure removes every R2 object written so far and
//     records nothing.
import { z } from "zod";
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { ApiError, invalidRequest, unavailable } from "../errors";
import { auditStmt } from "../audit/audit";
import { readLimited } from "../util/body";
import { b64ToBytes, bytesToHex, fromUtf8 } from "../util/encoding";
import { SEMVER_RE, newId } from "../util/ids";
import { isoNow } from "../util/time";

export const MAX_MANIFEST_BYTES = 256 * 1024;
export const MAX_SIG_BYTES = 4096;
export const MAX_ARTIFACT_BYTES = 250 * 1024 * 1024;
export const COMPONENTS = ["agent", "probe", "collector", "dashboard", "runner", "speedtest"] as const;

const ARTIFACT_NAME = /^exp-(agent|probe|collector|dashboard|runner|speedtest)-([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?)-(amd64|arm64|noarch)\.tar\.gz$/;
const TS = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$/;

const ManifestSchema = z.object({
  schema: z.literal("exp.manifest/1"),
  version: z.string().regex(SEMVER_RE).max(64),
  created: z.string().regex(TS),
  min_agent_version: z.string().regex(SEMVER_RE).max(64),
  artifacts: z
    .array(
      z.object({
        name: z.string().max(128),
        component: z.enum(COMPONENTS),
        arch: z.enum(["amd64", "arm64", "noarch"]),
        sha256: z.string().regex(/^[0-9a-f]{64}$/),
        size: z.number().int().min(0).max(MAX_ARTIFACT_BYTES),
      }),
    )
    .min(1)
    .max(64),
  notes_url: z.string().max(512).regex(/^https:\/\/[^\s]+$/).optional(),
});
export type Manifest = z.infer<typeof ManifestSchema>;

export const releaseError = (status: number, code: string, message: string, details: Record<string, unknown> = {}): ApiError => new ApiError(status, code, message, details);

// ---- signature ----------------------------------------------------------------------------------
function spkiFromPem(pem: string): Uint8Array {
  const m = /^-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----\s*$/.exec((pem ?? "").trim());
  if (!m) throw unavailable("RELEASE_PUBKEY_PEM is not configured or not a public key PEM");
  try {
    return b64ToBytes((m[1] as string).replace(/\s+/g, ""));
  } catch {
    throw unavailable("RELEASE_PUBKEY_PEM is not valid base64");
  }
}

export async function importReleaseKey(env: Env): Promise<CryptoKey> {
  const der = spkiFromPem(env.RELEASE_PUBKEY_PEM);
  try {
    return await crypto.subtle.importKey("spki", der, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    throw unavailable("RELEASE_PUBKEY_PEM is not an Ed25519 public key");
  }
}

/** The signature file holds base64 text (contract) or, for uploads, the raw 64 bytes. */
export function signatureBytes(sig: Uint8Array): Uint8Array {
  if (sig.length === 64) return sig;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(sig).trim();
  } catch {
    throw releaseError(422, "signature_invalid", "signature file is neither raw nor base64");
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) throw releaseError(422, "signature_invalid", "signature is not base64");
  let raw: Uint8Array;
  try {
    raw = b64ToBytes(text);
  } catch {
    throw releaseError(422, "signature_invalid", "signature is not base64");
  }
  if (raw.length !== 64) throw releaseError(422, "signature_invalid", "an Ed25519 signature is 64 bytes");
  return raw;
}

export async function verifyManifestSignature(env: Env, manifest: Uint8Array, sigFile: Uint8Array): Promise<string> {
  if (manifest.length === 0 || manifest.length > MAX_MANIFEST_BYTES) throw releaseError(422, "manifest_invalid", "manifest is empty or too large");
  if (sigFile.length === 0 || sigFile.length > MAX_SIG_BYTES) throw releaseError(422, "signature_invalid", "signature file is empty or too large");
  const key = await importReleaseKey(env);
  const sig = signatureBytes(sigFile);
  let ok = false;
  try {
    ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, manifest);
  } catch {
    ok = false;
  }
  if (!ok) throw releaseError(422, "signature_invalid", "manifest signature does not verify against the release public key");
  // the stored signature is canonical base64 whatever form was uploaded
  let s = "";
  for (const b of sig) s += String.fromCharCode(b);
  return btoa(s);
}

export function parseManifest(bytes: Uint8Array): Manifest {
  let raw: unknown;
  try {
    raw = JSON.parse(fromUtf8(bytes));
  } catch {
    throw releaseError(422, "manifest_invalid", "manifest is not valid JSON");
  }
  const p = ManifestSchema.safeParse(raw);
  if (!p.success) {
    throw releaseError(422, "manifest_invalid", "manifest failed schema validation", {
      errors: p.error.issues.slice(0, 10).map((i) => ({ path: "/" + i.path.map(String).join("/"), message: i.message.slice(0, 160) })),
    });
  }
  const m = p.data;
  const seen = new Set<string>();
  for (const a of m.artifacts) {
    const nm = ARTIFACT_NAME.exec(a.name);
    if (!nm || nm[1] !== a.component || nm[2] !== m.version || nm[3] !== a.arch) {
      throw releaseError(422, "manifest_invalid", `artifact name ${a.name.slice(0, 100)} does not match its component, arch and the manifest version`);
    }
    if (seen.has(a.name)) throw releaseError(422, "manifest_invalid", `duplicate artifact ${a.name}`);
    seen.add(a.name);
  }
  return m;
}

// ---- streaming artifacts into R2 ----------------------------------------------------------------
/** Streams `body` into R2 at `key`, hashing on the way. Returns the measured sha256 and size. */
export async function putVerified(env: Env, key: string, body: ReadableStream<Uint8Array>, expectedSize: number): Promise<{ sha256: string; size: number }> {
  const [forHash, forStore] = body.tee();
  const digest = new crypto.DigestStream("SHA-256");
  const hashing = forHash.pipeTo(digest);
  let counted = 0;
  const counter = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, ctl) {
      counted += chunk.byteLength;
      if (counted > expectedSize) throw new Error("artifact is larger than the manifest size");
      ctl.enqueue(chunk);
    },
  });
  // R2 needs a known length for a stream: FixedLengthStream also fails the write when the size differs
  const fixed = new FixedLengthStream(expectedSize);
  const [put] = await Promise.allSettled([env.ARTIFACTS.put(key, forStore.pipeThrough(counter).pipeThrough(fixed)), hashing]);
  const hashDone = await hashing.then(() => true, () => false);
  if (put.status === "rejected" || !hashDone || counted !== expectedSize) {
    throw releaseError(422, "artifact_hash_mismatch", "artifact size differs from the manifest or the transfer failed");
  }
  return { sha256: bytesToHex(new Uint8Array(await digest.digest)), size: counted };
}

export interface ArtifactSource {
  name: string;
  open: () => Promise<ReadableStream<Uint8Array>>;
}

export interface StoreResult {
  rel_id: string;
  version: string;
}

/**
 * Verifies and stores a release. `sources` supplies the bytes of each artifact by name. Nothing is recorded
 * (rows or R2 objects) unless EVERYTHING verified.
 */
export async function storeRelease(
  env: Env,
  actor: { email: string; ip?: string | null },
  source: "github" | "upload",
  manifestBytes: Uint8Array,
  sigFile: Uint8Array,
  sources: Map<string, ArtifactSource>,
): Promise<StoreResult> {
  const signature = await verifyManifestSignature(env, manifestBytes, sigFile);
  const manifest = parseManifest(manifestBytes);
  const exists = await env.DB.prepare("SELECT 1 AS x FROM releases WHERE version = ?1").bind(manifest.version).first();
  if (exists) throw new ApiError(409, "release_exists", `release ${manifest.version} is already imported`);
  for (const a of manifest.artifacts) if (!sources.has(a.name)) throw releaseError(422, "artifact_missing", `artifact ${a.name} was not provided`);
  for (const n of sources.keys()) if (!manifest.artifacts.some((a) => a.name === n)) throw releaseError(422, "artifact_unexpected", `artifact ${n.slice(0, 100)} is not in the manifest`);

  const relId = newId("rel_");
  const written: string[] = [];
  const cleanup = async (): Promise<void> => {
    for (const k of written) await env.ARTIFACTS.delete(k).catch(() => undefined);
  };
  try {
    const rows: Array<{ id: string; key: string; a: Manifest["artifacts"][number] }> = [];
    for (const a of manifest.artifacts) {
      const id = newId("art_");
      const key = `artifacts/${id}`;
      const src = sources.get(a.name) as ArtifactSource;
      written.push(key);
      const got = await putVerified(env, key, await src.open(), a.size);
      if (got.sha256 !== a.sha256 || got.size !== a.size) {
        throw releaseError(422, "artifact_hash_mismatch", `artifact ${a.name} does not match the sha256 in the signed manifest`, { artifact: a.name });
      }
      rows.push({ id, key, a });
    }
    const manifestKey = `releases/${manifest.version}/${relId}/manifest.json`;
    written.push(manifestKey);
    await env.ARTIFACTS.put(manifestKey, manifestBytes);
    const now = isoNow();
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO releases (version, org_id, manifest_r2_key, signature, min_agent_version, verified_at, source, notes_url, rel_id, manifest_created, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?6, ?6)`,
      ).bind(manifest.version, DEFAULT_ORG, manifestKey, signature, manifest.min_agent_version, now, source, manifest.notes_url ?? null, relId, manifest.created),
      ...rows.map((r) =>
        env.DB.prepare(
          `INSERT INTO artifacts (artifact_id, org_id, version, name, component, arch, sha256, size, r2_key, created_at, updated_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)`,
        ).bind(r.id, DEFAULT_ORG, manifest.version, r.a.name, r.a.component, r.a.arch, r.a.sha256, r.a.size, r.key, now),
      ),
      auditStmt(env.DB, { actor: actor.email, action: source === "github" ? "release.import" : "release.upload", resource: `release:${manifest.version}`, details: { artifacts: rows.length, source }, ip: actor.ip }),
    ]);
  } catch (e) {
    await cleanup();
    if (e instanceof ApiError) throw e;
    if (e instanceof Error && /UNIQUE|constraint/i.test(e.message)) throw new ApiError(409, "release_exists", `release ${manifest.version} is already imported`);
    console.error("release store failed", e instanceof Error ? e.name : "error");
    throw new ApiError(502, "release_store_failed", "storing the release failed; nothing was recorded");
  }
  return { rel_id: relId, version: manifest.version };
}

// ---- GitHub import ----------------------------------------------------------------------------------
const GH_API = "https://api.github.com";
const GH_HOSTS = (h: string): boolean => h === "api.github.com" || h === "github.com" || h.endsWith(".githubusercontent.com");

async function ghFetch(env: Env, url: string, accept: string, hops = 4): Promise<Response> {
  const u = new URL(url);
  if (u.protocol !== "https:" || !GH_HOSTS(u.hostname)) throw new ApiError(502, "github_error", "refusing to fetch from an unexpected host");
  const headers: Record<string, string> = { accept, "user-agent": "exp-manager", "x-github-api-version": "2022-11-28" };
  // the token only ever goes to the GitHub API host, never along a redirect to a CDN
  if (env.GITHUB_TOKEN && u.hostname === "api.github.com") headers.authorization = `Bearer ${env.GITHUB_TOKEN}`;
  let res: Response;
  try {
    res = await fetch(url, { headers, redirect: "manual", signal: AbortSignal.timeout(30_000) });
  } catch {
    throw new ApiError(502, "github_error", "could not reach GitHub");
  }
  if ([301, 302, 303, 307, 308].includes(res.status)) {
    const loc = res.headers.get("location");
    await res.body?.cancel().catch(() => undefined);
    if (!loc || hops <= 0) throw new ApiError(502, "github_error", "too many redirects from GitHub");
    return ghFetch(env, new URL(loc, url).toString(), accept, hops - 1);
  }
  return res;
}

async function ghBytes(env: Env, url: string, max: number): Promise<Uint8Array> {
  const res = await ghFetch(env, url, "application/octet-stream");
  if (!res.ok) throw new ApiError(res.status === 404 ? 404 : 502, res.status === 404 ? "not_found" : "github_error", `GitHub answered ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length > max) throw releaseError(413, "payload_too_large", "file exceeds the allowed size");
  return buf;
}

export async function importFromGithub(env: Env, actor: { email: string; ip?: string | null }, version: string): Promise<StoreResult> {
  if (!SEMVER_RE.test(version)) throw invalidRequest("version must be semver");
  const repo = (env.RELEASES_REPO ?? "").trim();
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new ApiError(409, "not_configured", "RELEASES_REPO is not configured (owner/repo)");
  const exists = await env.DB.prepare("SELECT 1 AS x FROM releases WHERE version = ?1").bind(version).first();
  if (exists) throw new ApiError(409, "release_exists", `release ${version} is already imported`);
  type GhRelease = { assets?: Array<{ name?: string; url?: string; size?: number }> };
  let rel = null as GhRelease | null;
  for (const tag of [`v${version}`, version]) {
    const res = await ghFetch(env, `${GH_API}/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`, "application/vnd.github+json");
    if (res.status === 404) {
      await res.body?.cancel().catch(() => undefined);
      continue;
    }
    if (!res.ok) throw new ApiError(502, "github_error", `GitHub answered ${res.status}`);
    rel = (await res.json()) as GhRelease;
    break;
  }
  if (!rel) throw new ApiError(404, "not_found", `no GitHub release for version ${version} in ${repo}`);
  const assets = new Map<string, string>();
  for (const a of rel.assets ?? []) if (typeof a.name === "string" && typeof a.url === "string") assets.set(a.name, a.url);
  const mUrl = assets.get(`exp-${version}-manifest.json`);
  const sUrl = assets.get(`exp-${version}-manifest.json.sig`);
  if (!mUrl || !sUrl) throw new ApiError(404, "not_found", "the GitHub release has no manifest or signature asset");
  const manifestBytes = await ghBytes(env, mUrl, MAX_MANIFEST_BYTES);
  const sigBytes = await ghBytes(env, sUrl, MAX_SIG_BYTES);
  // verify BEFORE downloading any artifact: a bad signature costs one small request
  await verifyManifestSignature(env, manifestBytes, sigBytes);
  const manifest = parseManifest(manifestBytes);
  const sources = new Map<string, ArtifactSource>();
  for (const a of manifest.artifacts) {
    const url = assets.get(a.name);
    if (!url) throw releaseError(422, "artifact_missing", `the GitHub release has no asset ${a.name}`);
    sources.set(a.name, {
      name: a.name,
      open: async () => {
        const res = await ghFetch(env, url, "application/octet-stream");
        if (!res.ok || !res.body) throw new ApiError(502, "github_error", `GitHub answered ${res.status} for ${a.name}`);
        return res.body;
      },
    });
  }
  return storeRelease(env, actor, "github", manifestBytes, sigBytes, sources);
}

// ---- upload -----------------------------------------------------------------------------------------
// The multipart body is parsed in memory (128 MB isolate): larger releases use the GitHub import, which streams.
export const MAX_UPLOAD_BYTES = 64 * 1024 * 1024;

export async function importFromUpload(env: Env, actor: { email: string; ip?: string | null }, req: Request): Promise<StoreResult> {
  const ct = req.headers.get("content-type") ?? "";
  if (!/^multipart\/form-data/i.test(ct)) throw new ApiError(415, "unsupported_media_type", "multipart/form-data required");
  // hard cap on the declared AND the actual size (a missing or lying content-length cannot bypass it)
  const bytes = await readLimited(req, MAX_UPLOAD_BYTES);
  let form: FormData;
  try {
    form = await new Response(bytes, { headers: { "content-type": ct } }).formData();
  } catch {
    throw invalidRequest("malformed multipart body");
  }
  const m = form.get("manifest");
  const s = form.get("signature");
  const arts = form.getAll("artifacts");
  if (!(m instanceof File) || !(s instanceof File)) throw invalidRequest("manifest and signature files are required");
  if (arts.length === 0 || arts.length > 64 || !arts.every((a): a is File => a instanceof File)) throw invalidRequest("one or more artifacts files are required");
  const sources = new Map<string, ArtifactSource>();
  for (const f of arts as File[]) {
    if (sources.has(f.name)) throw invalidRequest(`artifact ${f.name.slice(0, 100)} was uploaded twice`);
    sources.set(f.name, { name: f.name, open: async () => f.stream() as ReadableStream<Uint8Array> });
  }
  return storeRelease(env, actor, "upload", new Uint8Array(await m.arrayBuffer()), new Uint8Array(await s.arrayBuffer()), sources);
}
