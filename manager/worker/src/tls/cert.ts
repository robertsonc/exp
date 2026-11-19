// Provided dashboard TLS material: a minimal, bounded X.509 / PEM reader plus a proof-of-possession check.
// Only what the admin API needs: validity, subject, issuer, SAN, SHA-256 fingerprint and the SPKI. Every read is
// bounds-checked; malformed input throws TlsError (mapped to 422), never anything else. No dependency: DER is
// decoded here and the keys are checked with WebCrypto (import both, sign a random challenge, verify with the
// certificate's key).
import { sha256Hex } from "../util/encoding";

export class TlsError extends Error {}

export const MAX_CERT_PEM = 32 * 1024;
export const MAX_KEY_PEM = 8 * 1024;
const MAX_CHAIN = 5;
const MAX_DEPTH = 8;
const MAX_SAN = 64;

interface Tlv {
  tag: number;
  /** offset of the tag byte */
  off: number;
  /** content offsets in the buffer */
  start: number;
  end: number;
  /** offset just after this element */
  next: number;
}

function readTlv(b: Uint8Array, off: number, limit: number): Tlv {
  if (off + 2 > limit) throw new TlsError("truncated DER");
  const tag = b[off] as number;
  if ((tag & 0x1f) === 0x1f) throw new TlsError("unsupported DER tag");
  let len = b[off + 1] as number;
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3) throw new TlsError("unsupported DER length");
    if (p + n > limit) throw new TlsError("truncated DER");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (b[p + i] as number);
    p += n;
  }
  if (p + len > limit) throw new TlsError("DER length exceeds its container");
  return { tag, off, start: p, end: p + len, next: p + len };
}

function children(b: Uint8Array, t: Tlv, depth = 0): Tlv[] {
  if (depth > MAX_DEPTH) throw new TlsError("DER nested too deeply");
  const out: Tlv[] = [];
  let p = t.start;
  while (p < t.end) {
    const c = readTlv(b, p, t.end);
    out.push(c);
    p = c.next;
    if (out.length > 512) throw new TlsError("too many DER elements");
  }
  return out;
}

const expect = (t: Tlv | undefined, tag: number, what: string): Tlv => {
  if (!t || t.tag !== tag) throw new TlsError(`not a valid X.509 certificate (${what})`);
  return t;
};

function oidOf(b: Uint8Array, t: Tlv): string {
  expect(t, 0x06, "oid");
  const parts: number[] = [];
  let v = 0;
  for (let i = t.start; i < t.end; i++) {
    const x = b[i] as number;
    v = v * 128 + (x & 0x7f);
    if (!(x & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  const first = parts.shift() ?? 0;
  const a = first < 40 ? 0 : first < 80 ? 1 : 2;
  return [a, first - a * 40, ...parts].join(".");
}

const RDN_NAMES: Record<string, string> = {
  "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress",
};

const utf8 = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });
function strOf(b: Uint8Array, t: Tlv): string {
  // printable / utf8 / ia5 / teletex are all rendered as UTF-8 text (BMPString is UTF-16BE)
  if (t.tag === 0x1e) {
    let s = "";
    for (let i = t.start; i + 1 < t.end; i += 2) s += String.fromCharCode(((b[i] as number) << 8) | (b[i + 1] as number));
    return s;
  }
  return utf8.decode(b.subarray(t.start, t.end));
}
/** strip control characters so a hostile certificate cannot inject anything odd into audit / UI text */
const clean = (s: string): string => s.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, 256);

function nameOf(b: Uint8Array, t: Tlv): string {
  expect(t, 0x30, "name");
  const parts: string[] = [];
  for (const set of children(b, t)) {
    expect(set, 0x31, "rdn");
    for (const atv of children(b, set)) {
      const [o, v] = children(b, expect(atv, 0x30, "atv"));
      if (!o || !v) throw new TlsError("not a valid X.509 certificate (rdn)");
      const oid = oidOf(b, o);
      parts.push(`${RDN_NAMES[oid] ?? oid}=${clean(strOf(b, v))}`);
    }
  }
  return parts.join(", ");
}

function timeOf(b: Uint8Array, t: Tlv): number {
  const s = new TextDecoder().decode(b.subarray(t.start, t.end));
  let m: RegExpExecArray | null;
  if (t.tag === 0x17) m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s);
  else if (t.tag === 0x18) m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s);
  else throw new TlsError("not a valid X.509 certificate (validity)");
  if (!m) throw new TlsError("not a valid X.509 certificate (validity format)");
  let y = Number(m[1]);
  if (t.tag === 0x17) y += y >= 50 ? 1900 : 2000;
  const ms = Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  if (!Number.isFinite(ms)) throw new TlsError("not a valid X.509 certificate (validity)");
  return ms;
}

function ipText(raw: Uint8Array): string {
  if (raw.length === 4) return Array.from(raw).join(".");
  if (raw.length === 16) {
    const g: string[] = [];
    for (let i = 0; i < 16; i += 2) g.push((((raw[i] as number) << 8) | (raw[i + 1] as number)).toString(16));
    return g.join(":");
  }
  return "";
}

export interface CertInfo {
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  /** upper-case colon hex, the format the dashboard reports as tls_fingerprint_sha256 */
  sha256: string;
  san: string[];
  /** SubjectPublicKeyInfo DER */
  spki: Uint8Array;
  spki_alg: string;
  /** EC named curve OID, when the key is an EC key */
  ec_curve: string | null;
  not_after_ms: number;
  not_before_ms: number;
}

const EXT_SAN = "2.5.29.17";
export const OID_RSA = "1.2.840.113549.1.1.1";
export const OID_EC = "1.2.840.10045.2.1";
const CURVES: Record<string, { name: "P-256" | "P-384" | "P-521" }> = {
  "1.2.840.10045.3.1.7": { name: "P-256" },
  "1.3.132.0.34": { name: "P-384" },
  "1.3.132.0.35": { name: "P-521" },
};

export async function parseCertDer(der: Uint8Array): Promise<CertInfo> {
  const cert = expect(readTlv(der, 0, der.length), 0x30, "certificate");
  if (cert.next !== der.length) throw new TlsError("trailing data after the certificate");
  const top = children(der, cert);
  const tbs = expect(top[0], 0x30, "tbsCertificate");
  const f = children(der, tbs);
  let i = 0;
  if (f[i]?.tag === 0xa0) i++; // version
  expect(f[i++], 0x02, "serial");
  expect(f[i++], 0x30, "signature algorithm");
  const issuer = nameOf(der, f[i++] as Tlv);
  const validity = children(der, expect(f[i++], 0x30, "validity"));
  const notBefore = timeOf(der, validity[0] as Tlv);
  const notAfter = timeOf(der, validity[1] as Tlv);
  const subject = nameOf(der, f[i++] as Tlv);
  const spkiT = expect(f[i++], 0x30, "subjectPublicKeyInfo");
  const spki = der.slice(spkiT.off, spkiT.next);
  const spkiParts = children(der, spkiT);
  const algParts = children(der, expect(spkiParts[0], 0x30, "spki algorithm"));
  const spkiAlg = oidOf(der, algParts[0] as Tlv);
  const curve = spkiAlg === OID_EC && algParts[1]?.tag === 0x06 ? oidOf(der, algParts[1]) : null;
  const san: string[] = [];
  for (; i < f.length; i++) {
    const t = f[i] as Tlv;
    if (t.tag !== 0xa3) continue;
    const exts = children(der, expect(children(der, t)[0], 0x30, "extensions"));
    for (const e of exts) {
      const ep = children(der, expect(e, 0x30, "extension"));
      if (oidOf(der, ep[0] as Tlv) !== EXT_SAN) continue;
      const oct = expect(ep[ep.length - 1], 0x04, "san value");
      const seq = expect(readTlv(der, oct.start, oct.end), 0x30, "san");
      for (const g of children(der, seq)) {
        if (san.length >= MAX_SAN) break;
        const raw = der.subarray(g.start, g.end);
        if (g.tag === 0x82) san.push(clean(utf8.decode(raw)));
        else if (g.tag === 0x87) {
          const ip = ipText(raw);
          if (ip) san.push(ip);
        } else if (g.tag === 0x81) san.push(clean(utf8.decode(raw)));
        else if (g.tag === 0x86) san.push(clean(utf8.decode(raw)));
      }
    }
  }
  const hex = (await sha256Hex(der)).toUpperCase();
  return {
    subject,
    issuer,
    not_before: new Date(notBefore).toISOString().replace(/\.\d{3}Z$/, "Z"),
    not_after: new Date(notAfter).toISOString().replace(/\.\d{3}Z$/, "Z"),
    sha256: hex.match(/../g)!.join(":"),
    san,
    spki,
    spki_alg: spkiAlg,
    ec_curve: curve,
    not_after_ms: notAfter,
    not_before_ms: notBefore,
  };
}

// ---- PEM ----------------------------------------------------------------------------------------------------------
export function pemBlocks(pem: string, label: string): Uint8Array[] {
  const out: Uint8Array[] = [];
  const re = new RegExp(`-----BEGIN ${label}-----([A-Za-z0-9+/=\\s]*)-----END ${label}-----`, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem))) {
    const b64 = (m[1] as string).replace(/\s+/g, "");
    if (b64.length === 0 || b64.length % 4 !== 0 || b64.length > 40000) throw new TlsError(`malformed ${label} PEM`);
    try {
      const bin = atob(b64);
      const u = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
      out.push(u);
    } catch {
      throw new TlsError(`malformed ${label} PEM`);
    }
    if (out.length > MAX_CHAIN) throw new TlsError(`at most ${MAX_CHAIN} certificates are accepted`);
  }
  return out;
}

const der = (tag: number, ...parts: Uint8Array[]): Uint8Array => {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const hdr = len < 128 ? [tag, len] : len < 256 ? [tag, 0x81, len] : [tag, 0x82, len >> 8, len & 255];
  const out = new Uint8Array(hdr.length + len);
  out.set(hdr, 0);
  let o = hdr.length;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const OID_BYTES: Record<string, number[]> = {
  [OID_RSA]: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
  [OID_EC]: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
  "1.2.840.10045.3.1.7": [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
  "1.3.132.0.34": [0x2b, 0x81, 0x04, 0x00, 0x22],
  "1.3.132.0.35": [0x2b, 0x81, 0x04, 0x00, 0x23],
};
const oidDer = (oid: string): Uint8Array => der(0x06, new Uint8Array(OID_BYTES[oid] as number[]));

/** Returns PKCS#8 DER for "PRIVATE KEY", "RSA PRIVATE KEY" and "EC PRIVATE KEY" PEMs; refuses anything else. */
export function privateKeyPkcs8(pem: string, certAlg: string, certCurve: string | null): Uint8Array {
  if (/-----BEGIN ENCRYPTED PRIVATE KEY-----|Proc-Type:\s*4,ENCRYPTED/.test(pem)) throw new TlsError("the private key must not be passphrase-protected");
  const p8 = pemBlocks(pem, "PRIVATE KEY");
  const rsa = pemBlocks(pem, "RSA PRIVATE KEY");
  const ec = pemBlocks(pem, "EC PRIVATE KEY");
  const n = p8.length + rsa.length + ec.length;
  if (n !== 1) throw new TlsError("exactly one PEM private key (PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY) is required");
  if (p8[0]) {
    const t = expect(readTlv(p8[0], 0, p8[0].length), 0x30, "pkcs8");
    if (t.next !== p8[0].length) throw new TlsError("malformed private key");
    return p8[0];
  }
  if (rsa[0]) {
    if (certAlg !== OID_RSA) throw new TlsError("the private key does not match the certificate (key type)");
    expect(readTlv(rsa[0], 0, rsa[0].length), 0x30, "rsa key");
    return der(0x30, der(0x02, new Uint8Array([0])), der(0x30, oidDer(OID_RSA), der(0x05, new Uint8Array())), der(0x04, rsa[0]));
  }
  const k = ec[0] as Uint8Array;
  expect(readTlv(k, 0, k.length), 0x30, "ec key");
  if (certAlg !== OID_EC || !certCurve || !OID_BYTES[certCurve]) throw new TlsError("the private key does not match the certificate (key type)");
  return der(0x30, der(0x02, new Uint8Array([0])), der(0x30, oidDer(OID_EC), oidDer(certCurve)), der(0x04, k));
}

export interface ProvidedTls {
  info: CertInfo;
  chain: number;
}

/** Validates a cert (+ optional chain) and key pair. Throws TlsError with a message safe to show to the admin. */
export async function validateProvidedTls(certPem: string, keyPem: string, now: number = Date.now()): Promise<ProvidedTls> {
  if (certPem.length > MAX_CERT_PEM) throw new TlsError(`cert_pem exceeds ${MAX_CERT_PEM / 1024} KiB`);
  if (keyPem.length > MAX_KEY_PEM) throw new TlsError(`key_pem exceeds ${MAX_KEY_PEM / 1024} KiB`);
  const blocks = pemBlocks(certPem, "CERTIFICATE");
  if (blocks.length === 0) throw new TlsError("cert_pem holds no PEM CERTIFICATE");
  const infos: CertInfo[] = [];
  for (const b of blocks) infos.push(await parseCertDer(b));
  const leaf = infos[0] as CertInfo;
  if (leaf.not_after_ms <= now) throw new TlsError(`the certificate expired on ${leaf.not_after}`);
  if (leaf.not_before_ms > now + 86400_000) throw new TlsError(`the certificate is not valid before ${leaf.not_before}`);
  let alg: { name: string; hash: string } | { name: string; namedCurve: string };
  let sign: { name: string; hash?: string };
  if (leaf.spki_alg === OID_RSA) {
    alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    sign = { name: "RSASSA-PKCS1-v1_5" };
  } else if (leaf.spki_alg === OID_EC && leaf.ec_curve && CURVES[leaf.ec_curve]) {
    alg = { name: "ECDSA", namedCurve: CURVES[leaf.ec_curve]!.name };
    sign = { name: "ECDSA", hash: "SHA-256" };
  } else throw new TlsError("unsupported certificate key type (RSA and ECDSA P-256/P-384/P-521 are supported)");
  const pkcs8 = privateKeyPkcs8(keyPem, leaf.spki_alg, leaf.ec_curve);
  let priv: CryptoKey;
  try {
    priv = await crypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
  } catch {
    throw new TlsError("the private key could not be read, or its type does not match the certificate");
  }
  let pub: CryptoKey;
  try {
    pub = await crypto.subtle.importKey("spki", leaf.spki, alg, false, ["verify"]);
  } catch {
    throw new TlsError("the certificate public key could not be read");
  }
  // proof of possession: sign a fresh random challenge with the private key, verify with the certificate's key
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  let ok = false;
  try {
    const sig = await crypto.subtle.sign(sign, priv, challenge);
    ok = await crypto.subtle.verify(sign, pub, sig, challenge);
  } catch {
    ok = false;
  }
  if (!ok) throw new TlsError("the private key does not match the certificate");
  return { info: leaf, chain: infos.length };
}
