// Throwaway X.509 certificates built at test time (no private key is ever committed): a tiny DER writer + WebCrypto
// signing. Self-signed, one SAN extension, caller-chosen validity.
import { bytesToB64 } from "../src/util/encoding";

const cat = (...a: Uint8Array[]): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(new ArrayBuffer(a.reduce((n, x) => n + x.length, 0)));
  let o = 0;
  for (const x of a) (out.set(x, o), (o += x.length));
  return out;
};
const tlv = (tag: number, ...p: Uint8Array[]): Uint8Array => {
  const body = cat(...p);
  const n = body.length;
  const hdr = n < 128 ? [tag, n] : n < 256 ? [tag, 0x81, n] : [tag, 0x82, n >> 8, n & 255];
  return cat(new Uint8Array(hdr), body);
};
const oid = (...b: number[]) => tlv(0x06, new Uint8Array(b));
const OID_CN = oid(0x55, 0x04, 0x03);
const OID_O = oid(0x55, 0x04, 0x0a);
const OID_SAN = oid(0x55, 0x1d, 0x11);
const OID_ECDSA_SHA256 = oid(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02);
const OID_RSA_SHA256 = oid(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b);
const str = (s: string) => new TextEncoder().encode(s);
const name = (cn: string, org?: string) =>
  tlv(0x30, ...(org ? [tlv(0x31, tlv(0x30, OID_O, tlv(0x0c, str(org))))] : []), tlv(0x31, tlv(0x30, OID_CN, tlv(0x0c, str(cn)))));
const utc = (d: Date) => tlv(0x17, str(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"));
const pem = (label: string, der: Uint8Array) => `-----BEGIN ${label}-----\n${bytesToB64(der).match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;

/** ECDSA signature from WebCrypto (r||s) to DER SEQUENCE { INTEGER r, INTEGER s } */
function ecSigDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if ((v[0] as number) & 0x80) v = cat(new Uint8Array([0]), v);
    return tlv(0x02, v);
  };
  return tlv(0x30, int(raw.slice(0, half)), int(raw.slice(half)));
}

export interface TestCert {
  certPem: string;
  keyPem: string; // PKCS#8
  keyDer: Uint8Array;
  certDer: Uint8Array;
  kind: "ec" | "rsa";
}

export interface CertOpts {
  kind?: "ec" | "rsa";
  cn?: string;
  org?: string;
  san?: Array<{ dns?: string; ip?: [number, number, number, number] }>;
  notBefore?: Date;
  notAfter?: Date;
  serial?: number;
}

export async function makeCert(o: CertOpts = {}): Promise<TestCert> {
  const kind = o.kind ?? "ec";
  const now = Date.now();
  const nb = o.notBefore ?? new Date(now - 86400_000);
  const na = o.notAfter ?? new Date(now + 365 * 86400_000);
  const pair =
    kind === "ec"
      ? ((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair)
      : ((await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey) as ArrayBuffer);
  const keyDer = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey) as ArrayBuffer);
  const sigAlg = kind === "ec" ? tlv(0x30, OID_ECDSA_SHA256) : tlv(0x30, OID_RSA_SHA256, tlv(0x05));
  const gn = (o.san ?? [{ dns: "dash.example.test" }, { ip: [10, 32, 98, 30] as [number, number, number, number] }]).map((g) => (g.dns ? tlv(0x82, str(g.dns)) : tlv(0x87, new Uint8Array(g.ip!))));
  const ext = tlv(0xa3, tlv(0x30, tlv(0x30, OID_SAN, tlv(0x04, tlv(0x30, ...gn)))));
  const subj = name(o.cn ?? "dash.example.test", o.org ?? "Example Events");
  const tbs = tlv(0x30, tlv(0xa0, tlv(0x02, new Uint8Array([2]))), tlv(0x02, new Uint8Array([o.serial ?? 7])), sigAlg, subj, tlv(0x30, utc(nb), utc(na)), subj, spki, ext);
  const sigRaw = new Uint8Array(await crypto.subtle.sign(kind === "ec" ? { name: "ECDSA", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5" }, pair.privateKey, tbs));
  const sig = kind === "ec" ? ecSigDer(sigRaw) : sigRaw;
  const certDer = tlv(0x30, tbs, sigAlg, tlv(0x03, cat(new Uint8Array([0]), sig)));
  return { certPem: pem("CERTIFICATE", certDer), keyPem: pem("PRIVATE KEY", keyDer), keyDer, certDer, kind };
}

export const pemOf = pem;

/** The algorithm-specific private key (SEC1 ECPrivateKey / PKCS#1 RSAPrivateKey) inside a PKCS#8 DER. */
export function unwrapPkcs8(d: Uint8Array): Uint8Array {
  const read = (o: number): { start: number; end: number } => {
    let len = d[o + 1] as number;
    let p = o + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + (d[p + i] as number);
      p += n;
    }
    return { start: p, end: p + len };
  };
  const top = read(0);
  const ver = read(top.start);
  const alg = read(ver.end);
  const oct = read(alg.end);
  return d.slice(oct.start, oct.end);
}
