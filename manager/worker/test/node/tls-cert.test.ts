// The minimal X.509 reader against certificates produced by the real openssl (not by our own test builder).
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { TlsError, parseCertDer, pemBlocks, validateProvidedTls } from "../../src/tls/cert";

const dir = mkdtempSync(join(tmpdir(), "exp-tls-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
const ossl = (...a: string[]): string => execFileSync("openssl", a, { encoding: "utf8", timeout: 60_000, stdio: ["ignore", "pipe", "pipe"] });

function make(name: string, keyArgs: string[], extra: string[] = []): { cert: string; key: string } {
  const c = join(dir, `${name}.crt`);
  const k = join(dir, `${name}.key`);
  ossl("req", "-x509", "-newkey", ...keyArgs, "-nodes", "-keyout", k, "-out", c, "-days", "90", "-subj", "/O=Event Co/CN=dash.example.test", "-addext", "subjectAltName=DNS:dash.example.test,DNS:*.example.test,IP:10.32.98.30,IP:fd00::1", ...extra);
  return { cert: readFileSync(c, "utf8"), key: readFileSync(k, "utf8") };
}

describe("openssl-generated certificates", () => {
  for (const [name, args] of [
    ["ec256", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]],
    ["ec384", ["ec", "-pkeyopt", "ec_paramgen_curve:P-384"]],
    ["rsa2048", ["rsa:2048"]],
  ] as Array<[string, string[]]>) {
    it(`${name}: fingerprint, subject, validity, SAN match openssl; key proves possession`, async () => {
      const { cert, key } = make(name, args);
      const info = await parseCertDer(pemBlocks(cert, "CERTIFICATE")[0]!);
      const fp = ossl("x509", "-in", join(dir, `${name}.crt`), "-noout", "-fingerprint", "-sha256").trim().split("=")[1];
      expect(info.sha256).toBe(fp);
      expect(info.subject).toBe("O=Event Co, CN=dash.example.test");
      expect(info.san).toEqual(["dash.example.test", "*.example.test", "10.32.98.30", "fd00:0:0:0:0:0:0:1"]);
      const endText = ossl("x509", "-in", join(dir, `${name}.crt`), "-noout", "-enddate").trim().split("=")[1]!;
      expect(info.not_after_ms).toBe(Date.parse(endText));
      const v = await validateProvidedTls(cert, key);
      expect(v.chain).toBe(1);
      // the same key must be refused against another certificate
      const other = make(`${name}-other`, args);
      await expect(validateProvidedTls(cert, other.key)).rejects.toThrow(TlsError);
    });
  }

  it("an openssl PKCS#1 RSA key and a SEC1 EC key are accepted", async () => {
    const r = make("rsa-legacy", ["rsa:2048"]);
    const rsaTrad = ossl("rsa", "-in", join(dir, "rsa-legacy.key"), "-traditional");
    expect(rsaTrad).toContain("BEGIN RSA PRIVATE KEY");
    await validateProvidedTls(r.cert, rsaTrad);
    const e = make("ec-legacy", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]);
    const sec1 = ossl("ec", "-in", join(dir, "ec-legacy.key"));
    expect(sec1).toContain("BEGIN EC PRIVATE KEY");
    await validateProvidedTls(e.cert, sec1);
  });

  it("an expired certificate is refused against an injected clock", async () => {
    const { cert, key } = make("clock", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]);
    await expect(validateProvidedTls(cert, key, Date.now() + 200 * 86400_000)).rejects.toThrow(/expired/);
  });
});

describe("hostile DER never throws anything but TlsError", () => {
  it("random and truncated inputs", async () => {
    const { cert } = make("fuzz", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]);
    const der = pemBlocks(cert, "CERTIFICATE")[0]!;
    let seed = 12345;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    for (let i = 0; i < 300; i++) {
      const b = der.slice(0, Math.floor(rnd() * der.length));
      if (i % 2) for (let j = 0; j < 4; j++) b[Math.floor(rnd() * b.length)] = Math.floor(rnd() * 256);
      await parseCertDer(b).then(
        () => undefined,
        (e) => expect(e).toBeInstanceOf(TlsError),
      );
    }
  });
});
