"""HTTPS client pinned to the SHA-256 fingerprint of the peer's leaf certificate.

Collector and dashboard certificates are self-signed; the pin REPLACES CA verification
(02-probe.md section 8). Therefore:

* ``ssl.CERT_NONE`` and no hostname check -- the pin is the sole trust anchor. TLS >= 1.2.
* The fingerprint is compared (constant time) right after the handshake and BEFORE any HTTP
  request bytes are written. On mismatch the socket is closed and ``PinMismatch`` is raised;
  there is never a fallback to an unpinned connection.
* Because trust comes only from the pin, certificate validity dates do not matter: an expired
  or not-yet-valid certificate whose fingerprint matches the pin is accepted. Rotation is
  done by pinning the new fingerprint (``pins`` may list several: current + next).
* Every network operation has a mandatory timeout (connect, per-read, and a total deadline).
  Redirects are not followed; responses are size-bounded.

Fingerprint format: ``AB:CD:...`` uppercase colon-separated hex (32 bytes). Lowercase and
colon-less hex are accepted on input and normalized.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import logging
import math
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_TOTAL_TIMEOUT = 30.0
DEFAULT_MAX_RESPONSE = 4 * 1024 * 1024


class TlsPinError(Exception):
    """Base class for pinned-connection failures."""


class PinMismatch(TlsPinError):
    """The peer leaf certificate does not match any configured pin (connection closed, nothing sent)."""

    def __init__(self, actual: str, expected: Sequence[str]) -> None:
        self.actual = actual
        self.expected = list(expected)
        super().__init__(f"tls_pin_mismatch: peer certificate {actual} matches none of "
                         f"{len(self.expected)} configured pin(s)")


class PinFormatError(TlsPinError, ValueError):
    """A configured fingerprint is not a SHA-256 hex fingerprint."""


class PinnedTimeout(TlsPinError):
    """A connect/read/total timeout expired."""


# --------------------------------------------------------------------------------- fingerprints

def normalize_fingerprint(fp: str) -> str:
    """Normalize to uppercase ``AB:CD:...``. Raises PinFormatError unless it is 32 bytes of hex."""
    if not isinstance(fp, str):
        raise PinFormatError("fingerprint must be a string")
    hexs = fp.strip().replace(":", "")
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", hexs):
        raise PinFormatError("fingerprint must be 32 bytes of hex (SHA-256), optionally colon-separated")
    hexs = hexs.upper()
    return ":".join(hexs[i:i + 2] for i in range(0, 64, 2))


def fingerprint_of_der(der: bytes) -> str:
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, 64, 2))


def fingerprint_of_pem(pem: str | bytes) -> str:
    """Fingerprint of the first certificate in a PEM string/bytes."""
    text = pem.decode("ascii", "strict") if isinstance(pem, bytes) else pem
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.DOTALL)
    if not m:
        raise ValueError("no PEM certificate found")
    return fingerprint_of_der(ssl.PEM_cert_to_DER_cert(m.group(0)))


def fingerprint_of_pem_file(path: str | Path) -> str:
    return fingerprint_of_pem(Path(path).read_bytes())


def pins_match(der: bytes, pins: Iterable[str]) -> bool:
    actual = fingerprint_of_der(der).encode("ascii")
    ok = False
    for p in pins:   # no early exit: constant work per pin
        ok |= hmac.compare_digest(actual, normalize_fingerprint(p).encode("ascii"))
    return ok


# ------------------------------------------------------------------------------------ connection

def _check_timeout(name: str, v: float) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0:
        raise ValueError(f"{name} must be a positive finite number of seconds (timeouts are mandatory)")
    return float(v)


def _context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE        # the fingerprint pin replaces CA verification
    return ctx


def _handshake(host: str, port: int, connect_timeout: float, read_timeout: float) -> ssl.SSLSocket:
    try:
        raw = socket.create_connection((host, port), timeout=connect_timeout)
    except TimeoutError as exc:
        raise PinnedTimeout(f"connect to {host}:{port} timed out after {connect_timeout}s") from exc
    try:
        raw.settimeout(connect_timeout)      # bounds the handshake too
        sni = None if _is_ip(host) else host
        tls = _context().wrap_socket(raw, server_hostname=sni)
    except TimeoutError as exc:
        raw.close()
        raise PinnedTimeout(f"TLS handshake with {host}:{port} timed out") from exc
    except (ssl.SSLError, OSError):
        raw.close()
        raise
    tls.settimeout(read_timeout)
    return tls


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


class _PinnedConnection(http.client.HTTPSConnection):
    """HTTPSConnection that verifies the pin inside connect(), before http.client can send."""

    def __init__(self, host: str, port: int, pins: list[str], connect_timeout: float,
                 read_timeout: float) -> None:
        super().__init__(host, port, timeout=read_timeout, context=_context())
        self._pins = pins
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout

    def connect(self) -> None:
        tls = _handshake(self.host, self.port, self._connect_timeout, self._read_timeout)
        der = tls.getpeercert(binary_form=True)
        if not der or not pins_match(der, self._pins):
            actual = fingerprint_of_der(der) if der else "<no certificate>"
            try:
                tls.close()
            finally:
                log.warning("tls_pin_mismatch for %s:%s (peer %s)", self.host, self.port, actual)
            raise PinMismatch(actual, self._pins)
        self.sock = tls


def probe_fingerprint(host: str, port: int, connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
                      read_timeout: float = DEFAULT_READ_TIMEOUT) -> str:
    """Handshake and report the peer leaf fingerprint WITHOUT sending anything. For operator
    discovery ("what should I pin?") only -- never use the result as an automatic trust decision."""
    _check_timeout("connect_timeout", connect_timeout)
    _check_timeout("read_timeout", read_timeout)
    tls = _handshake(host, port, connect_timeout, read_timeout)
    try:
        der = tls.getpeercert(binary_form=True)
    finally:
        tls.close()
    if not der:
        raise TlsPinError("peer presented no certificate")
    return fingerprint_of_der(der)


@dataclass
class Response:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes

    def json(self) -> object:
        import json
        return json.loads(self.body.decode("utf-8"))


def request(method: str, url: str, pins: str | Sequence[str], *, body: bytes | None = None,
            headers: Mapping[str, str] | None = None,
            connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
            read_timeout: float = DEFAULT_READ_TIMEOUT,
            total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
            max_response_bytes: int = DEFAULT_MAX_RESPONSE) -> Response:
    """One pinned HTTPS request. `pins` is one fingerprint or a list (current + fallback pins).
    Raises PinMismatch (nothing was sent), PinnedTimeout, TlsPinError, or OSError/ssl.SSLError/
    http.client.HTTPException for transport failures. Only https:// URLs are accepted."""
    connect_timeout = _check_timeout("connect_timeout", connect_timeout)
    read_timeout = _check_timeout("read_timeout", read_timeout)
    total_timeout = _check_timeout("total_timeout", total_timeout)
    plist = [normalize_fingerprint(p) for p in ([pins] if isinstance(pins, str) else list(pins))]
    if not plist:
        raise PinFormatError("at least one pin is required (unpinned connections are not supported)")
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise ValueError("only https:// URLs with a host are supported")
    port = u.port or 443
    target = (u.path or "/") + (("?" + u.query) if u.query else "")
    deadline = time.monotonic() + total_timeout
    conn = _PinnedConnection(u.hostname, port, plist, connect_timeout, read_timeout)
    try:
        hdrs = dict(headers or {})
        conn.request(method, target, body=body, headers=hdrs)   # connect() -> pin check happens first
        resp = conn.getresponse()
        chunks: list[bytes] = []
        total = 0
        while True:
            if time.monotonic() > deadline:
                raise PinnedTimeout(f"total timeout of {total_timeout}s exceeded")
            chunk = resp.read(min(65536, max_response_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_response_bytes:
                raise TlsPinError(f"response exceeds {max_response_bytes} bytes")
            chunks.append(chunk)
        return Response(resp.status, resp.reason, {k.lower(): v for k, v in resp.getheaders()},
                        b"".join(chunks))
    except TimeoutError as exc:
        raise PinnedTimeout(f"timed out talking to {u.hostname}:{port}") from exc
    finally:
        conn.close()


# --------------------------------------------------------------------------------- test helpers

def generate_self_signed_cert(directory: str | Path, cn: str = "localhost", days: int = 365,
                              san: Sequence[str] = ("DNS:localhost", "IP:127.0.0.1"),
                              not_before: str | None = None, not_after: str | None = None,
                              ) -> tuple[Path, Path]:
    """Create a self-signed EC P-256 cert + key (PEM) in `directory` using the openssl CLI (argv,
    no shell). Returns (cert_path, key_path); key mode 0600. For tests and the collector's
    first-boot certificate. `not_before`/`not_after` (``YYYYMMDDHHMMSSZ``) allow creating an
    expired certificate via ``openssl ca -selfsign``."""
    openssl = shutil.which("openssl")
    if openssl is None:
        raise TlsPinError("openssl CLI not found")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,64}", cn):
        raise ValueError("invalid common name")
    for s in san:
        if not re.fullmatch(r"(DNS|IP):[A-Za-z0-9.:-]{1,64}", s):
            raise ValueError(f"invalid subjectAltName entry {s!r}")
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    cert, key = d / "cert.pem", d / "key.pem"
    old_umask = os.umask(0o077)
    try:
        if not_before is None and not_after is None:
            argv = [openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", str(key), "-out", str(cert), "-days", str(int(days)),
                    "-subj", f"/CN={cn}", "-addext", "subjectAltName=" + ",".join(san)]
            _run(argv)
        else:
            if not (not_before and not_after
                    and re.fullmatch(r"[0-9]{14}Z", not_before) and re.fullmatch(r"[0-9]{14}Z", not_after)):
                raise ValueError("not_before and not_after must both be YYYYMMDDHHMMSSZ")
            with tempfile.TemporaryDirectory(prefix="expca-") as td:
                t = Path(td)
                (t / "idx.txt").write_text("")
                (t / "serial").write_text("01\n")
                (t / "ca.cnf").write_text(
                    "[ca]\ndefault_ca=x\n[x]\ndatabase=idx.txt\nnew_certs_dir=.\nserial=serial\n"
                    "default_md=sha256\npolicy=p\nunique_subject=no\ncopy_extensions=copy\n"
                    f"[p]\ncommonName=supplied\n[req]\ndistinguished_name=dn\nprompt=no\n"
                    f"req_extensions=ext\n[dn]\nCN={cn}\n[ext]\nsubjectAltName={','.join(san)}\n")
                _run([openssl, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                      "-nodes", "-keyout", str(key), "-out", str(t / "r.csr"), "-config", str(t / "ca.cnf")])
                _run([openssl, "ca", "-batch", "-selfsign", "-keyfile", str(key), "-in", str(t / "r.csr"),
                      "-out", str(cert), "-config", str(t / "ca.cnf"), "-startdate", not_before,
                      "-enddate", not_after, "-notext"], cwd=t)
    finally:
        os.umask(old_umask)
    os.chmod(key, 0o600)
    return cert, key


def _run(argv: list[str], cwd: Path | None = None) -> None:
    try:
        subprocess.run(argv, check=True, capture_output=True, timeout=60, cwd=cwd)
    except subprocess.CalledProcessError as exc:
        raise TlsPinError(f"openssl failed: {exc.stderr.decode('utf-8', 'replace')[:300]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise TlsPinError("openssl timed out") from exc


__all__ = [
    "PinFormatError",
    "PinMismatch",
    "PinnedTimeout",
    "Response",
    "TlsPinError",
    "fingerprint_of_der",
    "fingerprint_of_pem",
    "fingerprint_of_pem_file",
    "generate_self_signed_cert",
    "normalize_fingerprint",
    "pins_match",
    "probe_fingerprint",
    "request",
]
