"""Throwaway CA for the M6 HTTPS fakes (dev/test tooling; stdlib + the openssl CLI, argv only).

``make_ca(dir)`` writes a self-signed EC P-256 CA (``ca.pem`` / ``ca.key``); ``issue(ca, dir, cn, sans)``
signs a leaf (``leaf.pem`` = leaf + CA chain, ``leaf.key``). Everything is generated at runtime into a
directory the caller owns (normally a pytest ``tmp_path``): no key or certificate is ever committed, so
gitleaks has nothing to find. A client trusts the fake by loading ``ca.pem``::

    ctx = ssl.create_default_context(cafile=str(ca.cert))
"""
from __future__ import annotations

import os
import re
import shutil
import ssl
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


class CaError(RuntimeError):
    pass


@dataclass(frozen=True)
class Ca:
    cert: Path
    key: Path


@dataclass(frozen=True)
class Leaf:
    cert_chain: Path   # leaf certificate followed by the CA certificate (what a server presents)
    key: Path


def _run(argv: list[str], cwd: Path | None = None) -> None:
    try:
        subprocess.run(argv, check=True, capture_output=True, timeout=60, cwd=cwd)  # noqa: S603 - argv only
    except subprocess.CalledProcessError as exc:
        raise CaError(f"openssl failed: {exc.stderr.decode('utf-8', 'replace')[:300]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CaError("openssl timed out") from exc


def _openssl() -> str:
    path = shutil.which("openssl")
    if path is None:
        raise CaError("openssl CLI not found")
    return path


def make_ca(directory: str | Path, cn: str = "exp-fakes throwaway CA", days: int = 30) -> Ca:
    """A fresh CA under `directory` (created, key mode 0600)."""
    if not re.fullmatch(r"[A-Za-z0-9 .-]{1,64}", cn):
        raise ValueError("invalid common name")
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    cert, key = d / "ca.pem", d / "ca.key"
    old = os.umask(0o077)
    try:
        _run([_openssl(), "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
              "-keyout", str(key), "-out", str(cert), "-days", str(int(days)), "-subj", f"/CN={cn}",
              "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    finally:
        os.umask(old)
    os.chmod(key, 0o600)
    return Ca(cert, key)


def issue(ca: Ca, directory: str | Path, cn: str = "localhost",
          sans: Sequence[str] = ("DNS:localhost", "IP:127.0.0.1"), days: int = 30) -> Leaf:
    """A leaf signed by `ca` (EC P-256), valid for `sans`."""
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,64}", cn):
        raise ValueError("invalid common name")
    for s in sans:
        if not re.fullmatch(r"(DNS|IP):[A-Za-z0-9.:-]{1,64}", s):
            raise ValueError(f"invalid subjectAltName entry {s!r}")
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    chain, key = d / "leaf.pem", d / "leaf.key"
    openssl = _openssl()
    old = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="expleaf-") as td:
            t = Path(td)
            (t / "ext.cnf").write_text(
                "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n"
                f"subjectAltName={','.join(sans)}\n")
            _run([openssl, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                  "-keyout", str(key), "-out", str(t / "r.csr"), "-subj", f"/CN={cn}"])
            _run([openssl, "x509", "-req", "-in", str(t / "r.csr"), "-CA", str(ca.cert), "-CAkey", str(ca.key),
                  "-CAcreateserial", "-CAserial", str(t / "ca.srl"), "-out", str(t / "leaf.crt"), "-days", str(int(days)),
                  "-extfile", str(t / "ext.cnf")])
            chain.write_bytes((t / "leaf.crt").read_bytes() + ca.cert.read_bytes())
    finally:
        os.umask(old)
    os.chmod(key, 0o600)
    return Leaf(chain, key)


def client_context(ca: Ca | Path | str) -> ssl.SSLContext:
    """A verifying client context that trusts only `ca` (hostname check on)."""
    path = ca.cert if isinstance(ca, Ca) else ca
    return ssl.create_default_context(cafile=str(path))


def make_server_tls(directory: str | Path, cn: str = "localhost",
                    sans: Sequence[str] = ("DNS:localhost", "IP:127.0.0.1")) -> tuple[Ca, Leaf]:
    """Convenience: a CA and a leaf in `directory`/ca and `directory`/leaf."""
    d = Path(directory)
    ca = make_ca(d / "ca")
    return ca, issue(ca, d / "leaf", cn=cn, sans=sans)
