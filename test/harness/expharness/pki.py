"""Throwaway CA + server certificate (openssl, argv only)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


def openssl(*argv: str, cwd: Path | None = None, input_: bytes | None = None) -> bytes:
    r = subprocess.run(  # noqa: S603
        ["openssl", *argv],
        cwd=cwd,
        input=input_,
        capture_output=True,
        timeout=60,
        check=False,  # noqa: S607
    )
    if r.returncode != 0:
        raise RuntimeError(f"openssl {argv[0]} failed: {r.stderr.decode(errors='replace')[-300:]}")
    return r.stdout


@dataclass(frozen=True)
class Pki:
    ca_pem: Path
    cert: Path
    key: Path

    @property
    def ca_text(self) -> str:
        return self.ca_pem.read_text()


def make_pki(directory: Path, names: list[str], ips: list[str] | None = None) -> Pki:
    """A 2-day CA and one server certificate valid for every DNS name / IP in `names` / `ips`."""
    directory.mkdir(parents=True, exist_ok=True)
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    openssl(
        "req",
        "-x509",
        *ec,
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-subj",
        "/CN=exp e2e throwaway CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        cwd=directory,
    )
    openssl("req", "-new", *ec, "-keyout", "srv.key", "-out", "srv.csr", "-subj", f"/CN={names[0]}", cwd=directory)
    san = ",".join([f"DNS:{n}" for n in names] + [f"IP:{i}" for i in (ips or ["127.0.0.1"])])
    (directory / "ext.cnf").write_text(f"subjectAltName={san}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
    openssl(
        "x509",
        "-req",
        "-in",
        "srv.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "srv.pem",
        "-days",
        "2",
        "-extfile",
        "ext.cnf",
        cwd=directory,
    )
    for f in ("ca.key", "srv.key"):
        (directory / f).chmod(0o600)
    return Pki(directory / "ca.pem", directory / "srv.pem", directory / "srv.key")
