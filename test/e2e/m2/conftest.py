"""Fixtures for the M2 control-plane end-to-end suite (SPEC.md section 9, M2: A2.2 - A2.8).

What runs, all local:
  * the manager Worker under `wrangler dev` (local D1/R2, HTTPS, throwaway CA + server cert);
  * a local Access issuer: RS256 JWTs signed by a throwaway key whose JWKS the Worker fetches over HTTPS from
    `https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs` (a local host name; the throwaway CA is trusted through
    SSL_CERT_FILE). Environment only: the production code has no JWKS override and no verification switch;
  * a release built from THIS tree with a throwaway Ed25519 key, published into the local D1/R2 with
    manager/scripts/publish-release.sh --local;
  * Ubuntu 24.04 systemd containers as the managed hosts (the throwaway CA is in their trust store only).

Opt out / configure with environment variables:
  EXP_E2E=0                   skip the suite
  EXP_E2E_SLOT=<n>            run beside another session of this suite (distinct manager/Access names and JWKS address)
  EXP_E2E_ARTIFACTS=<dir>     keep logs/diagnostics there (default: a tmp dir)
  EXP_E2E_DIST=<dir> EXP_E2E_RELEASE_PUBKEY=<pem>   use an already built signed release instead of building one
                              (the upgrade / rollback tests then skip: they need the signing key to build more releases)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "test" / "harness"))

from expharness import dockerhost, hostsfile  # noqa: E402
from expharness.access import AccessIssuer, JwksServer  # noqa: E402
from expharness.manager import AdminClient, ManagerDev, clean_env  # noqa: E402
from expharness.pki import make_pki, openssl  # noqa: E402

# EXP_E2E_SLOT=<n> lets several sessions of this suite run side by side (own names, own JWKS address, own wrangler dev)
_SLOT = os.environ.get("EXP_E2E_SLOT", "")
MANAGER_NAME = f"exp-manager{_SLOT}.test"
TEAM_DOMAIN = f"access{_SLOT}.exp-e2e.test"
JWKS_BIND = f"127.0.0.{77 + int(_SLOT or 0)}"
AUD = "e2e-access-aud-0123456789abcdef"
OWNER = "owner@e2e.test"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    here = str(Path(__file__).resolve().parent)
    for item in items:
        if str(item.path).startswith(here):
            item.add_marker(pytest.mark.e2e)
            if os.environ.get("EXP_E2E") == "0":
                item.add_marker(pytest.mark.skip(reason="EXP_E2E=0"))


@dataclass
class Stack:
    tmp: Path
    artifacts: Path
    mgr: ManagerDev
    issuer: AccessIssuer
    jwks: JwksServer
    admin: AdminClient
    version: str
    ca_pem: str
    dist: Path
    pub: Path
    key: Path | None  # the throwaway release signing key (None when EXP_E2E_DIST supplied a prebuilt release)

    def token(self, email: str = OWNER) -> str:
        return self.issuer.mint(email)


def _why_skip() -> str | None:
    for tool in ("openssl", "node", "npx", "docker", "curl"):
        if shutil.which(tool) is None:
            return f"{tool} is not installed"
    if not hostsfile.can_edit():
        return "/etc/hosts is not writable (the Worker reaches the local Access issuer by host name)"
    if not (REPO / "manager" / "node_modules" / ".bin" / "wrangler").exists():
        return "manager/node_modules is missing: run `npm ci` in manager/"
    return dockerhost.docker_unavailable()


def _build_release(tmp: Path) -> tuple[Path, Path]:
    pre = os.environ.get("EXP_E2E_DIST")
    if pre:
        pub = os.environ.get("EXP_E2E_RELEASE_PUBKEY")
        assert pub, "EXP_E2E_DIST needs EXP_E2E_RELEASE_PUBKEY"
        return Path(pre), Path(pub)
    keydir = tmp / "releasekey"
    keydir.mkdir()
    priv, pub = keydir / "release.pem", keydir / "release-pub.pem"
    openssl("genpkey", "-algorithm", "ED25519", "-out", str(priv))
    priv.chmod(0o600)
    openssl("pkey", "-in", str(priv), "-pubout", "-out", str(pub))
    out = tmp / "dist"
    r = subprocess.run(  # noqa: S603
        [str(REPO / "packaging" / "build.sh"), "--release", "0.1.0", "--out", str(out)],
        env=clean_env(EXP_RELEASE_KEY=str(priv), EXP_RELEASE_PUBKEY=str(pub)),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        cwd=REPO,
    )
    assert r.returncode == 0, f"packaging/build.sh failed: {(r.stdout + r.stderr)[-800:]}"
    return out, pub


@pytest.fixture(scope="session")
def stack() -> Iterator[Stack]:
    why = _why_skip()
    if why:
        pytest.skip(why)
    tmp = Path(tempfile.mkdtemp(prefix="exp-e2e-m2-"))
    artifacts = Path(os.environ.get("EXP_E2E_ARTIFACTS") or tmp / "artifacts")
    artifacts.mkdir(parents=True, exist_ok=True)
    pki = make_pki(tmp / "pki", [MANAGER_NAME, TEAM_DOMAIN], ["127.0.0.1", JWKS_BIND])
    dist, pub = _build_release(tmp)
    issuer = AccessIssuer(tmp / "access", TEAM_DOMAIN, AUD)
    mgr = ManagerDev(
        tmp,
        host=MANAGER_NAME,
        team_domain=TEAM_DOMAIN,
        aud=AUD,
        owner_email=OWNER,
        ca_pem=pki.ca_pem,
        cert=pki.cert,
        key=pki.key,
        release_pubkey=pub,
    )
    hosts = hostsfile.HostsEntries({MANAGER_NAME: "127.0.0.1", TEAM_DOMAIN: JWKS_BIND}, tag=f"m2-{os.getpid()}")
    jwks = JwksServer(issuer.key.jwks, pki.cert, pki.key, JWKS_BIND)
    try:
        hosts.__enter__()
        jwks.start()
        mgr.prepare()
        pr = mgr.publish_release(dist, pub)
        assert pr.returncode == 0, f"publish-release.sh --local failed: {(pr.stdout + pr.stderr)[-800:]}"
        mgr.start()
        version = next(iter(sorted(p.name for p in dist.glob("exp-*-manifest.json")))).split("-")[1]
        admin = AdminClient(mgr, lambda: issuer.mint(OWNER))
        key = tmp / "releasekey" / "release.pem"
        yield Stack(tmp, artifacts, mgr, issuer, jwks, admin, version, pki.ca_text, dist, pub, key if key.is_file() else None)
    finally:
        mgr.stop()
        try:
            shutil.copy(mgr.log_path, artifacts / "wrangler-dev.log")
        except OSError:
            pass
        jwks.stop()
        hosts.__exit__(None, None, None)
        if not os.environ.get("EXP_E2E_KEEP_TMP"):
            shutil.rmtree(tmp / "wrangler-state", ignore_errors=True)


@pytest.fixture(scope="session")
def host_image() -> None:
    reason = dockerhost.ensure_image("24.04")
    if reason:
        pytest.skip(reason)


def start_host(stack: Stack, label: str) -> dockerhost.Host:
    try:
        return dockerhost.Host(label, {MANAGER_NAME: "host-gateway"}, stack.ca_pem)
    except dockerhost.SystemdUnavailable as exc:
        pytest.skip(str(exc))
    except RuntimeError as exc:
        pytest.skip(str(exc))
    raise AssertionError("unreachable")
