"""TLS key + self-signed certificate for collector/dashboard (generated locally, never sent by the
manager). Layout (03-collector.md section 8): /var/lib/exp/<c>/tls/{key.pem,cert.pem}; P-256, CN =
component id, SAN = the listen address. The directory is root-owned and not service-writable; the key
is `lchown`ed to the service user (0600) on a file root created in a private dir. A valid existing pair
is never regenerated."""

from __future__ import annotations

import ipaddress
import logging
import os
import pwd
import re
import secrets
import stat
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from exp_common import tlspin

from .errors import AgentError, Refused
from .pathguard import SafeFS
from .runner import Runner

log = logging.getLogger(__name__)

TLS_USERS = {"collector": "exp-collector", "dashboard": "exp-dashboard"}
_CN_RE = re.compile(r"[A-Za-z0-9.-]{1,64}\Z")
_DNS_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,62}[A-Za-z0-9])?\Z")
WILDCARDS = {"0.0.0.0", "::", ""}  # noqa: S104 - addresses we must NOT put in a SAN


def lookup_user(name: str) -> tuple[int, int] | None:
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        return None
    return pw.pw_uid, pw.pw_gid


def _san_entry(host: str) -> str | None:
    host = host.strip("[]")
    if host in WILDCARDS:
        return None
    try:
        ipaddress.ip_address(host)
        return f"IP:{host}"
    except ValueError:
        pass
    return f"DNS:{host}" if _DNS_RE.match(host) else None


def san_for(component: str, config: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    if component == "collector":
        listen = str(config.get("listen", ""))
        hosts.append(listen.rpartition(":")[0])
    elif component == "dashboard":
        try:
            hosts.append(urlsplit(str(config.get("url", ""))).hostname or "")
        except ValueError:
            pass
        https = (
            (config.get("listen") or {}).get("https", "") if isinstance(config.get("listen"), dict) else ""
        )
        hosts.append(str(https).rpartition(":")[0])
    sans: list[str] = []
    for h in hosts:
        e = _san_entry(h)
        if e and e not in sans:
            sans.append(e)
    if not sans:
        raise Refused(f"cannot derive a TLS SAN for {component}: no usable listen address in its config")
    return sans


def component_id(component: str, config: dict[str, Any]) -> str:
    cid = str(config.get(f"{component}_id", component))
    if not _CN_RE.match(cid):
        raise Refused("component id is not usable as a certificate CN")
    return cid


def wants_tls(component: str, config: dict[str, Any]) -> bool:
    if component == "collector":
        return True
    if component == "dashboard":
        return (config.get("tls") or {}).get("mode", "self_signed") != "provided"
    return False


def _pair_valid(runner: Runner, cert: str, key: str) -> bool:
    chk = runner.run(["openssl", "x509", "-in", cert, "-noout", "-checkend", "0"], timeout=20)
    if chk.rc != 0:
        return False
    pub_c = runner.run(["openssl", "x509", "-in", cert, "-noout", "-pubkey"], timeout=20)
    pub_k = runner.run(["openssl", "pkey", "-in", key, "-pubout"], timeout=20)
    return pub_c.rc == 0 and pub_k.rc == 0 and pub_c.stdout.strip() != "" and pub_c.stdout == pub_k.stdout


def tls_is_valid(fs: SafeFS, runner: Runner, component: str, config: dict[str, Any]) -> bool:
    """True when no TLS is needed or a valid (unexpired, matching) pair is in place. Read-only."""
    if not wants_tls(component, config):
        return True
    tls = fs.paths.state_dir(component) / "tls"
    key, cert = tls / "key.pem", tls / "cert.pem"
    try:
        if not (fs.exists(key) and fs.exists(cert)) or os.path.islink(key) or os.path.islink(cert):
            return False
    except Refused:
        return False
    return _pair_valid(runner, str(cert), str(key))


def ensure_tls(
    fs: SafeFS,
    runner: Runner,
    component: str,
    config: dict[str, Any],
    lookup: Callable[[str], tuple[int, int] | None] = lookup_user,
) -> bool:
    """Ensure a valid key/cert pair exists. Returns True when a new pair was generated."""
    if not wants_tls(component, config):
        return False
    svc = TLS_USERS[component]
    ids = lookup(svc)
    if ids is None:
        raise AgentError(f"service user {svc} does not exist yet")
    state = fs.paths.state_dir(component)
    fs.mkdir(fs.paths.var, 0o755)
    fs.mkdir(state, 0o755)
    tls = state / "tls"
    fs.mkdir(tls, 0o755)
    st = fs.lstat(tls)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != fs.paths.uid or st.st_mode & 0o022:
        raise Refused(f"{fs.paths.logical(tls)} must be a root-owned directory not writable by others")
    key, cert = tls / "key.pem", tls / "cert.pem"
    if (
        fs.exists(key)
        and fs.exists(cert)
        and not os.path.islink(key)
        and not os.path.islink(cert)
        and _pair_valid(runner, str(cert), str(key))
    ):
        kst = fs.lstat(key)
        if kst.st_uid != ids[0] or stat.S_IMODE(kst.st_mode) != 0o600:
            fs.chmod(key, 0o600)
            fs.lchown(key, ids[0], ids[1])
        return False
    tmp = state / f".tls-{secrets.token_hex(6)}"
    os.mkdir(fs.g(tmp), 0o700)
    try:
        try:
            tlspin.generate_self_signed_cert(
                tmp, cn=component_id(component, config), days=3650, san=san_for(component, config)
            )
        except (tlspin.TlsPinError, ValueError) as exc:
            raise AgentError(f"TLS certificate generation failed: {exc}") from None
        fs.chmod(tmp / "key.pem", 0o600)
        fs.lchown(tmp / "key.pem", ids[0], ids[1])
        fs.chmod(tmp / "cert.pem", 0o644)
        os.replace(fs.g(tmp / "cert.pem"), fs.g(cert))
        os.replace(fs.g(tmp / "key.pem"), fs.g(key))
    finally:
        fs.rmtree(tmp)
    log.info("generated a TLS key and self-signed certificate for %s", component)
    return True
