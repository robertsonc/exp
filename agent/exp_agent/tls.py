"""TLS key + self-signed certificate for collector/dashboard (generated locally, never sent by the
manager). Layout (CR-wp2-state-layout-and-wrappers; documented in agent/README.md):

  /var/lib/exp/<c>/            owned by the service user (the unit's StateDirectory= chowns it only when
                               the owner differs, so the agent creates it with the right owner and
                               systemd never recurses into exp-vm's data)
  /var/lib/exp/<c>/tls/        service user, 0700; key.pem 0600 (service user), cert.pem 0644
  /var/lib/exp/collector/vm/   exp-vm:exp-vm 0700

Everything is created by root and handled through directory descriptors opened with O_NOFOLLOW, so a
service user that owns its state directory can never turn a path into a symlink under the agent's feet;
ownership is changed with fchown/lchown on exactly the object root just created or opened, never
recursively. P-256 pair, CN = component id, SAN = the listen address; a valid pair is never regenerated."""

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


# component -> (state dir owner, state dir mode, [(subdir, owner, mode)])
STATE_LAYOUT: dict[str, tuple[str, int, list[tuple[str, str, int]]]] = {
    "collector": ("exp-collector", 0o755, [("tls", "exp-collector", 0o700), ("vm", "exp-vm", 0o700)]),
    "dashboard": ("exp-dashboard", 0o700, [("tls", "exp-dashboard", 0o700)]),
}
_DIRFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_dir(fs: SafeFS, path: Any, dir_fd: int | None = None, name: str | None = None) -> int:
    try:
        if dir_fd is None:
            return os.open(fs.g(path), _DIRFLAGS)
        return os.open(name or "", _DIRFLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise Refused(f"{fs.paths.logical(path)} must be a real directory, not a link ({exc.strerror})") from None


def _settle_dir(fs: SafeFS, fd: int, path: Any, ids: tuple[int, int], mode: int) -> None:
    st = os.fstat(fd)
    if (st.st_uid, st.st_gid) != ids:
        fs.fchown(fd, path, ids[0], ids[1])
    if stat.S_IMODE(st.st_mode) != mode:
        os.fchmod(fd, mode)


def prepare_state(
    fs: SafeFS,
    component: str,
    config: dict[str, Any],
    lookup: Callable[[str], tuple[int, int] | None] = lookup_user,
) -> int | None:
    """Create/repair the component's state layout before its first start. Returns an open descriptor on
    the tls/ directory (caller closes it) when the component needs TLS, else None."""
    layout = STATE_LAYOUT.get(component)
    if layout is None:
        return None
    owner, mode, subs = layout
    ids: dict[str, tuple[int, int]] = {}
    for user in {owner, *(u for _n, u, _m in subs)}:
        got = lookup(user)
        if got is None:
            raise AgentError(f"service user {user} does not exist yet")
        ids[user] = got
    state = fs.paths.state_dir(component)
    fs.mkdir(fs.paths.var, 0o755)
    fs.mkdir(state, 0o700)  # refuses a symlink / non-directory; root-created while root-owned
    sfd = _open_dir(fs, state)
    tls_fd: int | None = None
    try:
        for name, user, smode in subs:
            if name == "tls" and not wants_tls(component, config):
                continue
            try:
                os.mkdir(name, smode, dir_fd=sfd)
            except FileExistsError:
                pass
            fd = _open_dir(fs, state / name, sfd, name)
            try:
                _settle_dir(fs, fd, state / name, ids[user], smode)
            except BaseException:
                os.close(fd)
                raise
            if name == "tls":
                tls_fd = fd
            else:
                os.close(fd)
        _settle_dir(fs, sfd, state, ids[owner], mode)
    except BaseException:
        if tls_fd is not None:
            os.close(tls_fd)
        raise
    finally:
        os.close(sfd)
    return tls_fd


def _regular(dir_fd: int, name: str) -> os.stat_result | None:
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return st if stat.S_ISREG(st.st_mode) else None


def ensure_tls(
    fs: SafeFS,
    runner: Runner,
    component: str,
    config: dict[str, Any],
    lookup: Callable[[str], tuple[int, int] | None] = lookup_user,
) -> bool:
    """Prepare the state layout and ensure a valid key/cert pair exists. True when a new pair was generated."""
    tls_fd = prepare_state(fs, component, config, lookup)
    if tls_fd is None:
        return False
    try:
        svc = TLS_USERS[component]
        ids = lookup(svc)
        if ids is None:
            raise AgentError(f"service user {svc} does not exist yet")
        tls = fs.paths.state_dir(component) / "tls"
        key, cert = tls / "key.pem", tls / "cert.pem"
        kst, cst = _regular(tls_fd, "key.pem"), _regular(tls_fd, "cert.pem")
        if kst and cst and _pair_valid(runner, str(cert), str(key)):
            kfd = os.open("key.pem", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=tls_fd)
            try:
                if (kst.st_uid, kst.st_gid) != ids:
                    fs.fchown(kfd, key, ids[0], ids[1])
                if stat.S_IMODE(kst.st_mode) != 0o600:
                    os.fchmod(kfd, 0o600)
            finally:
                os.close(kfd)
            cfd = os.open("cert.pem", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=tls_fd)
            try:
                if stat.S_IMODE(os.fstat(cfd).st_mode) != 0o644:
                    os.fchmod(cfd, 0o644)
            finally:
                os.close(cfd)
            return False
        # generate in a private root-only directory outside the service-owned state dir, then rename
        # into the (descriptor-pinned) tls directory; rename replaces a planted symlink, never follows it
        fs.mkdir(fs.paths.agent_state, 0o700)
        tmp = fs.paths.agent_state / f".tls-{secrets.token_hex(6)}"
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
            tfd = _open_dir(fs, tmp)
            try:
                os.rename("cert.pem", "cert.pem", src_dir_fd=tfd, dst_dir_fd=tls_fd)
                os.rename("key.pem", "key.pem", src_dir_fd=tfd, dst_dir_fd=tls_fd)
            finally:
                os.close(tfd)
        finally:
            fs.rmtree(tmp)
        log.info("generated a TLS key and self-signed certificate for %s", component)
        return True
    finally:
        os.close(tls_fd)
