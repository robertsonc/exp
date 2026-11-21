"""Install mechanics: apt requirements (allowlist), service users, committing a staged artifact to
/opt/exp/<c>/<ver>/, the `current` symlink flip and the /usr/local/bin link."""

from __future__ import annotations

import logging
import os
import pwd
import re
import stat
from collections.abc import Callable
from pathlib import Path

from .errors import AgentError, AptError, Refused
from .pathguard import VERSION_RE, SafeFS
from .runner import Result, Runner

log = logging.getLogger(__name__)

APT_ALLOWLIST = frozenset(
    {
        "busybox",
        "busybox-static",
        "iproute2",
        "iputils-ping",
        "iperf3",
        "curl",
        "openssl",
        "ca-certificates",
        "ethtool",
        "iw",
        "wpasupplicant",
        "tcpdump",
    }
)
SERVICE_USERS: dict[str, tuple[str, ...]] = {
    "collector": ("exp-collector", "exp-vm"),
    "dashboard": ("exp-dashboard",),
    "runner": ("exp-runner",),
    "speedtest": ("exp-speedtest",),
    "probe": (),
}
_PKG_RE = re.compile(r"[a-z0-9][a-z0-9+.-]{1,63}\Z")
MAX_REQ_BYTES = 16 * 1024


def read_requirements(root: Path) -> list[str]:
    """Package names from <root>/requirements.apt (one per line, # comments, blanks ignored)."""
    p = root / "requirements.apt"
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise Refused(f"requirements.apt cannot be read ({exc.strerror})") from None
    try:
        with os.fdopen(fd, "rb", closefd=False) as fh:
            raw = fh.read(MAX_REQ_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_REQ_BYTES:
        raise Refused("requirements.apt is too large")
    names: list[str] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and line not in names:
            names.append(line)
    return names


def check_requirements(names: list[str]) -> list[str]:
    """Refuse the component if ANY requirement is off the built-in allowlist."""
    bad = [n for n in names if not _PKG_RE.match(n) or n not in APT_ALLOWLIST]
    if bad:
        raise Refused(
            "requirements.apt lists packages outside the agent allowlist: "
            + ", ".join(repr(b[:64]) for b in bad[:5])
        )
    return names


def _installed(runner: Runner, name: str) -> bool:
    r = runner.run(["dpkg-query", "-W", "-f=${Status}", name], timeout=20)
    return r.rc == 0 and r.stdout.strip().endswith("installed")


def apt_install(runner: Runner, names: list[str], session: dict[str, bool] | None = None) -> list[str]:
    """Install the not-yet-installed subset of `names`; returns what was installed.

    Fresh and cloud images often ship no (or stale) package lists, so when something must be installed
    the lists are refreshed first (`apt-get update`, never when nothing is missing, and only once per
    `session` dict, which the reconciler shares across its components)."""
    missing = [n for n in names if not _installed(runner, n)]
    if not missing:
        return []
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    sess = session if session is not None else {}
    if sess.get("updated"):
        upd = Result(0, "", "")
    else:
        upd = runner.run(["apt-get", "update", "-q"], timeout=300, env=env)
        sess["updated"] = True
    if upd.rc != 0:
        # not fatal by itself: cached lists may still carry the packages; the install below decides
        log.warning("apt-get update failed (rc=%s): %s", upd.rc, upd.stderr.strip()[-200:])
    r = runner.run(["apt-get", "install", "-y", "--no-install-recommends", *missing], timeout=900, env=env)
    if r.rc != 0:
        why = r.stderr.strip()[-200:]
        if upd.rc != 0:
            why += f" (apt-get update also failed: {upd.stderr.strip()[-120:]})"
        raise AptError("apt-get install failed for " + ", ".join(missing) + ": " + why)
    return missing


def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
    except KeyError:
        return False
    return True


def ensure_users(runner: Runner, component: str, exists: Callable[[str], bool] = user_exists) -> list[str]:
    created: list[str] = []
    for user in SERVICE_USERS.get(component, ()):
        if exists(user):
            continue
        r = runner.run(
            ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", user], timeout=30
        )
        if r.rc != 0 and not exists(user):
            raise AgentError(f"cannot create service user {user}: {r.stderr.strip()[-200:]}")
        created.append(user)
    return created


def commit_staging(fs: SafeFS, staging: Path, version_dir: Path) -> None:
    """Atomic rename of the unpacked tree to /opt/exp/<c>/<ver>/ (root:root, not service-writable)."""
    if fs.exists(version_dir):
        fs.rmtree(staging)
        return
    fs.chmod(staging, 0o755)
    fs.rename(staging, version_dir)


def flip_current(fs: SafeFS, component: str, version: str) -> None:
    paths = fs.paths
    if not fs.is_dir(paths.version_dir(component, version)):
        raise Refused(f"cannot activate {component} {version}: not installed")
    fs.symlink(version, paths.current(component))
    link = paths.bin_link(component)
    os.makedirs(paths.usr_bin, exist_ok=True)
    fs.symlink(f"../../../opt/exp/{component}/current/bin/exp-{component}", link)


def current_version(fs: SafeFS, component: str) -> str | None:
    t = fs.readlink(fs.paths.current(component))
    return t if t and "/" not in t else None


def prune_versions(fs: SafeFS, component: str, keep: set[str]) -> list[str]:
    """Remove version directories under /opt/exp/<c>/ except `keep`, the one `current` points at and the
    one the agent's `previous` symlink points at (the rollback target). Only real directories named like
    a version are removed (never a symlink target, never `current`/`previous`/`rollback-check`); stale
    `.staging-*` directories are cleaned up too. Returns the removed version names."""
    removed: list[str] = []
    base = fs.paths.comp_opt(component)
    protected = set(keep)
    for link in ("current", "previous"):
        t = fs.readlink(base / link)
        if t and VERSION_RE.match(t):
            protected.add(t)
    for name in fs.listdir(base):
        p = base / name
        try:
            real_dir = stat.S_ISDIR(os.lstat(p).st_mode)  # lstat: a symlink is never followed or removed
        except OSError:
            continue
        if not real_dir:
            continue
        if name.startswith(".staging-"):
            fs.rmtree(p)
            continue
        if name in protected or not VERSION_RE.match(name):
            continue
        fs.rmtree(p)
        removed.append(name)
    return removed
