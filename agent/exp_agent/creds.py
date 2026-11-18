"""Credential files: /etc/exp/<c>/creds/ (root 0700), files root 0600, written atomically. Values come
from the desired state and are never logged. Files no longer in desired state are removed; files a unit
references through LoadCredential= are created empty if desired left them out (a missing file stops
the unit from starting)."""

from __future__ import annotations

import logging
import stat

from .errors import Refused
from .pathguard import CRED_NAME_RE, SafeFS

log = logging.getLogger(__name__)


def _validate(names: list[str] | set[str]) -> None:
    for n in names:
        if not CRED_NAME_RE.match(n):
            raise Refused(f"invalid credential file name {n[:40]!r}")


def ensure_creds_dir(fs: SafeFS, component: str):
    d = fs.paths.creds_dir(component)
    fs.mkdir(fs.paths.etc, 0o755)
    fs.mkdir(fs.paths.etc_dir(component), 0o755)
    fs.mkdir(d, 0o700)
    fs.chmod(d, 0o700)
    return d


def snapshot(fs: SafeFS, component: str) -> dict[str, bytes]:
    """Current credential files (name -> bytes); used for the rollback copy."""
    d = fs.paths.creds_dir(component)
    out: dict[str, bytes] = {}
    for name in fs.listdir(d):
        if CRED_NAME_RE.match(name):
            data = fs.read_bytes(d / name, 1024 * 1024)
            if data is not None:
                out[name] = data
    return out


def sync(
    fs: SafeFS, component: str, creds: dict[str, str | bytes], referenced: set[str] | None = None
) -> bool:
    """Make creds/ exactly `creds` (+ empty files for `referenced` names); True if anything changed."""
    wanted: dict[str, bytes] = {n: v if isinstance(v, bytes) else v.encode("utf-8") for n, v in creds.items()}
    _validate(list(wanted))
    refs = set(referenced or ())
    _validate(refs)
    for n in refs:
        wanted.setdefault(n, b"")
    d = ensure_creds_dir(fs, component)
    changed = False
    for name, data in wanted.items():
        p = d / name
        cur = fs.read_bytes(p, 1024 * 1024)
        if cur != data:
            fs.write(p, data, 0o600)
            changed = True
        else:
            st = fs.lstat(p)
            if stat.S_IMODE(st.st_mode) != 0o600:
                fs.chmod(p, 0o600)
    for name in fs.listdir(d):
        if name not in wanted:
            p = d / name
            if fs.is_dir(p):
                fs.rmtree(p)
            else:
                fs.remove(p)
            changed = True
    return changed


def restore(fs: SafeFS, component: str, snap: dict[str, bytes]) -> None:
    d = ensure_creds_dir(fs, component)
    _validate(list(snap))
    for name, data in snap.items():
        fs.write(d / name, data, 0o600)
    for name in fs.listdir(d):
        if name not in snap:
            fs.remove(d / name)


def remove_all(fs: SafeFS, component: str) -> None:
    d = fs.paths.creds_dir(component)
    if fs.exists(d):
        fs.rmtree(d)
