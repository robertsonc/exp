"""The ONE path guard (06-agent.md section 6, SR-17).

Every filesystem mutation the agent makes goes through `SafeFS`, which asks `Paths.guard` first.
Allowed roots (logical paths, i.e. as seen on a real host; `Paths(root=...)` maps them under a
prefix so tests run unprivileged in a tmp dir):

    /opt/exp  /etc/exp  /var/lib/exp  /run/exp  /etc/systemd/system/exp-*.service|timer
    plus the /usr/local/bin/exp-<component> convenience symlinks.

A path is refused when it contains "..", is relative, is outside the roots lexically, or when its
*resolved* location (symlinks followed) leaves the roots. Deleting a root itself is refused.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from exp_common.atomic import atomic_write

from .errors import PathRefused

COMPONENT_RE = re.compile(r"[a-z][a-z0-9]{0,31}\Z")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?\Z")
UNIT_RE = re.compile(r"exp-[a-z0-9][a-z0-9._@-]{0,100}\.(service|timer)\Z")
BIN_RE = re.compile(r"exp-[a-z][a-z0-9]{0,31}\Z")
CRED_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

ALLOWED_ROOTS = ("/opt/exp", "/etc/exp", "/var/lib/exp", "/run/exp")
UNIT_DIR = "/etc/systemd/system"
BIN_DIR = "/usr/local/bin"
PROTECTED = frozenset(ALLOWED_ROOTS) | {UNIT_DIR, BIN_DIR}
# Plain system directories above the roots: they exist on every host; only a tmp test root lacks them.
_ANCESTORS = frozenset(
    {
        "/etc",
        "/opt",
        "/run",
        "/var",
        "/var/lib",
        "/usr",
        "/usr/local",
        "/usr/local/bin",
        "/etc/systemd",
        "/etc/systemd/system",
    }
)


def _lexical_ok(logical: PurePosixPath) -> bool:
    s = str(logical)
    for root in ALLOWED_ROOTS:
        if s == root or s.startswith(root + "/"):
            return True
    if logical.parent == PurePosixPath(UNIT_DIR) and UNIT_RE.match(logical.name):
        return True
    return logical.parent == PurePosixPath(BIN_DIR) and bool(BIN_RE.match(logical.name))


class Paths:
    """All agent paths, derived from one place. `root` is a prefix for tests ("/" on a host).
    `uid`/`gid` are the owner the agent expects for root-owned files ("0" on a host)."""

    def __init__(self, root: str | os.PathLike[str] = "/", uid: int = 0, gid: int = 0) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.uid, self.gid = uid, gid
        self.opt = self.host("/opt/exp")
        self.etc = self.host("/etc/exp")
        self.var = self.host("/var/lib/exp")
        self.run = self.host("/run/exp")
        self.systemd = self.host(UNIT_DIR)
        self.usr_bin = self.host(BIN_DIR)
        self.proc = self.host("/proc")
        self.sys = self.host("/sys")
        self.agent_json = self.etc / "agent.json"
        self.agent_state = self.var / "agent"

    def host(self, logical: str) -> Path:
        """Map a logical absolute path under the root prefix (no checks)."""
        rel = logical.lstrip("/")
        return self.root / rel if rel else self.root

    # ----- per-component locations (names validated: they end up in paths) -----
    @staticmethod
    def _c(component: str) -> str:
        if not isinstance(component, str) or not COMPONENT_RE.match(component):
            raise PathRefused(f"invalid component name {component!r}")
        return component

    @staticmethod
    def _v(version: str) -> str:
        if not isinstance(version, str) or not VERSION_RE.match(version):
            raise PathRefused(f"invalid version {version!r}")
        return version

    def comp_opt(self, c: str) -> Path:
        return self.opt / self._c(c)

    def version_dir(self, c: str, version: str) -> Path:
        return self.opt / self._c(c) / self._v(version)

    def current(self, c: str) -> Path:
        return self.opt / self._c(c) / "current"

    def etc_dir(self, c: str) -> Path:
        return self.etc / self._c(c)

    def config(self, c: str) -> Path:
        return self.etc / self._c(c) / "config.json"

    def creds_dir(self, c: str) -> Path:
        return self.etc / self._c(c) / "creds"

    def state_dir(self, c: str) -> Path:
        return self.var / self._c(c)

    def run_dir(self, c: str) -> Path:
        return self.run / self._c(c)

    def unit(self, name: str) -> Path:
        if not UNIT_RE.match(name):
            raise PathRefused(f"unit name {name!r} does not match exp-*.service|timer")
        return self.systemd / name

    def bin_link(self, c: str) -> Path:
        return self.usr_bin / f"exp-{self._c(c)}"

    def logical(self, path: str | os.PathLike[str]) -> str:
        """Logical (host) spelling of a real path under the root."""
        p = Path(os.path.normpath(os.fspath(path)))
        try:
            rel = p.relative_to(self.root)
        except ValueError:
            raise PathRefused(f"path {p} is outside the agent root") from None
        return "/" + str(rel) if str(rel) != "." else "/"

    # ----- the guard -----
    def guard(self, path: str | os.PathLike[str]) -> Path:
        """Return the (normalised) path if it is inside the allowed roots, else raise PathRefused."""
        s = os.fspath(path)
        if "\x00" in s:
            raise PathRefused("path contains NUL")
        p = Path(s)
        if not p.is_absolute():
            raise PathRefused(f"path {s!r} is not absolute")
        if ".." in p.parts:
            raise PathRefused(f"path {s!r} contains '..'")
        norm = Path(os.path.normpath(s))
        logical = PurePosixPath(self.logical(norm))
        if not _lexical_ok(logical):
            raise PathRefused(f"path {logical} is outside the allowed roots")
        real = Path(os.path.realpath(norm))
        try:
            rel = real.relative_to(Path(os.path.realpath(self.root)))
        except ValueError:
            raise PathRefused(f"path {logical} resolves outside the agent root") from None
        real_logical = PurePosixPath("/" + str(rel)) if str(rel) != "." else PurePosixPath("/")
        if not _lexical_ok(real_logical):
            raise PathRefused(f"path {logical} resolves to {real_logical}, outside the allowed roots")
        return norm


class SafeFS:
    """Filesystem operations confined by `Paths.guard`. Ownership changes are `lchown` only."""

    def __init__(self, paths: Paths, lchown: Callable[[str, int, int], None] | None = None) -> None:
        self.paths = paths
        self._lchown = lchown or os.lchown

    def g(self, path: str | os.PathLike[str]) -> Path:
        return self.paths.guard(path)

    # reads
    def exists(self, path: str | os.PathLike[str]) -> bool:
        return os.path.lexists(self.g(path))

    def is_dir(self, path: str | os.PathLike[str]) -> bool:
        p = self.g(path)
        return stat.S_ISDIR(os.lstat(p).st_mode) if os.path.lexists(p) else False

    def lstat(self, path: str | os.PathLike[str]) -> os.stat_result:
        return os.lstat(self.g(path))

    def listdir(self, path: str | os.PathLike[str]) -> list[str]:
        p = self.g(path)
        try:
            return sorted(os.listdir(p))
        except FileNotFoundError:
            return []

    def read_bytes(self, path: str | os.PathLike[str], max_bytes: int = 8 * 1024 * 1024) -> bytes | None:
        """Contents of a regular file (never through a symlink leaf), or None when absent."""
        p = self.g(path)
        try:
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise PathRefused(f"cannot read {self.paths.logical(p)}: {exc.strerror}") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PathRefused(f"{self.paths.logical(p)} is not a regular file")
            if st.st_size > max_bytes:
                raise PathRefused(f"{self.paths.logical(p)} is larger than {max_bytes} bytes")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                return fh.read(max_bytes + 1)
        finally:
            os.close(fd)

    def readlink(self, path: str | os.PathLike[str]) -> str | None:
        p = self.g(path)
        try:
            return os.readlink(p)
        except (FileNotFoundError, OSError):
            return None

    # writes
    def write(self, path: str | os.PathLike[str], data: bytes | str, mode: int = 0o644) -> None:
        atomic_write(self.g(path), data, mode)

    def mkdir(self, path: str | os.PathLike[str], mode: int = 0o755) -> Path:
        """Create a directory (and missing parents, all inside the roots). An existing symlink or
        non-directory is refused; the final mode is applied to the leaf only if we created it."""
        p = self.g(path)
        if os.path.lexists(p):
            if not stat.S_ISDIR(os.lstat(p).st_mode):
                raise PathRefused(f"{self.paths.logical(p)} exists and is not a directory")
            return p
        parent = p.parent
        if not os.path.lexists(parent):
            if self._within_roots(parent):
                self.mkdir(parent, 0o755)
            elif self.paths.logical(parent) in _ANCESTORS:
                os.makedirs(parent, mode=0o755, exist_ok=True)
        os.mkdir(p, mode)
        os.chmod(p, mode)
        return p

    def _within_roots(self, p: Path) -> bool:
        try:
            self.g(p)
        except PathRefused:
            return False
        return True

    def remove(self, path: str | os.PathLike[str]) -> bool:
        """Unlink a file or symlink (never a directory). False when absent."""
        p = self.g(path)
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            return False
        if stat.S_ISDIR(st.st_mode):
            raise PathRefused(f"{self.paths.logical(p)} is a directory; use rmtree")
        os.unlink(p)
        return True

    def rmtree(self, path: str | os.PathLike[str]) -> bool:
        """Remove a directory tree (symlinks inside are unlinked, never followed)."""
        p = self.g(path)
        if self.paths.logical(p) in PROTECTED:
            raise PathRefused(f"refusing to remove protected root {self.paths.logical(p)}")
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            os.unlink(p)
            return True
        shutil.rmtree(p)
        return True

    def rename(self, src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        s, d = self.g(src), self.g(dst)
        os.rename(s, d)

    def symlink(self, target: str, link: str | os.PathLike[str]) -> None:
        """Create/replace `link` -> `target` atomically. `target` must be relative (so the link is
        position independent) and must resolve inside the allowed roots."""
        lp = self.g(link)
        if os.path.isabs(target) or "\x00" in target:
            raise PathRefused("symlink targets must be relative")
        resolved = Path(os.path.normpath(lp.parent / target))
        self.g(resolved)
        tmp = lp.parent / f".{lp.name}.{os.getpid()}.lnk"
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        os.symlink(target, tmp)
        os.replace(tmp, lp)

    def chmod(self, path: str | os.PathLike[str], mode: int) -> None:
        p = self.g(path)
        if stat.S_ISLNK(os.lstat(p).st_mode):
            raise PathRefused("refusing chmod through a symlink")
        os.chmod(p, mode)

    def lchown(self, path: str | os.PathLike[str], uid: int, gid: int) -> None:
        """Ownership change on a path root just created: lchown only, never through a symlink,
        and only when the parent directory is not writable by anyone but its owner (root)."""
        p = self.g(path)
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode):
            raise PathRefused("refusing to chown a symlink")
        pst = os.lstat(p.parent)
        if stat.S_ISLNK(pst.st_mode) or pst.st_uid != self.paths.uid or pst.st_mode & 0o022:
            raise PathRefused(
                f"refusing to chown inside {self.paths.logical(p.parent)}: parent is "
                "not a root-owned, non-service-writable directory"
            )
        self._lchown(str(p), uid, gid)
