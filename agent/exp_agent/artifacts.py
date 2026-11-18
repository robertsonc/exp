"""Artifact download (verified against the signed manifest) and SAFE UNPACK (06-agent.md section 6).

Unpack rules, enforced member by member into a private staging dir that is deleted on any violation:
absolute paths, `..`, NUL, symlinks or hardlinks pointing outside the tree, symlink chains that could
redirect later writes, device/FIFO members, setuid/setgid/sticky bits, duplicate members, and absurd
sizes are refused. Files are created with O_EXCL|O_NOFOLLOW; ownership comes from the agent (root),
never from the archive. Nothing is unpacked before signature + sha256 verification.
"""

from __future__ import annotations

import logging
import os
import posixpath
import secrets
import stat
import tarfile
from pathlib import Path
from typing import Any

from .client import ManagerClient
from .errors import UnsafeArchive, VerifyError
from .pathguard import SafeFS
from .verify import sha256_file

log = logging.getLogger(__name__)

MAX_MEMBERS = 50_000
MAX_UNPACKED_BYTES = 3 * 1024**3
MAX_NAME = 1024
MAX_COMPONENT = 255


def _clean_member_path(name: str) -> list[str]:
    if "\x00" in name or "\\" in name:
        raise UnsafeArchive(f"unsafe member name {name!r}")
    if name.startswith("/"):
        raise UnsafeArchive(f"absolute path in archive: {name!r}")
    if len(name) > MAX_NAME:
        raise UnsafeArchive("member name too long")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnsafeArchive(f"'..' in archive path: {name!r}")
    if any(len(p) > MAX_COMPONENT for p in parts):
        raise UnsafeArchive("member name component too long")
    return parts


def _check_link_target(member_parts: list[str], target: str, hard: bool, top: str) -> str:
    """Return the in-tree relative path (below `top`) a link points at; raise if it can escape."""
    if "\x00" in target or "\\" in target or target.startswith("/"):
        raise UnsafeArchive(f"link target {target!r} is absolute or malformed")
    if hard:  # hardlink targets are archive-root relative paths
        parts = _clean_member_path(target)
        if not parts or parts[0] != top:
            raise UnsafeArchive(f"hardlink target {target!r} is outside the artifact")
        return "/".join(parts[1:])
    comps = [p for p in target.split("/") if p not in ("", ".")]
    seen_name = False
    for c in comps:
        if c == "..":
            if seen_name:
                # `a/..` through a symlinked `a` could climb out of the tree: refuse the pattern outright
                raise UnsafeArchive(f"symlink target {target!r} uses '..' after a name")
        else:
            seen_name = True
    base = member_parts[1:-1]  # directory of the link below top
    resolved = posixpath.normpath("/".join(base + comps)) if (base or comps) else "."
    if resolved == ".." or resolved.startswith("../"):
        raise UnsafeArchive(f"symlink target {target!r} escapes the artifact")
    return resolved


def safe_unpack(
    archive: str | os.PathLike[str], dest: str | os.PathLike[str], expect_top_prefix: str
) -> None:
    """Unpack `archive` (tar.gz) into the existing, empty directory `dest`, stripping the single top directory
    (its name must start with `expect_top_prefix`). Raises UnsafeArchive; the caller deletes `dest`."""
    dest_path = Path(dest)
    if os.listdir(dest_path):
        raise UnsafeArchive("staging directory is not empty")
    top: str | None = None
    seen: set[str] = set()
    links: set[str] = set()
    regular: set[str] = set()
    total = 0
    count = 0
    try:
        tf = tarfile.open(archive, "r:gz")  # noqa: SIM115 - closed in finally
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise UnsafeArchive(f"not a readable tar.gz archive: {exc}") from None
    dfd = os.open(dest_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for m in tf:
            count += 1
            if count > MAX_MEMBERS:
                raise UnsafeArchive("too many archive members")
            parts = _clean_member_path(m.name)
            if not parts:
                continue
            if top is None:
                top = parts[0]
                if not top.startswith(expect_top_prefix):
                    raise UnsafeArchive(f"unexpected top directory {top!r} (expected {expect_top_prefix}...)")
            if parts[0] != top:
                raise UnsafeArchive("archive has more than one top-level entry")
            if len(parts) == 1:
                if not m.isdir():
                    raise UnsafeArchive("the top-level entry must be a directory")
                continue
            rel_parts = parts[1:]
            rel = "/".join(rel_parts)
            if rel in seen:
                raise UnsafeArchive(f"duplicate archive member {rel!r}")
            for i in range(1, len(rel_parts)):
                if "/".join(rel_parts[:i]) in links:
                    raise UnsafeArchive(f"member {rel!r} is below a symlink")
            if m.mode & 0o7000:
                raise UnsafeArchive(f"setuid/setgid/sticky bit on {rel!r}")
            if m.isdir():
                seen.add(rel)
                _mkdirs(dfd, rel_parts)
            elif m.isreg():
                seen.add(rel)
                total += m.size
                if total > MAX_UNPACKED_BYTES:
                    raise UnsafeArchive("archive unpacks to too much data")
                _write_file(dfd, tf, m, rel_parts)
                regular.add(rel)
            elif m.issym():
                _check_link_target(parts, m.linkname, False, top)
                seen.add(rel)
                links.add(rel)
                _mkdirs(dfd, rel_parts[:-1])
                pfd = _open_dir(dfd, rel_parts[:-1])
                try:
                    os.symlink(m.linkname, rel_parts[-1], dir_fd=pfd)
                finally:
                    os.close(pfd)
            elif m.islnk():
                target = _check_link_target(parts, m.linkname, True, top)
                if target not in regular:
                    raise UnsafeArchive(f"hardlink {rel!r} does not refer to an earlier regular file")
                seen.add(rel)
                _mkdirs(dfd, rel_parts[:-1])
                parent_fd = _open_dir(dfd, rel_parts[:-1])
                src_fd = _open_dir(dfd, target.split("/")[:-1])
                try:
                    os.link(
                        target.split("/")[-1],
                        rel_parts[-1],
                        src_dir_fd=src_fd,
                        dst_dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                finally:
                    os.close(parent_fd)
                    os.close(src_fd)
                regular.add(rel)
            else:
                raise UnsafeArchive(f"special file (device/FIFO/other) in archive: {rel!r}")
        if top is None:
            raise UnsafeArchive("archive is empty")
    except (tarfile.TarError, EOFError, OSError, UnicodeError) as exc:
        if isinstance(exc, UnsafeArchive):
            raise
        raise UnsafeArchive(f"archive could not be unpacked safely: {type(exc).__name__}") from None
    finally:
        tf.close()
        os.close(dfd)


def _open_dir(dfd: int, parts: list[str]) -> int:
    """Open `parts` below dfd component by component with O_NOFOLLOW (no symlink can be traversed)."""
    cur = os.dup(dfd)
    for p in parts:
        try:
            nxt = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur)
        finally:
            os.close(cur)
        cur = nxt
    return cur


def _mkdirs(dfd: int, parts: list[str]) -> None:
    cur = os.dup(dfd)
    try:
        for p in parts:
            try:
                os.mkdir(p, 0o755, dir_fd=cur)
            except FileExistsError:
                pass
            nxt = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur)
            os.close(cur)
            cur = nxt
    finally:
        os.close(cur)


def _write_file(dfd: int, tf: tarfile.TarFile, m: tarfile.TarInfo, parts: list[str]) -> None:
    _mkdirs(dfd, parts[:-1])
    parent = _open_dir(dfd, parts[:-1])
    try:
        mode = (m.mode & 0o755) | 0o400
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            src = tf.extractfile(m)
            if src is None:
                raise UnsafeArchive(f"cannot read member {'/'.join(parts)!r}")
            remaining = m.size
            while remaining > 0:
                chunk = src.read(min(1 << 20, remaining))
                if not chunk:
                    raise UnsafeArchive("archive member is truncated")
                os.write(fd, chunk)
                remaining -= len(chunk)
            os.fchmod(fd, mode & ~0o022)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def download_verified(client: ManagerClient, fs: SafeFS, art: dict[str, Any], entry: dict[str, Any]) -> Path:
    """Download artifact `art` to a private file under /var/lib/exp/agent/downloads; check size and
    sha256 against the SIGNED manifest entry. Returns the path (caller deletes it)."""
    ddir = fs.paths.agent_state / "downloads"
    fs.mkdir(ddir, 0o700)
    path = ddir / f"{art['id']}.{secrets.token_hex(4)}.part"
    fs.g(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        try:
            digest = client.download_artifact(art["url"], fd, int(entry["size"]))
        finally:
            os.close(fd)
        if digest != entry["sha256"]:
            raise VerifyError(f"artifact {art['name']}: sha256 does not match the signed manifest")
    except BaseException:
        fs.remove(path)
        raise
    return path


def stage_and_unpack(
    client: ManagerClient,
    fs: SafeFS,
    art: dict[str, Any],
    entry: dict[str, Any],
    component: str,
    parent: Path,
) -> Path:
    """Download + verify + unpack into a fresh staging dir inside `parent`; returns the staging dir."""
    archive = download_verified(client, fs, art, entry)
    staging = parent / f".staging-{secrets.token_hex(6)}"
    try:
        fs.mkdir(parent, 0o755)
        fs.g(staging)
        os.mkdir(staging, 0o755)
        # defence in depth: re-hash right before unpacking (the file was only ever written by us)
        if sha256_file(archive) != entry["sha256"]:
            raise VerifyError("artifact changed on disk after verification")
        safe_unpack(archive, staging, f"exp-{component}-")
    except BaseException:
        fs.rmtree(staging)
        raise
    finally:
        fs.remove(archive)
    return staging


def is_regular_nofollow(path: str | os.PathLike[str]) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False
