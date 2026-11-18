"""Atomic, symlink-safe file writes.

``atomic_write`` writes a temp file in the destination directory (opened O_CREAT|O_EXCL|
O_NOFOLLOW, mode 0600 until finished), fchmods it to the requested mode, fsyncs, renames it over
the target, then fsyncs the directory. Readers see the old or the new file, never a partial one.

Refusals (AtomicWriteError): the parent directory is a symlink, the target is an existing
symlink, or the target exists and is not a regular file. The parent is opened with O_NOFOLLOW and
all operations are relative to that directory fd, so a symlink swapped in after the check cannot
redirect the write.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any, Union

__all__ = ["AtomicWriteError", "atomic_write", "atomic_write_text", "atomic_write_json"]


class AtomicWriteError(OSError):
    """The write was refused or failed; the target is untouched."""


def atomic_write(path: Union[str, Path], data: Union[bytes, str], mode: int = 0o644) -> None:
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or str")
    p = Path(os.path.abspath(os.fspath(path)))
    name = p.name
    if not name or name in (".", ".."):
        raise AtomicWriteError(f"invalid target file name: {path!r}")
    parent = p.parent
    try:
        if stat.S_ISLNK(os.lstat(parent).st_mode):
            raise AtomicWriteError(f"refusing to write: parent directory {parent} is a symlink")
        dfd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                      | getattr(os, "O_CLOEXEC", 0))
    except AtomicWriteError:
        raise
    except OSError as exc:
        raise AtomicWriteError(f"cannot open directory {parent}: {exc.strerror}") from exc
    tmp = None
    try:
        try:
            st = os.lstat(name, dir_fd=dfd)
        except FileNotFoundError:
            st = None
        if st is not None:
            if stat.S_ISLNK(st.st_mode):
                raise AtomicWriteError(f"refusing to write: target {p} is a symlink")
            if not stat.S_ISREG(st.st_mode):
                raise AtomicWriteError(f"refusing to write: target {p} is not a regular file")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = -1
        for _ in range(8):
            tmp = f".{name}.{secrets.token_hex(6)}.tmp"
            try:
                fd = os.open(tmp, flags, 0o600, dir_fd=dfd)
                break
            except FileExistsError:
                continue
        if fd < 0:
            tmp = None
            raise AtomicWriteError(f"cannot create a temporary file next to {p}")
        try:
            view = memoryview(bytes(data))
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fchmod(fd, mode)          # before rename: the final file never exists with wrong mode
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = None
        os.fsync(dfd)
    except AtomicWriteError:
        raise
    except OSError as exc:
        raise AtomicWriteError(f"atomic write to {p} failed: {exc.strerror}") from exc
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
        os.close(dfd)


def atomic_write_text(path: Union[str, Path], text: str, mode: int = 0o644) -> None:
    atomic_write(path, text.encode("utf-8"), mode)


def atomic_write_json(path: Union[str, Path], obj: Any, mode: int = 0o644, indent: Union[int, None] = 2,
                      sort_keys: bool = True) -> None:
    """Write `obj` as UTF-8 JSON plus a trailing newline. NaN/Infinity are refused."""
    text = json.dumps(obj, indent=indent, sort_keys=sort_keys, ensure_ascii=False, allow_nan=False)
    atomic_write(path, text + "\n", mode)
