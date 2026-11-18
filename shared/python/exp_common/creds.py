"""Named credentials from systemd ``LoadCredential=`` ($CREDENTIALS_DIRECTORY).

Each credential is one regular file in the credentials directory. Reads are hardened:
the name must be a plain file name, the file is opened relative to the directory fd with
O_NOFOLLOW (a symlink planted as a credential is refused), must be a regular file, and is
bounded in size. One trailing newline is stripped. Values are NEVER logged or included in
exceptions: errors name the credential file only.
"""
from __future__ import annotations

import json
import logging
import os
import re
import stat
from pathlib import Path
from typing import Any, Optional, Union

log = logging.getLogger(__name__)

MAX_CREDENTIAL_BYTES = 1024 * 1024
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class CredentialError(Exception):
    """Credential missing / unreadable / unsafe. The message never contains the value."""


def credentials_dir(directory: Union[str, Path, None] = None) -> Path:
    d = directory if directory is not None else os.environ.get("CREDENTIALS_DIRECTORY")
    if not d:
        raise CredentialError("no credentials directory: CREDENTIALS_DIRECTORY is not set "
                              "(is the unit missing LoadCredential=?)")
    return Path(d)


def read_credential_bytes(name: str, directory: Union[str, Path, None] = None,
                          max_bytes: int = MAX_CREDENTIAL_BYTES,
                          require_private: bool = False) -> bytes:
    """Raw bytes of credential `name` with one trailing b"\\n" stripped.
    `require_private=True` additionally refuses files readable by group/other."""
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise CredentialError(f"invalid credential name {name!r}")
    base = credentials_dir(directory)
    where = base / name
    try:
        dfd = os.open(str(base), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise CredentialError(f"credentials directory {base} is not usable ({exc.strerror})") from exc
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd)
        except FileNotFoundError as exc:
            raise CredentialError(f"credential file {where} is missing") from exc
        except OSError as exc:  # ELOOP for a symlink, EACCES, ...
            raise CredentialError(f"credential file {where} cannot be opened ({exc.strerror}); "
                                  "symlinks are refused") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise CredentialError(f"credential file {where} is not a regular file")
            if require_private and st.st_mode & 0o077:
                raise CredentialError(f"credential file {where} is accessible to group/other "
                                      f"(mode {st.st_mode & 0o777:04o})")
            if st.st_size > max_bytes:
                raise CredentialError(f"credential file {where} exceeds {max_bytes} bytes")
            chunks = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        except OSError as exc:
            raise CredentialError(f"credential file {where} cannot be read ({exc.strerror})") from exc
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
    if len(data) > max_bytes:
        raise CredentialError(f"credential file {where} exceeds {max_bytes} bytes")
    if data.endswith(b"\n"):
        data = data[:-1]
    log.debug("read credential %s (%d bytes)", name, len(data))
    return data


def read_credential(name: str, directory: Union[str, Path, None] = None,
                    max_bytes: int = MAX_CREDENTIAL_BYTES, require_private: bool = False) -> str:
    """Credential as UTF-8 text, one trailing newline stripped."""
    data = read_credential_bytes(name, directory, max_bytes, require_private)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CredentialError(f"credential {name!r} is not valid UTF-8") from exc


def read_credential_json(name: str, directory: Union[str, Path, None] = None,
                         max_bytes: int = MAX_CREDENTIAL_BYTES) -> Any:
    """Credential parsed as JSON. Parse errors report position only, never content."""
    text = read_credential(name, directory, max_bytes)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CredentialError(f"credential {name!r} is not valid JSON "
                              f"(line {exc.lineno}, column {exc.colno})") from None
    except RecursionError:
        raise CredentialError(f"credential {name!r} is nested too deeply") from None


def has_credential(name: str, directory: Union[str, Path, None] = None) -> bool:
    try:
        read_credential_bytes(name, directory)
    except CredentialError:
        return False
    return True


def optional_credential(name: str, directory: Union[str, Path, None] = None) -> Optional[str]:
    """Value, or None only when the file is simply absent; unsafe/unreadable files still raise."""
    try:
        return read_credential(name, directory)
    except CredentialError as exc:
        if str(exc).endswith("is missing"):
            return None
        raise
