"""/etc/exp/agent.json: manager_url, agent_id, agent_secret, release_pubkey_pem (root 0600).

Read safely: O_NOFOLLOW, regular file, owned by root, no group/other access, size-bounded, strict
JSON, validated with exp_common.config. The secret is never logged or put in an error message.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import stat
from dataclasses import dataclass
from urllib.parse import urlsplit

from exp_common import config as exp_config
from exp_common import ids as exp_ids
from exp_common.atomic import atomic_write_json

from .pathguard import Paths, SafeFS

log = logging.getLogger(__name__)

MAX_CONFIG_BYTES = 64 * 1024
_HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")

AGENT_CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "manager_url": {"type": "string", "minLength": 9, "maxLength": 512},
        "agent_id": {"$ref": "common.schema.json#/$defs/h_id"},
        "agent_secret": {"$ref": "common.schema.json#/$defs/expa_token"},
        "release_pubkey_pem": {"type": "string", "maxLength": 4096, "pattern": "^-----BEGIN PUBLIC KEY-----"},
    },
    "required": ["manager_url", "agent_id", "agent_secret", "release_pubkey_pem"],
    "additionalProperties": False,
}


class AgentConfigError(exp_config.ConfigError):
    """agent.json is unreadable, unsafe or invalid (message names the reason, never the secret)."""


@dataclass
class AgentConfig:
    manager_url: str
    agent_id: str
    agent_secret: str
    release_pubkey_pem: str

    def __repr__(self) -> str:  # never leak the secret through repr()/logging
        return f"AgentConfig(manager_url={self.manager_url!r}, agent_id={self.agent_id!r}, secret=<hidden>)"

    def to_json(self) -> dict[str, str]:
        return {
            "manager_url": self.manager_url,
            "agent_id": self.agent_id,
            "agent_secret": self.agent_secret,
            "release_pubkey_pem": self.release_pubkey_pem,
        }


def normalise_manager_url(url: str, allow_http: bool = False) -> str:
    """Origin only: https://host[:port]. No userinfo, path, query or fragment."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise AgentConfigError(f"manager_url is not a valid URL ({exc})") from None
    if not (parts.scheme == "https" or (allow_http and parts.scheme == "http")):
        raise AgentConfigError("manager_url must be an https:// URL")
    host = parts.hostname or ""
    if ":" in host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise AgentConfigError("manager_url host is not valid") from None
    elif not _HOST_RE.match(host):
        raise AgentConfigError("manager_url host is not valid")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise AgentConfigError("manager_url must be just scheme://host[:port]")
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc += f":{port}"
    return f"{parts.scheme}://{netloc}"


def _read_private(path: str, expect_uid: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        raise AgentConfigError(f"{path}: not found (host not enrolled?)") from None
    except OSError as exc:  # ELOOP for a symlink, EACCES...
        raise AgentConfigError(f"{path}: cannot open ({exc.strerror}); symlinks are refused") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AgentConfigError(f"{path}: not a regular file")
        if st.st_uid != expect_uid:
            raise AgentConfigError(f"{path}: must be owned by uid {expect_uid} (found {st.st_uid})")
        if st.st_mode & 0o077:
            raise AgentConfigError(f"{path}: mode {st.st_mode & 0o777:04o} is too open; must be 0600")
        if st.st_size > MAX_CONFIG_BYTES:
            raise AgentConfigError(f"{path}: larger than {MAX_CONFIG_BYTES} bytes")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(MAX_CONFIG_BYTES + 1)
    finally:
        os.close(fd)


def load_agent_config(
    paths: Paths, path: str | os.PathLike[str] | None = None, allow_http: bool = False
) -> AgentConfig:
    p = os.fspath(path) if path is not None else str(paths.agent_json)
    raw = _read_private(p, paths.uid)
    try:
        doc = exp_config.parse_json(raw, what=p)
    except exp_config.ConfigError as exc:
        raise AgentConfigError(exc.summary) from None
    issues = exp_config.iter_errors(doc, AGENT_CONFIG_SCHEMA)
    if issues:
        raise AgentConfigError(f"{p}: invalid agent config", issues)
    url = normalise_manager_url(doc["manager_url"], allow_http=allow_http)
    return AgentConfig(url, doc["agent_id"], doc["agent_secret"], doc["release_pubkey_pem"])


def save_agent_config(fs: SafeFS, cfg: AgentConfig) -> None:
    """Atomic 0600 write of agent.json (enrol, rotate)."""
    if not exp_ids.is_token(cfg.agent_secret, "expa"):
        raise AgentConfigError("refusing to save a malformed agent secret")
    fs.mkdir(fs.paths.etc, 0o755)
    atomic_write_json(fs.g(fs.paths.agent_json), cfg.to_json(), mode=0o600)
