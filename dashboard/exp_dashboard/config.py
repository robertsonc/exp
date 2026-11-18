"""Dashboard configuration (exp.dashboard.config/1) plus runtime paths.

The document is validated with ``exp_common.config`` against the frozen schema; an invalid config
means the service refuses to start (``load_settings`` raises ``ConfigError``). Paths that are not
part of the contract (state, creds, run dirs; dev TLS overrides) come from CLI flags or the
systemd environment (``STATE_DIRECTORY``, ``CREDENTIALS_DIRECTORY``, ``RUNTIME_DIRECTORY``).
"""
from __future__ import annotations

import os
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from exp_common import config as _cfg
from exp_common.tlspin import normalize_fingerprint

SCHEMA_NAME = "dashboard.config.schema.json"
DEFAULT_CONFIG = "/etc/exp/dashboard/config.json"
DEFAULT_STATE_DIR = "/var/lib/exp/dashboard"
DEFAULT_CREDS_DIR = "/etc/exp/dashboard/creds"
DEFAULT_RUN_DIR = "/run/exp/dashboard"
ConfigError = _cfg.ConfigError


@dataclass(frozen=True)
class CollectorCfg:
    collector_id: str
    site: str
    url: str
    pin: str


@dataclass(frozen=True)
class Settings:
    dashboard_id: str
    title: str
    url: str
    origin: str                      # scheme://host[:port] of `url`
    https: tuple[str, int]
    http_redirect: tuple[str, int] | None
    collectors: tuple[CollectorCfg, ...]
    voice: str
    timezone: str
    sso_issuer: str | None
    manager_url: str | None
    session_hours: int
    local_users: bool
    noc_tokens: bool
    tls_mode: str
    state_dir: Path
    creds_dir: Path
    run_dir: Path
    tls_cert: Path
    tls_key: Path

    @property
    def sessions_db(self) -> Path:
        return self.state_dir / "sessions.db"


def parse_hostport(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        raise ConfigError(f"bad host:port {value!r}")
    return host, int(port)


def _first_dir(env: str, default: str) -> str:
    v = os.environ.get(env)
    if v:
        return v.split(":")[0]
    return default


def origin_of(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = u.port
    return f"{u.scheme}://{host}" + (f":{port}" if port and port != 443 else "")


def load_settings(config_path: str | Path, *, state_dir: str | Path | None = None,
                  creds_dir: str | Path | None = None, run_dir: str | Path | None = None,
                  tls_cert: str | Path | None = None, tls_key: str | Path | None = None) -> Settings:
    doc = _cfg.load_config(config_path, SCHEMA_NAME)
    sd = Path(state_dir) if state_dir else Path(_first_dir("STATE_DIRECTORY", DEFAULT_STATE_DIR))
    cd = Path(creds_dir) if creds_dir else Path(_first_dir("CREDENTIALS_DIRECTORY", DEFAULT_CREDS_DIR))
    rd = Path(run_dir) if run_dir else Path(_first_dir("RUNTIME_DIRECTORY", DEFAULT_RUN_DIR))
    listen = doc["listen"]
    https = parse_hostport(listen["https"])
    redirect = parse_hostport(listen["http_redirect"]) if listen.get("http_redirect") else None
    seen: set[str] = set()
    collectors = []
    for c in doc["collectors"]:
        if c["collector_id"] in seen:
            raise ConfigError(f"duplicate collector_id {c['collector_id']!r}")
        seen.add(c["collector_id"])
        collectors.append(CollectorCfg(c["collector_id"], c["site"], c["url"].rstrip("/"),
                                       normalize_fingerprint(c["tls_fingerprint_sha256"])))
    auth = doc["auth"]
    sso = auth.get("sso") or {}
    mode = doc["tls"]["mode"]
    if tls_cert or tls_key:
        cert, key = Path(tls_cert or ""), Path(tls_key or "")
    elif mode == "provided":
        cert, key = cd / "tls.crt", cd / "tls.key"
    else:
        cert, key = sd / "tls" / "cert.pem", sd / "tls" / "key.pem"
    return Settings(
        dashboard_id=doc["dashboard_id"], title=doc["title"], url=doc["url"].rstrip("/"),
        origin=origin_of(doc["url"]), https=https, http_redirect=redirect,
        collectors=tuple(collectors), voice=doc.get("voice", "plain"),
        timezone=doc.get("timezone", "UTC"), sso_issuer=sso.get("issuer"),
        manager_url=sso.get("manager_url"), session_hours=int(auth.get("session_hours", 12)),
        local_users=bool(auth.get("local_users", True)), noc_tokens=bool(auth.get("noc_tokens", True)),
        tls_mode=mode, state_dir=sd, creds_dir=cd, run_dir=rd, tls_cert=cert, tls_key=key)
