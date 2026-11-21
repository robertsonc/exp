"""Runner configuration (``exp.runner.config/1``), credentials and runtime paths.

The config document carries no secrets (01 section 9.4). Credentials come from ``$CREDENTIALS_DIRECTORY``
(systemd ``LoadCredential=``) through :mod:`exp_common.creds`; values are never logged.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Any

from exp_common import config as exp_config
from exp_common import creds as exp_creds
from exp_common import ids as exp_ids

log = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/etc/exp/runner/config.json"
DEFAULT_STATE_DIR = "/var/lib/exp/runner"
DEFAULT_RUN_DIR = "/run/exp/runner"
DEFAULT_LISTEN = ("udp:5514", "tcp:5514", "tls:6514")
DEFAULT_CHANNEL_URL = "http://127.0.0.1:8480/local/v1"
MAX_INTEGRATIONS_BYTES = 64 * 1024


class RunnerConfigError(Exception):
    """The config is schema-valid but unusable (e.g. a privileged syslog port)."""


@dataclasses.dataclass(frozen=True)
class SyslogCfg:
    listen: tuple[tuple[str, int], ...]
    bind: str
    allow: tuple[ipaddress.IPv4Network, ...]
    rate_limit_lines_per_s: int
    max_line_bytes: int
    ring_minutes: int
    tls_mode: str


@dataclasses.dataclass(frozen=True)
class NetworkCfg:
    """Identity-resolution inputs (CR-m6-runner-network)."""

    require_real_client_ip: bool
    client_subnets: tuple[ipaddress.IPv4Network, ...]
    translated_addresses: frozenset[str]
    zone_subnets: tuple[tuple[ipaddress.IPv4Network, str], ...]


@dataclasses.dataclass(frozen=True)
class RunnerConfig:
    runner_id: str
    site: str
    collector_url: str
    collector_pin: str
    drills_enabled: bool
    correlation_enabled: bool
    window_before_s: int
    window_after_s: int
    poll_interval_s: int
    mist: dict[str, Any] | None
    ec: dict[str, Any] | None
    syslog: SyslogCfg
    network: NetworkCfg
    scrub_after_diagnosis: bool
    channel_url: str | None
    raw: dict[str, Any] = dataclasses.field(repr=False, default_factory=dict)


@dataclasses.dataclass(frozen=True)
class Paths:
    state_dir: Path
    run_dir: Path
    creds_dir: Path | None
    syslog_db: Path
    work_db: Path
    tls_dir: Path
    health_file: Path

    @classmethod
    def resolve(cls, state_dir: str | None = None, run_dir: str | None = None, creds_dir: str | None = None,
                syslog_db: str | None = None) -> Paths:
        sd = Path(state_dir or os.environ.get("STATE_DIRECTORY", "").split(":")[0] or DEFAULT_STATE_DIR)
        rd = Path(run_dir or os.environ.get("RUNTIME_DIRECTORY", "").split(":")[0] or DEFAULT_RUN_DIR)
        cd = creds_dir or os.environ.get("CREDENTIALS_DIRECTORY")
        return cls(sd, rd, Path(cd) if cd else None, Path(syslog_db) if syslog_db else sd / "syslog.db",
                   sd / "runner.db", sd / "tls", rd / "health.json")


def _net(text: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(text, strict=False)  # type: ignore[return-value]


def parse_listen(entries: list[str]) -> tuple[tuple[str, int], ...]:
    out = []
    for e in entries:
        proto, _, port_s = e.partition(":")
        port = int(port_s)
        if not 1024 <= port <= 65535:
            raise RunnerConfigError(f"syslog.listen {e!r}: privileged or invalid port (the runner never binds ports below 1024)")
        out.append((proto, port))
    return tuple(out)


def parse_config(doc: dict[str, Any]) -> RunnerConfig:
    corr = doc.get("correlation") or {}
    srcs = corr.get("sources") or {}
    sl = srcs.get("syslog") or {}
    net = corr.get("network") or {}
    listen = parse_listen(list(sl.get("listen") or DEFAULT_LISTEN))
    syslog = SyslogCfg(
        listen=listen, bind=str(sl.get("bind", "0.0.0.0")),  # noqa: S104 - allowlisted receiver, SR-24
        allow=tuple(_net(c) for c in sl.get("allow", [])),
        rate_limit_lines_per_s=int(sl.get("rate_limit_lines_per_s", 200)),
        max_line_bytes=int(sl.get("max_line_bytes", 4096)),
        ring_minutes=int(sl.get("ring_minutes", 60)),
        tls_mode=str((sl.get("tls") or {}).get("mode", "self_signed")))
    network = NetworkCfg(
        require_real_client_ip=bool(net.get("require_real_client_ip", True)),
        client_subnets=tuple(_net(c) for c in net.get("client_subnets", [])),
        translated_addresses=frozenset(str(a) for a in net.get("translated_addresses", [])),
        zone_subnets=tuple((_net(z["cidr"]), z["zone"]) for z in net.get("zone_subnets", [])))
    chan = corr.get("speedtest_channel")
    coll = doc["collector"]
    return RunnerConfig(
        runner_id=doc["runner_id"], site=doc["site"], collector_url=coll["url"],
        collector_pin=coll["tls_fingerprint_sha256"], drills_enabled=bool(doc.get("drills_enabled")),
        correlation_enabled=bool(corr.get("enabled", False)),
        window_before_s=int(corr.get("window_before_s", 300)), window_after_s=int(corr.get("window_after_s", 120)),
        poll_interval_s=int(corr.get("poll_interval_s", 5)),
        mist=srcs.get("mist") if isinstance(srcs.get("mist"), dict) else None,
        ec=srcs.get("ec") if isinstance(srcs.get("ec"), dict) else None,
        syslog=syslog, network=network,
        scrub_after_diagnosis=bool((corr.get("privacy") or {}).get("scrub_after_diagnosis", False)),
        channel_url=(chan or {}).get("url") if chan else None, raw=doc)


def load_config(path: str | Path) -> RunnerConfig:
    """Load and validate. Raises ``exp_config.ConfigError`` / ``RunnerConfigError``. M5 drill fields are ignored
    with one log line (M6 builds no drills)."""
    doc = exp_config.load_config(path, "runner.config")
    cfg = parse_config(doc)
    if cfg.drills_enabled or doc.get("drills") or doc.get("pullers"):
        log.warning("drill/puller fields (M5) are present and ignored: this runner build correlates speedtests only")
    return cfg


class CredStore:
    """Credentials of the runner. Everything is optional at load time; ``missing_for`` says what a config needs."""

    def __init__(self, directory: str | Path | None) -> None:
        self.directory = directory

    def _text(self, name: str) -> str | None:
        if self.directory is None:
            return None
        try:
            v = exp_creds.read_credential(name, self.directory).strip()
        except exp_creds.CredentialError:
            return None
        return v or None

    def collector_token(self) -> str | None:
        v = self._text("collector_token")
        return v if v and exp_ids.is_token(v, "expr_") else None

    def channel_token(self) -> str | None:
        v = self._text("speedtest_channel_token")
        return v if v and exp_ids.is_token(v, "expl_") else None

    def device_key_secret(self) -> str | None:
        v = self._text("device_key_secret")
        return v if v and exp_ids.is_token(v, "expk_") else None

    def integrations(self) -> dict[str, Any]:
        """``{mist: {api_base, token}, ec: {url, api_key}}``; unusable entries are dropped (never an SSE entry)."""
        if self.directory is None:
            return {}
        try:
            doc = exp_creds.read_credential_json("integrations.json", self.directory, max_bytes=MAX_INTEGRATIONS_BYTES)
        except (exp_creds.CredentialError, ValueError):
            return {}
        out: dict[str, Any] = {}
        if isinstance(doc, dict):
            m, e = doc.get("mist"), doc.get("ec")
            if isinstance(m, dict) and isinstance(m.get("api_base"), str) and isinstance(m.get("token"), str):
                out["mist"] = {"api_base": m["api_base"], "token": m["token"]}
            if isinstance(e, dict) and isinstance(e.get("url"), str) and isinstance(e.get("api_key"), str):
                out["ec"] = {"url": e["url"], "api_key": e["api_key"]}
        return out

    def syslog_tls_files(self) -> tuple[Path, Path] | None:
        if self.directory is None:
            return None
        crt, key = Path(self.directory) / "syslog_tls.crt", Path(self.directory) / "syslog_tls.key"
        if crt.is_file() and key.is_file() and crt.stat().st_size and key.stat().st_size:
            return crt, key
        return None

    def missing_for(self, cfg: RunnerConfig) -> list[str]:
        """Human-readable list of credentials the config needs and does not have."""
        if not cfg.correlation_enabled:
            return []
        out = []
        if self.collector_token() is None:
            out.append("collector_token (expr_)")
        if self.device_key_secret() is None:
            out.append("device_key_secret (expk_)")
        if cfg.channel_url and self.channel_token() is None:
            out.append("speedtest_channel_token (expl_)")
        if cfg.syslog.tls_mode == "provided" and self.syslog_tls_files() is None:
            out.append("syslog_tls.crt / syslog_tls.key")
        ints = self.integrations()
        if cfg.mist is not None and "mist" not in ints:
            out.append("integrations.json mist {api_base, token}")
        if cfg.ec is not None and "ec" not in ints:
            out.append("integrations.json ec {url, api_key}")
        return out


def dump(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)
