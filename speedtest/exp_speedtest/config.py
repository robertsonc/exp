"""exp-speedtest configuration: ``exp.speedtest.config/1`` with the contract defaults applied, the filesystem
layout and the credentials (01-contracts.md section 14.7, CR-m6-spec-resolutions).

``load_speedtest_config`` validates with exp_common.config (JSON Schema) and refuses to start on anything
invalid. Credentials come from ``$CREDENTIALS_DIRECTORY`` (systemd ``LoadCredential=``) or ``--creds-dir``:

* ``collector_token``              ``exps_`` token for the collector (read again for every delivery: rotation = new file)
* ``runner_channel_token_sha256``  sha256 hex of the runner's ``expl_`` token (the box never holds the token itself)
* ``tls.crt`` / ``tls.key``        only when ``tls.mode = provided``

Stand-alone mode (no manager) uses exactly the same files; only where they come from differs.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Any

from exp_common import config as exp_config
from exp_common import creds as exp_creds

log = logging.getLogger(__name__)

SCHEMA_NAME = "exp.speedtest.config/1"
DEFAULT_CONFIG_PATH = "/etc/exp/speedtest/config.json"
DEFAULT_STATE_DIR = "/var/lib/exp/speedtest"
DEFAULT_RUN_DIR = "/run/exp/speedtest"
DEFAULT_ASSETS_DIR = "/etc/exp/speedtest/assets"

CRED_COLLECTOR_TOKEN = "collector_token"  # noqa: S105 - a credential FILE NAME, not a secret
CRED_CHANNEL_SHA = "runner_channel_token_sha256"
CRED_TLS_CRT = "tls.crt"
CRED_TLS_KEY = "tls.key"

DEFAULT_CONSENT_TEXT = ("We measure your connection speed and the network team will look at this device's Wi-Fi and "
                        "traffic metadata to diagnose it. No name or email is collected.")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class SpeedtestConfigError(ValueError):
    """Semantically invalid configuration (beyond what the JSON Schema checks)."""


@dataclasses.dataclass(frozen=True)
class Limits:
    tests_per_10min_per_ip: int = 6
    max_concurrent_per_ip: int = 1
    max_concurrent_tests: int = 20           # CR-m6-spec-resolutions A2
    max_concurrent_internet: int = 10
    bytes_local: int = 200_000_000           # CR-m6-spec-resolutions A2 (supersedes 400 MB)
    bytes_internet: int = 200_000_000
    leg_token_ttl_s: int = 60
    result_deadline_s: int = 180
    # fixed page-facing hints (not in the contract's config; the box enforces its own bounds regardless)
    streams_start: int = 4
    streams_max: int = 8
    ramp_min_bytes: int = 100_000
    ramp_max_bytes: int = 25_000_000
    ping_count: int = 20


@dataclasses.dataclass(frozen=True)
class CollectorRef:
    url: str
    tls_fingerprint_sha256: str
    fallback: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class CoreGuardCfg:
    iface: str | None
    util_pct: int = 70
    min_bytes: int = 5_000_000


class SpeedtestConfig:
    """Validated, defaulted view of the config document (``raw`` keeps the document for the public config hash)."""

    def __init__(self, doc: dict[str, Any]) -> None:
        self.raw = doc
        self.speedtest_id: str = doc["speedtest_id"]
        self.site: str = doc["site"]
        self.zones: dict[str, str] = {z["id"]: z["name"] for z in doc.get("zones", [])}
        subs = [(ipaddress.ip_network(s["cidr"], strict=False), s["zone"])
                for s in (doc.get("zone_labels") or {}).get("subnets", [])]
        subs.sort(key=lambda t: t[0].prefixlen, reverse=True)           # longest prefix first
        self.subnet_zones: list[tuple[ipaddress.IPv4Network, str]] = subs  # type: ignore[assignment]

        b = doc.get("branding") or {}
        self.title: str = b.get("title") or "Speed check"
        self.logo_artifact: str | None = b.get("logo_artifact")
        self.colors: dict[str, str] = dict(b.get("colors") or {})
        self.languages: list[str] = list(b.get("languages") or ["en"])
        self.copy: dict[str, str] = dict(b.get("copy") or {})
        c = doc.get("consent") or {}
        self.consent_text: str = c.get("text") or DEFAULT_CONSENT_TEXT
        self.consent_version: int = int(c.get("version", 1))
        self.show_network_details: bool = bool((doc.get("display") or {}).get("show_network_details", False))
        t = doc.get("targets") or {}
        self.target_down_mbps: float = float(t.get("down_mbps", 25))
        self.target_up_mbps: float = float(t.get("up_mbps", 10))

        lim = doc.get("limits") or {}
        known = {f.name for f in dataclasses.fields(Limits)}
        self.limits = Limits(**{k: int(v) for k, v in lim.items() if k in known})

        il = doc.get("internet_leg") or {}
        self.internet_enabled: bool = bool(il.get("enabled", True))
        self.internet_paused: bool = bool(il.get("paused", False))
        self.auto_pause_wan_util_pct: int = int(il.get("auto_pause_wan_util_pct", 80))

        s = doc["serve"]
        self.hostname: str = s["hostname"]
        self.listen_ip: str = s["listen_ip"]
        self.require_real_client_ip: bool = bool(s.get("require_real_client_ip", True))
        self.client_subnets = [ipaddress.ip_network(x, strict=False) for x in s.get("client_subnets", [])]
        self.translated_addresses = frozenset(ipaddress.ip_address(x) for x in s.get("translated_addresses", []))
        self.tls_mode: str = doc["tls"]["mode"]
        self._port: int | None = s.get("port")

        d = doc.get("dns_leg") or {}
        self.dns_zone: str | None = (d.get("zone") or "").lower().rstrip(".") or None
        self.dns_enabled: bool = bool(d.get("enabled", bool(self.dns_zone))) and self.dns_zone is not None
        self.dns_port: int = int(d.get("port", 53))

        p = doc.get("path") or {}
        self.path_gateway: str | None = p.get("gateway", "auto")
        self.path_edge: str | None = p.get("edge")
        self.path_edge1: str | None = p.get("edge1", "auto" if p.get("edge") else None)

        pr = doc.get("privacy") or {}
        self.retention_days: int = int(pr.get("retention_days", 30))
        self.scrub_after_diagnosis: bool = bool(pr.get("scrub_after_diagnosis", False))

        g = doc.get("core_guard") or {}
        self.core_guard = CoreGuardCfg(iface=g.get("iface"), util_pct=int(g.get("util_pct", 70)),
                                       min_bytes=int(g.get("min_bytes", 5_000_000)))

        col = doc["collector"]
        self.collector = CollectorRef(col["url"], col["tls_fingerprint_sha256"], tuple(col.get("fallback") or ()))
        listen = (doc.get("local_channel") or {}).get("listen", "127.0.0.1:8480")
        host, _, port = listen.rpartition(":")
        self.channel_host: str = host
        self.channel_port: int = int(port)
        if self.channel_host != "127.0.0.1" and not self.channel_host.startswith("127."):
            raise SpeedtestConfigError("local_channel.listen must be a loopback address")

    # --------------------------------------------------------------------------------------------- derived
    @property
    def listen_port(self) -> int:
        """80 when plain HTTP, 443 when TLS is provided; ``serve.port`` only for tests/dev."""
        return self._port if self._port else (443 if self.tls_mode == "provided" else 80)

    @property
    def redirect_port(self) -> int | None:
        """The 80 -> 443 redirect listener (tls.mode = provided only)."""
        return 80 if self.tls_mode == "provided" and self._port is None else None

    def public_url(self) -> str:
        scheme = "https" if self.tls_mode == "provided" else "http"
        default = 443 if self.tls_mode == "provided" else 80
        port = self.listen_port
        return f"{scheme}://{self.hostname}" + ("" if port == default else f":{port}")


@dataclasses.dataclass(frozen=True)
class Paths:
    state_dir: Path
    run_dir: Path
    assets_dir: Path
    creds_dir: Path | None

    @property
    def db(self) -> Path:
        return self.state_dir / "speedtest.db"

    @property
    def payload(self) -> Path:
        return self.state_dir / "payload.bin"

    @property
    def runtime_json(self) -> Path:
        return self.state_dir / "runtime.json"

    @property
    def status_file(self) -> Path:
        return self.run_dir / "status.json"


def load_speedtest_config(path: str | Path) -> SpeedtestConfig:
    doc = exp_config.load_config(path, SCHEMA_NAME)
    return SpeedtestConfig(doc)


def make_paths(state_dir: str | None = None, run_dir: str | None = None, assets_dir: str | None = None,
               creds_dir: str | None = None) -> Paths:
    cd = creds_dir or os.environ.get("CREDENTIALS_DIRECTORY")
    return Paths(Path(state_dir or os.environ.get("STATE_DIRECTORY") or DEFAULT_STATE_DIR),
                 Path(run_dir or os.environ.get("RUNTIME_DIRECTORY") or DEFAULT_RUN_DIR),
                 Path(assets_dir or DEFAULT_ASSETS_DIR), Path(cd) if cd else None)


class Credentials:
    """The box's credentials, read lazily so rotation (a new file) needs no code path of its own."""

    def __init__(self, cfg: SpeedtestConfig, creds_dir: Path | None) -> None:
        self.cfg = cfg
        self.dir = creds_dir

    def collector_token(self) -> str:
        return exp_creds.read_credential(CRED_COLLECTOR_TOKEN, self.dir).strip()

    def channel_token_sha256(self) -> str | None:
        """sha256 hex of the runner's ``expl_`` token, or None when the channel is not provisioned."""
        try:
            v = exp_creds.read_credential(CRED_CHANNEL_SHA, self.dir).strip().lower()
        except exp_creds.CredentialError:
            return None
        return v if _HEX64.match(v) else None

    def tls_files(self) -> tuple[Path, Path]:
        base = exp_creds.credentials_dir(self.dir)
        for name in (CRED_TLS_CRT, CRED_TLS_KEY):
            exp_creds.read_credential_bytes(name, self.dir)     # existence + hardening checks (value unused)
        return base / CRED_TLS_CRT, base / CRED_TLS_KEY
