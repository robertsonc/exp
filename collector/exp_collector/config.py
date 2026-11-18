"""Collector configuration: `exp.collector.config/1`, filesystem layout, and credentials.

* ``load_config`` validates with exp_common.config (JSON Schema) and refuses to start on anything
  invalid, naming every problem.
* ``Paths`` resolves the state / run / creds directories (systemd sets STATE_DIRECTORY,
  RUNTIME_DIRECTORY and CREDENTIALS_DIRECTORY; the CLI can override them for dev and tests).
* ``CredStore`` reads ``ingest_tokens.json``, ``dashboard_tokens.json`` and ``webhooks.json`` with
  exp_common.creds and re-reads them when they change (mtime poll, <= 10 s) so rotation needs no
  restart. A bad file on reload keeps the previous good set; values are never logged.
"""
from __future__ import annotations

import dataclasses
import hmac
import json
import logging
import os
import re
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from exp_common import config as exp_config
from exp_common import creds as exp_creds
from exp_common import ids as exp_ids

log = logging.getLogger(__name__)

SCHEMA_NAME = "exp.collector.config/1"
DEFAULT_CONFIG_PATH = "/etc/exp/collector/config.json"
DEFAULT_STATE_DIR = "/var/lib/exp/collector"
DEFAULT_RUN_DIR = "/run/exp/collector"

CRED_INGEST = "ingest_tokens.json"
CRED_DASHBOARD = "dashboard_tokens.json"
CRED_WEBHOOKS = "webhooks.json"
CRED_FILES = (CRED_INGEST, CRED_DASHBOARD, CRED_WEBHOOKS)

MIB = 1024 * 1024
WILDCARD_HOSTS = frozenset({"", "0.0.0.0", "::", "[::]", "*"})  # noqa: S104 - these are REFUSED, not bound
_HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")


class CollectorConfigError(ValueError):
    """Semantically invalid configuration (beyond what the JSON Schema checks)."""


@dataclasses.dataclass(frozen=True)
class ProbeEntry:
    probe_id: str
    site: str
    label: str = ""


@dataclasses.dataclass(frozen=True)
class CollectorConfig:
    collector_id: str
    site: str
    listen_host: str
    listen_port: int
    probes: Mapping[str, ProbeEntry]
    dashboards: tuple[str, ...]
    metrics_days: int = 30
    records_days: int = 7
    vm_host: str = "127.0.0.1"
    vm_port: int = 8428
    vm_memory_allowed_pct: int = 40
    edge_label: str = "EC"
    lines: tuple[str, ...] = ("network", "dhcp", "dns", "internet", "apps", "wifi", "path")
    alerts: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    reflector_enabled: bool = True
    reflector_port: int = 8862
    iperf3_enabled: bool = True
    iperf3_port: int = 5201
    max_body_bytes: int = 4 * MIB
    max_records: int = 1000
    raw: Mapping[str, Any] = dataclasses.field(default_factory=dict, compare=False, repr=False)

    @property
    def listen(self) -> str:
        return f"{self.listen_host}:{self.listen_port}"

    @property
    def vm_url(self) -> str:
        return f"http://{self.vm_host}:{self.vm_port}"

    def site_of(self, probe: str) -> str | None:
        """The site a probe is configured for; None if the probe is not configured."""
        entry = self.probes.get(probe)
        return entry.site if entry else None

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> CollectorConfig:
        """Build from an already schema-validated document."""
        host, _, port_s = str(d["listen"]).rpartition(":")
        probes: dict[str, ProbeEntry] = {}
        for p in d.get("probes", []):
            pid = p["probe_id"]
            if pid in probes:
                raise CollectorConfigError(f"probe {pid!r} is listed twice")
            probes[pid] = ProbeEntry(pid, p["site"], p.get("label", ""))
        retention = d.get("retention") or {}
        vm = d.get("vm") or {}
        vm_host, _, vm_port = str(vm.get("listen", "127.0.0.1:8428")).rpartition(":")
        rules = d.get("rules") or {}
        reflector = d.get("reflector") or {}
        iperf3 = d.get("iperf3") or {}
        ing = d.get("ingest") or {}
        return cls(
            collector_id=d["collector_id"], site=d["site"], listen_host=host, listen_port=int(port_s),
            probes=probes, dashboards=tuple(d.get("dashboards", [])),
            metrics_days=int(retention.get("metrics_days", 30)),
            records_days=int(retention.get("records_days", 7)),
            vm_host=vm_host, vm_port=int(vm_port),
            vm_memory_allowed_pct=int(vm.get("memory_allowed_pct", 40)),
            edge_label=str(rules.get("edge_label", "EC")),
            lines=tuple(rules.get("lines", ("network", "dhcp", "dns", "internet", "apps", "wifi", "path"))),
            alerts=dict(d.get("alerts") or {}),
            reflector_enabled=bool(reflector.get("enabled", True)),
            reflector_port=int(reflector.get("port", 8862)),
            iperf3_enabled=bool(iperf3.get("enabled", True)),
            iperf3_port=int(iperf3.get("port", 5201)),
            max_body_bytes=int(ing.get("max_body_mb", 4)) * MIB,
            max_records=int(ing.get("max_records", 1000)),
            raw=dict(d),
        )


def load_config(path: str | os.PathLike[str]) -> CollectorConfig:
    """Load and validate; raises exp_common.config.ConfigError / CollectorConfigError (callers
    must refuse to start)."""
    doc = exp_config.load_config(path, SCHEMA_NAME)
    return CollectorConfig.from_dict(doc)


def check_listen_address(host: str) -> None:
    """SR-5: the collector binds a management address only, never a wildcard."""
    if host.strip().lower() in WILDCARD_HOSTS:
        raise CollectorConfigError(
            f"listen address {host!r} is a wildcard: the collector must bind a management IP (SR-5)")


# ------------------------------------------------------------------------------------------- paths

@dataclasses.dataclass(frozen=True)
class Paths:
    state_dir: Path
    run_dir: Path
    creds_dir: Path | None
    tls_key: Path
    tls_cert: Path

    @property
    def db_path(self) -> Path:
        return self.state_dir / "records.db"

    @property
    def health_snapshot(self) -> Path:
        return self.run_dir / "health.json"

    @property
    def vm_data_dir(self) -> Path:
        return self.state_dir / "vm"

    @classmethod
    def resolve(cls, state_dir: str | os.PathLike[str] | None = None,
                run_dir: str | os.PathLike[str] | None = None,
                creds_dir: str | os.PathLike[str] | None = None,
                tls_key: str | os.PathLike[str] | None = None,
                tls_cert: str | os.PathLike[str] | None = None) -> Paths:
        def first(env: str) -> str | None:
            v = os.environ.get(env)
            return v.split(":")[0] if v else None

        state = Path(state_dir or first("STATE_DIRECTORY") or DEFAULT_STATE_DIR)
        run = Path(run_dir or first("RUNTIME_DIRECTORY") or DEFAULT_RUN_DIR)
        cdir = creds_dir or os.environ.get("CREDENTIALS_DIRECTORY")
        return cls(state_dir=state, run_dir=run, creds_dir=Path(cdir) if cdir else None,
                   tls_key=Path(tls_key) if tls_key else state / "tls" / "key.pem",
                   tls_cert=Path(tls_cert) if tls_cert else state / "tls" / "cert.pem")


# ---------------------------------------------------------------------------------------- creds

def _parse_json_text(text: str, name: str) -> Any:
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise exp_creds.CredentialError(
            f"credential {name!r} is not valid JSON (line {exc.lineno}, column {exc.colno})") from None
    except RecursionError:
        raise exp_creds.CredentialError(f"credential {name!r} is nested too deeply") from None


def parse_token_hashes(obj: Any, name: str) -> dict[str, str]:
    """`{id: sha256hex}` -> normalised lower-case map. Errors name the file and the id, never a hash."""
    if obj is None:
        return {}
    if not isinstance(obj, dict):
        raise exp_creds.CredentialError(f"credential {name!r} must be a JSON object {{id: sha256}}")
    out: dict[str, str] = {}
    for ident, digest in obj.items():
        if not exp_ids.is_slug(ident):
            raise exp_creds.CredentialError(f"credential {name!r}: identity {str(ident)[:40]!r} is not a slug")
        if not isinstance(digest, str) or not _HEX64.match(digest):
            raise exp_creds.CredentialError(f"credential {name!r}: entry for {ident!r} is not a sha256 hex digest")
        out[ident] = digest.lower()
    return out


def parse_webhooks(obj: Any, name: str = CRED_WEBHOOKS) -> list[dict[str, str]]:
    if obj is None:
        return []
    if not isinstance(obj, list):
        raise exp_creds.CredentialError(f"credential {name!r} must be a JSON array")
    out: list[dict[str, str]] = []
    for i, item in enumerate(obj):
        if (not isinstance(item, dict) or item.get("format") not in ("slack", "teams", "json")
                or not isinstance(item.get("url"), str) or not isinstance(item.get("id", ""), str)):
            raise exp_creds.CredentialError(f"credential {name!r}: entry {i} is not {{id, format, url}}")
        out.append({"id": str(item.get("id", f"wh_{i}")), "format": item["format"], "url": item["url"]})
    return out


class TokenTable:
    """Immutable id -> sha256 table with constant-time lookup."""

    __slots__ = ("_entries",)

    def __init__(self, hashes: Mapping[str, str]) -> None:
        self._entries = tuple(hashes.items())

    def __len__(self) -> int:
        return len(self._entries)

    def identities(self) -> tuple[str, ...]:
        return tuple(i for i, _ in self._entries)

    def lookup(self, token: str) -> str | None:
        """Identity whose stored digest matches sha256(token). Every entry is compared, in constant
        time, so timing reveals neither which entry matched nor how many exist."""
        digest = exp_ids.token_hash(token).encode("ascii")
        found: str | None = None
        for ident, stored in self._entries:
            if hmac.compare_digest(digest, stored.encode("ascii")) and found is None:
                found = ident
        return found


_EMPTY = TokenTable({})


class CredStore:
    """The three credential files with change detection. Thread-safe; readers get immutable snapshots."""

    def __init__(self, directory: str | os.PathLike[str] | None, poll_s: float = 5.0) -> None:
        if directory is None:
            raise exp_creds.CredentialError(
                "no credentials directory: CREDENTIALS_DIRECTORY is not set (is the unit missing LoadCredential=?)")
        if not 0 < poll_s <= 10:
            raise ValueError("poll_s must be in (0, 10]: rotation must be picked up within 10 s")
        self.directory = Path(directory)
        self.poll_s = poll_s
        self._lock = threading.Lock()
        self._sig: dict[str, tuple[int, int, int] | None] = {}
        self._ingest = _EMPTY
        self._dashboard = _EMPTY
        self._webhooks: tuple[dict[str, str], ...] = ()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.reload_errors = 0
        self.last_error = ""
        self.generation = 0

    # --- access -------------------------------------------------------------------------------
    @property
    def ingest(self) -> TokenTable:
        return self._ingest

    @property
    def dashboard(self) -> TokenTable:
        return self._dashboard

    def webhooks(self) -> list[dict[str, str]]:
        return [dict(w) for w in self._webhooks]

    # --- loading ------------------------------------------------------------------------------
    def _signature(self, name: str) -> tuple[int, int, int] | None:
        try:
            st = os.lstat(self.directory / name)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def _read_all(self) -> tuple[TokenTable, TokenTable, tuple[dict[str, str], ...]]:
        texts = {n: exp_creds.read_credential(n, self.directory) for n in CRED_FILES}
        ingest = parse_token_hashes(_parse_json_text(texts[CRED_INGEST], CRED_INGEST), CRED_INGEST)
        dash = parse_token_hashes(_parse_json_text(texts[CRED_DASHBOARD], CRED_DASHBOARD), CRED_DASHBOARD)
        hooks = parse_webhooks(_parse_json_text(texts[CRED_WEBHOOKS], CRED_WEBHOOKS))
        return TokenTable(ingest), TokenTable(dash), tuple(hooks)

    def load(self) -> None:
        """Initial load: raises CredentialError so the caller refuses to start."""
        sigs = {n: self._signature(n) for n in CRED_FILES}
        tables = self._read_all()
        with self._lock:
            self._sig = sigs
            self._ingest, self._dashboard, self._webhooks = tables
            self.generation += 1
        log.info("credentials loaded: %d ingest identities, %d dashboard identities, %d webhooks",
                 len(self._ingest), len(self._dashboard), len(self._webhooks))

    def reload_if_changed(self, force: bool = False) -> bool:
        """Re-read the files when any changed (or always with `force`, e.g. on SIGHUP). On error the previous
        good set stays active."""
        sigs = {n: self._signature(n) for n in CRED_FILES}
        if sigs == self._sig and not force:
            return False
        try:
            tables = self._read_all()
        except exp_creds.CredentialError as exc:
            self.reload_errors += 1
            self.last_error = str(exc)
            log.error("credential reload failed, keeping previous credentials: %s", exc)
            with self._lock:
                self._sig = sigs  # do not retry (and re-log) until the files change again
            return False
        with self._lock:
            self._sig = sigs
            self._ingest, self._dashboard, self._webhooks = tables
            self.generation += 1
            self.last_error = ""
        log.info("credentials reloaded: %d ingest identities, %d dashboard identities, %d webhooks",
                 len(self._ingest), len(self._dashboard), len(self._webhooks))
        return True

    # --- poller -------------------------------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll, name="cred-poll", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout=2)
            self._thread = None

    def _poll(self) -> None:
        while not self._stop.wait(self.poll_s):
            try:
                self.reload_if_changed()
            except Exception:  # noqa: BLE001 - the poller must never die
                log.exception("credential poller error")
