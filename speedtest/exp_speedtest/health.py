"""``exp-speedtest health [--json]`` (01-contracts.md section 8.1): ``exp.health/1``.

Combines the daemon's status file (``/run/exp/speedtest/status.json``: counters, listener state, collector link) with the
config. ``fail`` (exit 1): invalid config, the daemon is not running (no fresh status), the HTTP listener is not up, the
collector refuses the token or the pin does not match (results cannot be delivered). ``degraded`` (exit 0): the collector
is unreachable and results are spooling, the DNS-leg server or the runner channel did not bind, no ICMP mechanism for the
path timer, the spool is more than half full. Output is capped at 64 KiB and never contains a secret.
"""
from __future__ import annotations

import json
import time
from typing import Any

from exp_common.config import ConfigError

from . import __version__
from .config import Paths, SpeedtestConfig, load_speedtest_config
from .store import SPOOL_MAX_ROWS

STATUS_MAX_AGE_S = 15.0
MAX_OUTPUT = 64 * 1024


def read_status(paths: Paths) -> dict[str, Any] | None:
    try:
        with open(paths.status_file, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and doc.get("schema") == "exp.speedtest.status/1" else None


def load_for_health(path: str) -> tuple[SpeedtestConfig | None, str | None]:
    try:
        return load_speedtest_config(path), None
    except (ConfigError, OSError, ValueError) as exc:
        return None, str(exc).replace("\n", " ")[:900]


def collect(cfg: SpeedtestConfig | None, config_error: str | None, paths: Paths, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    doc: dict[str, Any] = {"schema": "exp.health/1", "status": "ok", "detail": "", "version": __version__,
                           "uptime_s": 0, "metrics": {}, "facts": {}}
    if cfg is None:
        doc.update(status="fail", detail=f"config invalid: {config_error}"[:1000])
        return doc
    status = read_status(paths)
    problems: list[str] = []
    notes: list[str] = []
    up = status is not None and now - float(status.get("ts", 0)) <= STATUS_MAX_AGE_S
    if not up:
        problems.append("exp-speedtest daemon is not running (no fresh status)" if status is None
                        else f"exp-speedtest daemon status is {now - float(status['ts']):.0f}s old")
    st = status or {}
    listening = st.get("listening") or {}
    if up and not listening.get("http"):
        problems.append("the HTTP listener is not up")
    if up and cfg.dns_enabled and not listening.get("dns"):
        notes.append("the DNS-leg server is not running: the page falls back to the probe's DNS figure")
    if up and not listening.get("channel"):
        notes.append("the runner channel is not listening: no correlation 'where' cache, no WAN auto-pause")
    fw = st.get("forwarder") or {}
    state = fw.get("state", "")
    if state == "auth_failed":
        problems.append(f"auth_failed: {fw.get('detail') or 'the collector refused the speedtest token'}")
    elif state == "tls_pin_mismatch":
        problems.append(f"tls_pin_mismatch: {fw.get('detail') or 'the collector certificate does not match the pin'}")
    elif state == "unreachable":
        notes.append("collector unreachable; results are spooling")
    depth = int(fw.get("depth") or 0)
    if depth > SPOOL_MAX_ROWS // 2:
        notes.append(f"delivery spool is {depth} rows")
    if (st.get("path") or {}).get("backend") == "none":
        notes.append("no ICMP mechanism for the path timer (set net.ipv4.ping_group_range or install iputils-ping)")
    for n in st.get("notes") or []:
        notes.append(str(n)[:200])
    word = "fail" if problems else ("degraded" if notes else "ok")
    started = st.get("started")
    doc.update(status=word, detail="; ".join(problems + notes)[:1000],
               uptime_s=round(max(0.0, now - float(started)), 1) if isinstance(started, (int, float)) and up else 0)
    m = st.get("metrics") or {}
    doc["metrics"] = {k: m.get(k, 0) for k in ("tests_per_hour", "active_tests", "queue_depth", "internet_leg_paused",
                                                "local_leg_gbps_p95", "rejected_per_hour")}
    doc["metrics"]["spool_depth"] = depth
    doc["facts"] = {"url": cfg.public_url(), "tls_mode": cfg.tls_mode,
                    "collector_reachable": bool(fw.get("collector_reachable")),
                    "collector_url": cfg.collector.url}
    if cfg.tls_mode == "provided" and st.get("tls_fingerprint_sha256"):
        doc["facts"]["tls_fingerprint_sha256"] = st["tls_fingerprint_sha256"]
    return doc


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, separators=(",", ":"), sort_keys=True)[:MAX_OUTPUT]


def exit_code(doc: dict[str, Any]) -> int:
    return 0 if doc.get("status") in ("ok", "degraded") else 1
