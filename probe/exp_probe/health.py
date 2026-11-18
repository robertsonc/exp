"""`exp-probe health --json` (02-probe.md section 9, 01-contracts.md section 8.1): exp.health/1.

`health` runs beside the daemon, so it combines (a) ``/run/exp/probe/status.json`` written by the daemon
(measurement counters, shipper state, last result per line), (b) the spool file (read-only), (c) the
leases, and (d) live per-port counters read INSIDE each namespace (``ip -n exp-<port> -s -j link``), since
the agent cannot see them. It never prints secrets, answers well under 5 s (parallel, bounded
queries) and its JSON is capped at 64 KiB.

Status: ``fail`` (exit 1) when the config is invalid, the daemon is not running, a namespace or its
port is missing, a client port has no lease and no recent error explaining why, the spool is not
accepting writes, the shipper has an auth/TLS-pin problem, or it has not pushed for > 120 s with a
non-empty spool. ``degraded`` (exit 0, still healthy per section 9) when the collector is unreachable
or not configured and the spool is accepting, or a port explains its missing lease with a recent error.
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import time
from typing import Any

from exp_common.config import ConfigError
from exp_common.schema import iso_to_ms

from . import __version__, lease, spool
from .config import Paths, Port, ProbeConfig
from .netns import netns_names
from .selftel import STATUS_MAX_AGE_S, STATUS_SCHEMA

log = logging.getLogger(__name__)

PUSH_STALE_S = 120.0
EXPLAIN_WINDOW_S = 120.0
MAX_OUTPUT = 64 * 1024


def _read_status(paths: Paths) -> dict[str, Any] | None:
    try:
        with open(paths.status_file, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and doc.get("schema") == STATUS_SCHEMA else None


def read_counters(runner: Any, cfg: ProbeConfig, port: Port) -> dict[str, Any] | None:
    """Link state and counters of the port, read in its namespace (host mode: the host)."""
    argv = ["ip", "-s", "-j", "link", "show", "dev", port.iface]
    if cfg.mode == "netns":
        argv = ["ip", "-n", port.ns, "-s", "-j", "link", "show", "dev", port.iface]
    r = runner.run(argv, 2)
    if not r.ok:
        return None
    try:
        doc = json.loads(r.stdout)
        link = doc[0]
        st = link.get("stats64") or link.get("stats") or {}
        rx, tx = st.get("rx") or {}, st.get("tx") or {}
        flags = link.get("flags") or []
        return {"up": "LOWER_UP" in flags and link.get("operstate") not in ("DOWN", "LOWERLAYERDOWN"),
                "rx_bytes": int(rx.get("bytes", 0)), "rx_packets": int(rx.get("packets", 0)),
                "rx_errors": int(rx.get("errors", 0)), "rx_dropped": int(rx.get("dropped", 0)),
                "tx_bytes": int(tx.get("bytes", 0)), "tx_packets": int(tx.get("packets", 0)),
                "tx_errors": int(tx.get("errors", 0)), "tx_dropped": int(tx.get("dropped", 0))}
    except (ValueError, IndexError, KeyError, TypeError, AttributeError):
        return None


def _read_all_counters(runner: Any, cfg: ProbeConfig, budget_s: float = 3.0) -> list[dict[str, Any] | None]:
    """Counters of every port, read in parallel inside a total time budget (health must answer < 5 s);
    a port that does not answer in time reads as absent."""
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    futs = [pool.submit(read_counters, runner, cfg, p) for p in cfg.ports]
    concurrent.futures.wait(futs, timeout=budget_s)
    pool.shutdown(wait=False, cancel_futures=True)
    return [f.result() if f.done() and not f.cancelled() and f.exception() is None else None for f in futs]


def _rates(prev: dict[str, Any] | None, cur: dict[str, Any], now: float) -> dict[str, float | None]:
    keys = ("rx_pps", "tx_pps", "rx_bps", "tx_bps")
    if not prev or not isinstance(prev.get("ts"), (int, float)) or now - prev["ts"] < 1.0:
        return dict.fromkeys(keys)
    dt = now - prev["ts"]
    try:
        out: dict[str, float | None] = {}
        for k, (field_, mult) in {"rx_pps": ("rx_packets", 1), "tx_pps": ("tx_packets", 1),
                                  "rx_bps": ("rx_bytes", 8), "tx_bps": ("tx_bytes", 8)}.items():
            delta = cur[field_] - int(prev[field_])
            out[k] = None if delta < 0 else round(delta * mult / dt, 2)      # counter reset -> null
        return out
    except (KeyError, TypeError, ValueError):
        return dict.fromkeys(keys)


def collect(cfg: ProbeConfig | None, config_error: str | None, runner: Any, paths: Paths,
            now: float | None = None) -> dict[str, Any]:
    """Build the exp.health/1 document."""
    now = time.time() if now is None else now
    doc: dict[str, Any] = {"schema": "exp.health/1", "status": "ok", "detail": "", "version": __version__,
                           "uptime_s": 0, "metrics": {}, "facts": {}}
    if cfg is None:
        doc.update(status="fail", detail=f"config invalid: {config_error}"[:1000])
        return doc
    status = _read_status(paths)
    problems: list[str] = []      # -> fail
    notes: list[str] = []         # -> degraded
    daemon_up = bool(status) and now - float(status.get("ts", 0)) <= STATUS_MAX_AGE_S
    if not daemon_up:
        problems.append("exp-probe daemon is not running (no fresh status)" if status is None
                        else f"exp-probe daemon status is {now - float(status['ts']):.0f}s old")
    stats = (status or {}).get("stats", {})
    ship = (status or {}).get("shipper", {})
    prev_counters = (status or {}).get("counters", {})
    sp = spool.read_stat(paths.spool_db) or {"depth": 0, "bytes": 0, "oldest_ts": None, "dropped_total": 0}
    push_lag = 0.0
    if sp.get("oldest_ts"):
        try:
            push_lag = max(0.0, now - iso_to_ms(sp["oldest_ts"]) / 1000.0)
        except ValueError:
            push_lag = 0.0

    names = netns_names(runner) if cfg.mode == "netns" else set()
    counters = _read_all_counters(runner, cfg)
    ports_out: list[dict[str, Any]] = []
    for port, cur in zip(cfg.ports, counters, strict=True):
        ls = lease.read_lease(paths, port.id) if port.role == "client" and cfg.mode == "netns" else None
        leased = lease.has_lease(ls)
        pstat = (stats.get("ports") or {}).get(port.id, {})
        if cfg.mode == "netns" and port.ns not in names:
            problems.append(f"namespace {port.ns} is missing")
        elif cur is None:
            where = f" in {port.ns}" if cfg.mode == "netns" else ""
            problems.append(f"port {port.id} ({port.iface}) is not present{where}")
        if cfg.mode == "netns" and port.role == "client" and not leased:
            err_ts = pstat.get("last_error_ts")
            if err_ts and now - float(err_ts) <= EXPLAIN_WINDOW_S:
                notes.append(f"port {port.id} has no lease: {pstat.get('last_error') or 'see its error records'}")
            else:
                problems.append(f"port {port.id} has no lease and no recent error explains it")
        rates = _rates(prev_counters.get(port.id), cur, now) if cur else dict.fromkeys(
            ("rx_pps", "tx_pps", "rx_bps", "tx_bps"))
        ports_out.append({
            "id": port.id, "iface": port.iface, "role": port.role,
            "link": "up" if cur and cur["up"] else "down", "leased": leased,
            "ip": ls.get("ip") if leased and ls else None,
            "gateway": (ls.get("router") or [None])[0] if leased and ls else None,
            **rates,
            "rx_errors": cur["rx_errors"] if cur else 0, "tx_errors": cur["tx_errors"] if cur else 0,
            "rx_drops": cur["rx_dropped"] if cur else 0, "tx_drops": cur["tx_dropped"] if cur else 0,
            "last": dict(pstat.get("last") or {})})

    # shipping
    state = ship.get("state", "")
    last_ok = ship.get("last_ok")
    werr = int(((status or {}).get("spool") or {}).get("write_errors", 0) or 0)
    if werr:
        notes.append(f"spool had {werr} write errors since start")
    if state == "auth_failed":
        problems.append(f"auth_failed: {ship.get('detail') or 'collector refused the ingest token'}")
    elif state == "tls_pin_mismatch":
        problems.append(f"tls_pin_mismatch: {ship.get('detail') or 'collector certificate does not match the pin'}")
    elif state == "no_collector":
        notes.append("no collector configured; measuring and spooling")
    elif state in ("unreachable", "error", "throttled"):
        notes.append("collector unreachable; spooling" if state != "throttled" else "collector is throttling; spooling")
    if daemon_up and state in ("ok", "idle", "") and sp["depth"] > 0 and push_lag > PUSH_STALE_S and (
            last_ok is None or now - float(last_ok) > PUSH_STALE_S):
        problems.append(f"shipper has not pushed for {push_lag:.0f}s")

    reachable = ship.get("collector_reachable")
    status_word = "fail" if problems else ("degraded" if notes else "ok")
    detail = "; ".join(problems + notes)
    started = (status or {}).get("started")
    doc.update(status=status_word, detail=detail[:1000],
               uptime_s=round(max(0.0, now - float(started)), 1)
               if isinstance(started, (int, float)) and daemon_up else 0)
    doc["metrics"] = {
        "measurements_per_min": stats.get("measurements_per_min", 0),
        "by_test_per_min": stats.get("by_test_per_min", {}),
        "fail_per_min": stats.get("fail_per_min", 0), "error_per_min": stats.get("error_per_min", 0),
        "spool_depth": sp["depth"], "spool_bytes": sp["bytes"], "push_lag_s": round(push_lag, 1),
        "clock_offset_ms": stats.get("clock_offset_ms"),
        "skipped_per_hour": stats.get("skipped_per_hour", 0),
        "dropped_total": sp.get("dropped_total", 0),
        "ports": ports_out}
    doc["facts"] = {"collector_reachable": bool(reachable) if reachable is not None else False,
                    "mode": cfg.mode,
                    "shipper_state": state or "unknown", "tls_pin_mismatch": state == "tls_pin_mismatch",
                    "auth_failed": state == "auth_failed"}
    if cfg.collector:  # health.schema.json: collector_url is an https URL; with no collector the key is absent, never null
        doc["facts"]["collector_url"] = cfg.collector.url
    return doc


def counters_snapshot(runner: Any, cfg: ProbeConfig, now: float) -> dict[str, Any]:
    """Per-port counter samples (with timestamp) the daemon stores in status.json for rate deltas."""
    out: dict[str, Any] = {}
    for port in cfg.ports:
        cur = read_counters(runner, cfg, port)
        if cur:
            out[port.id] = {**cur, "ts": now}
    return out


def render(doc: dict[str, Any]) -> str:
    text = json.dumps(doc, separators=(",", ":"), sort_keys=True)
    if len(text.encode()) > MAX_OUTPUT:      # never exceed 64 KiB: drop the bulky parts
        doc = {**doc, "metrics": {k: v for k, v in doc["metrics"].items() if k != "ports"}}
        text = json.dumps(doc, separators=(",", ":"), sort_keys=True)
    return text


def exit_code(doc: dict[str, Any]) -> int:
    return 0 if doc.get("status") in ("ok", "degraded") else 1


def load_for_health(config_path: str) -> tuple[ProbeConfig | None, str | None]:
    from .config import load_probe_config
    try:
        return load_probe_config(config_path), None
    except (ConfigError, OSError) as exc:
        return None, str(exc).replace("\n", " ")[:900]
