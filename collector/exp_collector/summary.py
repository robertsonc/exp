"""Details tables of the pulse board (01-contracts.md section 5 ``GET summary``).

ported from reference/exm/lib/exm/report.py:summarize / dashboard_summary / servers_seen: per client DHCP
and DNS timings, per resolver latency pooled across clients, per app Apdex, per server port who is
testing it. Differences: EXM's "client" is a port of the probe here, EXM's multi-test records are one
exp.measurement/1 record per test per port, and the numbers are computed on the collector from SQLite
(the window is ``minutes`` <= 1440) instead of on the probe.

Everything read from a record is untrusted: values are type-checked, strings are clipped and stripped of
control characters, and every table is bounded.
"""
from __future__ import annotations

import json
import math
import statistics
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from .store import Store

MAX_MINUTES = 1440
MAX_RECORDS_PER_TEST = 150_000
MAX_ROWS = 500
SUMMARY_TESTS = ("dhcp", "dhcp_hb", "dns", "dns_hb", "app", "throughput", "target_access", "wifi_hb")
GOOD = ("ok", "degraded")        # a lease / answer that came back slow still counts as served


def iso_ms(ms: int | float) -> str:
    import datetime
    return (datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def pct(values: Iterable[float | None], p: float) -> float | None:
    """Percentile by linear interpolation; None for no data (ported from exm events.pct)."""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    if len(vals) == 1:
        return round(vals[0], 2)
    k = (len(vals) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return round(vals[lo] + (vals[hi] - vals[lo]) * (k - lo), 2)


def median(values: Iterable[float | None]) -> float | None:
    vals = [v for v in values if v is not None]
    return round(statistics.median(vals), 2) if vals else None


def _txt(v: Any, n: int = 128) -> str:
    if not isinstance(v, str):
        return ""
    return "".join(ch for ch in v if ch >= " " and ch != "\x7f")[:n]


def _num(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    return float(v)


class Rec:
    __slots__ = ("ts", "test", "outcome", "port", "labels", "metrics", "detail", "dur")

    def __init__(self, ts: int, d: dict[str, Any]) -> None:
        self.ts = ts
        self.test = _txt(d.get("test"), 64)
        self.outcome = _txt(d.get("outcome"), 16)
        self.labels: dict[str, Any] = d.get("labels") if isinstance(d.get("labels"), dict) else {}
        self.metrics: dict[str, Any] = d.get("metrics") if isinstance(d.get("metrics"), dict) else {}
        self.detail: dict[str, Any] = d.get("detail") if isinstance(d.get("detail"), dict) else {}
        self.port = _txt(self.labels.get("port"), 64)
        self.dur = _num(d.get("duration_ms"))

    def label(self, k: str) -> str:
        return _txt(self.labels.get(k), 128)

    def m(self, k: str) -> float | None:
        return _num(self.metrics.get(k))


def load(store: Store, probe: str, from_ms: int, to_ms: int) -> dict[str, list[Rec]]:
    out: dict[str, list[Rec]] = {}
    for test in SUMMARY_TESTS:
        recs: list[Rec] = []
        after: tuple[int, str] | None = None
        while len(recs) < MAX_RECORDS_PER_TEST:
            rows = store.read_records(probe, from_ms, to_ms, test=test, limit=5000, after=after)
            for ts, _rid, body in rows:
                try:
                    d = json.loads(body)
                except ValueError:
                    continue
                if isinstance(d, dict):
                    recs.append(Rec(ts, d))
            if len(rows) < 5000:
                break
            after = (rows[-1][0], rows[-1][1])
        out[test] = recs
    return out


def _ok_pct(recs: list[Rec]) -> float | None:
    real = [r for r in recs if r.outcome != "error"]       # `error`: the probe could not run it, not a verdict
    return round(100.0 * sum(1 for r in real if r.outcome in GOOD) / len(real), 1) if real else None


def _apdex(recs: list[Rec]) -> float | None:
    vals = []
    for r in recs:
        if r.outcome == "error":
            continue
        a = r.m("apdex")
        if a is None:
            a = 1.0 if r.outcome == "ok" else 0.5 if r.outcome == "degraded" else 0.0
        vals.append(min(1.0, max(0.0, a)))
    return round(sum(vals) / len(vals), 2) if vals else None


def build(store: Store, probe: str, minutes: int, now_ms: int) -> dict[str, list[dict[str, Any]]]:
    """The six tables for `probe` over the last `minutes` minutes."""
    minutes = max(1, min(int(minutes), MAX_MINUTES))
    recs = load(store, probe, now_ms - minutes * 60_000, now_ms)
    return {
        "clients": _clients(recs),
        "dhcp": _dhcp(recs),
        "dns": _dns(recs),
        "apps": _apps(recs),
        "throughput": _throughput(recs),
        "servers": _servers(recs),
    }


def _by_port(recs: Iterable[Rec]) -> dict[str, list[Rec]]:
    d: dict[str, list[Rec]] = defaultdict(list)
    for r in recs:
        if r.port:
            d[r.port].append(r)
    return d


def _clients(recs: dict[str, list[Rec]]) -> list[dict[str, Any]]:
    """One row per port acting as a client: DHCP, DNS and app health."""
    dhcp = _by_port(recs["dhcp"] + recs["dhcp_hb"])
    dns = _by_port(recs["dns"] + recs["dns_hb"])
    apps = _by_port(recs["app"])
    wifi = _by_port(recs["wifi_hb"])
    ports = sorted(set(dhcp) | set(dns) | set(apps) | set(wifi))[:MAX_ROWS]
    rows = []
    for p in ports:
        full = [r for r in dhcp.get(p, []) if r.test == "dhcp"]
        rtts = [r.m("rtt_ms") for r in dns.get(p, [])]
        by_app = _by_port_app(apps.get(p, []))
        worst = min(((a, _apdex(rs)) for a, rs in by_app.items()), key=lambda x: (x[1] if x[1] is not None else 2.0),
                    default=None)
        last_wifi = max(wifi.get(p, []), key=lambda r: r.ts, default=None)
        flags = sorted({_txt(f, 32) for r in full for f in _flags(r)})[:8]
        no_link = sum(1 for r in dns.get(p, []) + apps.get(p, []) if r.outcome == "fail" and "carrier" in
                      _txt(r.detail.get("error"), 64).lower())
        rows.append({
            "port": p,
            "dhcp_runs": len(full) or len(dhcp.get(p, [])),
            "dhcp_ok_pct": _ok_pct(full or dhcp.get(p, [])),
            "dhcp_total_p50_ms": pct((r.m("total_ms") for r in full), 50),
            "dhcp_total_p95_ms": pct((r.m("total_ms") for r in full), 95),
            "dns_runs": len(dns.get(p, [])),
            "dns_ok_pct": _ok_pct(dns.get(p, [])),
            "dns_p50_ms": pct(rtts, 50),
            "dns_p95_ms": pct(rtts, 95),
            "apps_runs": len(apps.get(p, [])),
            "apdex": _apdex(apps.get(p, [])),
            "worst_app": worst[0] if worst else None,
            "worst_apdex": worst[1] if worst else None,
            "wifi_ssid": last_wifi.label("ssid") or None if last_wifi else None,
            "wifi_rssi_dbm": last_wifi.m("rssi_dbm") if last_wifi else None,
            "flags": flags,
            "no_link_runs": no_link,
        })
    return rows


def _flags(r: Rec) -> list[Any]:
    f = r.detail.get("flags")
    return f[:16] if isinstance(f, list) else []


def _by_port_app(recs: Iterable[Rec]) -> dict[str, list[Rec]]:
    d: dict[str, list[Rec]] = defaultdict(list)
    for r in recs:
        d[r.label("app") or "unknown"].append(r)
    return d


def _dhcp(recs: dict[str, list[Rec]]) -> list[dict[str, Any]]:
    """DHCP servers seen (who answered a DISCOVER), with the ports they served and their timings."""
    by: dict[str, list[Rec]] = defaultdict(list)
    for r in recs["dhcp"] + recs["dhcp_hb"]:
        s = r.label("server")
        if s:
            by[s].append(r)
    rows = []
    for server, rs in sorted(by.items())[:MAX_ROWS]:
        full = [r for r in rs if r.test == "dhcp"]
        rows.append({"server": server, "ports": sorted({r.port for r in rs if r.port})[:32], "runs": len(rs),
                     "ok_pct": _ok_pct(rs),
                     "offer_p50_ms": pct((r.m("offer_ms") if r.test == "dhcp_hb" else r.m("discover_offer_ms")
                                          for r in rs), 50),
                     "total_p50_ms": pct((r.m("total_ms") for r in full), 50),
                     "total_p95_ms": pct((r.m("total_ms") for r in full), 95),
                     "last_seen": iso_ms(max(r.ts for r in rs))})
    return rows


def _dns(recs: dict[str, list[Rec]]) -> list[dict[str, Any]]:
    """Per resolver, pooled over ports: latency and failure share."""
    by: dict[str, list[Rec]] = defaultdict(list)
    for r in recs["dns"] + recs["dns_hb"]:
        res = r.label("resolver")
        if res:
            by[res].append(r)
    rows = []
    for res, rs in sorted(by.items())[:MAX_ROWS]:
        real = [r for r in rs if r.outcome != "error"]
        kinds = sorted({r.label("resolver_kind") for r in rs if r.label("resolver_kind")})
        rows.append({"resolver": res, "kind": kinds[0] if len(kinds) == 1 else (None if not kinds else "mixed"),
                     "runs": len(rs), "ports": sorted({r.port for r in rs if r.port})[:32],
                     "p50_ms": pct((r.m("rtt_ms") for r in rs), 50), "p95_ms": pct((r.m("rtt_ms") for r in rs), 95),
                     "fail_pct": round(100.0 * sum(1 for r in real if r.outcome == "fail") / len(real), 1)
                     if real else None})
    return rows


def _apps(recs: dict[str, list[Rec]]) -> list[dict[str, Any]]:
    by: dict[str, list[Rec]] = defaultdict(list)
    for r in recs["app"]:
        by[r.label("app") or "unknown"].append(r)
    rows = []
    for app, rs in sorted(by.items())[:MAX_ROWS]:
        rows.append({"app": app, "apdex": _apdex(rs), "runs": len(rs),
                     "clients": len({r.port for r in rs if r.port}),
                     "p50_total_ms": pct((r.m("total_ms") for r in rs), 50),
                     "p95_total_ms": pct((r.m("total_ms") for r in rs), 95),
                     "ok_pct": _ok_pct(rs)})
    return rows


def _throughput(recs: dict[str, list[Rec]]) -> list[dict[str, Any]]:
    """The latest speed test per (port, provider)."""
    latest: dict[tuple[str, str], Rec] = {}
    for r in recs["throughput"]:
        if r.outcome == "error":
            continue
        k = (r.port, r.label("provider"))
        if k not in latest or r.ts >= latest[k].ts:
            latest[k] = r
    rows = []
    for (port, provider), r in sorted(latest.items())[:MAX_ROWS]:
        idle, loaded = r.m("latency_idle_ms"), r.m("latency_loaded_ms")
        rows.append({"port": port, "provider": provider or None, "down_mbps": r.m("down_mbps"),
                     "up_mbps": r.m("up_mbps"), "latency_idle_ms": idle, "latency_loaded_ms": loaded,
                     "bufferbloat_ms": round(loaded - idle, 2) if idle is not None and loaded is not None else None,
                     "outcome": r.outcome, "ts": iso_ms(r.ts)})
    return rows


def _servers(recs: dict[str, list[Rec]]) -> list[dict[str, Any]]:
    """Target-server ports: who is testing them (``target_access`` every 60 s)."""
    by: dict[tuple[str, str], list[Rec]] = defaultdict(list)
    for r in recs["target_access"]:
        by[(r.port, r.label("proto"))].append(r)
    rows = []
    for (port, proto), rs in sorted(by.items())[:MAX_ROWS]:
        sources: dict[str, int] = defaultdict(int)
        for r in rs:
            tc = r.detail.get("top_clients")
            for item in (tc[:32] if isinstance(tc, list) else []):
                if isinstance(item, str):
                    sources[_txt(item, 64)] += 1
                elif isinstance(item, dict):
                    name = _txt(item.get("ip") or item.get("client") or item.get("src"), 64)
                    n = _num(item.get("requests") or item.get("count")) or 1
                    if name:
                        sources[name] += int(n)
        top = sorted(sources.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        rows.append({"port": port, "proto": proto or None,
                     "requests": int(sum(r.m("requests") or 0 for r in rs)),
                     "errors": int(sum(r.m("errors") or 0 for r in rs)),
                     "p50_ms": median(r.m("p50_ms") for r in rs),
                     "sources": [{"client": k, "count": v} for k, v in top],
                     "last_seen": iso_ms(max(r.ts for r in rs))})
    return rows
