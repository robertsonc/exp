"""Synthetic measurement records for the rules/incident tests: small hand-made sequences shaped like
test/fixtures/measurements/*.json (one record per port for gateway / dns_hb / trace ...)."""
from __future__ import annotations

import itertools
from typing import Any

from exp_common import ids

PROBE, SITE = "probe-a1", "hall-b"
_seq = itertools.count()


def _id(ts_ms: int) -> str:
    return ids.new_ulid(ts_ms)


def mk(test: str, ts_ms: int, outcome: str = "ok", *, port: str = "c01", labels: dict[str, str] | None = None,
       metrics: dict[str, float] | None = None, detail: dict[str, Any] | None = None, error: str | None = None,
       target: str | None = None, probe: str = PROBE, site: str = SITE) -> dict[str, Any]:
    """A measurement dict (what the store keeps as `body`). Timestamps are epoch ms."""
    import datetime
    ts = datetime.datetime.fromtimestamp(ts_ms / 1000, datetime.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")
    d: dict[str, Any] = {"schema": "exp.measurement/1", "id": _id(ts_ms), "ts": ts, "probe": probe, "site": site,
                         "test": test, "outcome": outcome, "labels": {"port": port, **(labels or {})}}
    if metrics:
        d["metrics"] = metrics
    if detail:
        d["detail"] = detail
    if error:
        d["error"] = error
    if target:
        d["target"] = target
    return d


def gateway(t: int, *, ports: int = 4, bad: int = 0, ip: str = "10.1.0.1", nolink: int = 0,
            degraded: int = 0) -> list[dict[str, Any]]:
    """One gateway beat: `ports` records; the first `nolink` have no carrier, the next `bad` get no reply."""
    out = []
    for i in range(ports):
        port = f"c{i + 1:02d}"
        if i < nolink:
            out.append(mk("gateway", t, "fail", port=port, metrics={"link_up": 0, "loss_pct": 100},
                          detail={"gateway_ip": ip}, error="no link"))
        elif i < nolink + bad:
            out.append(mk("gateway", t, "fail", port=port, metrics={"link_up": 1, "loss_pct": 100},
                          detail={"gateway_ip": ip}, error=f"no reply from {ip}"))
        elif i < nolink + bad + degraded:
            out.append(mk("gateway", t, "degraded", port=port, metrics={"link_up": 1, "loss_pct": 20, "rtt_ms": 3},
                          detail={"gateway_ip": ip}))
        else:
            out.append(mk("gateway", t, "ok", port=port, metrics={"link_up": 1, "loss_pct": 0, "rtt_ms": 0.5},
                          detail={"gateway_ip": ip}))
    return out


def dns_hb(t: int, *, ok: bool = True, alt_ok: bool | None = None, sx: str = "8.8.8.8", ax: str = "1.1.1.1",
           port: str = "c01") -> list[dict[str, Any]]:
    out = [mk("dns_hb", t, "ok" if ok else "fail", port=port,
              labels={"resolver": sx, "resolver_kind": "dhcp"}, metrics={"rtt_ms": 12.0, "rcode": 0} if ok else None,
              error=None if ok else f"no answer from {sx} within 2 s")]
    if alt_ok is not None:
        out.append(mk("dns_hb", t + 100, "ok" if alt_ok else "fail", port=port,
                      labels={"resolver": ax, "resolver_kind": "alternate"},
                      error=None if alt_ok else f"no answer from {ax} within 2 s"))
    return out


def trace(t: int, *, reached: bool = True, last_ip: str = "10.99.0.1", last_ttl: int = 1, target: str = "8.8.8.8",
          path: str = "test", port: str = "c01", error: bool = False) -> dict[str, Any]:
    """A trace record (shape of test/fixtures/measurements/trace*.json)."""
    if error:
        return mk("trace", t, "error", port=port, labels={"path": path}, error="no client holds a lease")
    if reached:
        return mk("trace", t, "ok", port=port, labels={"path": path},
                  metrics={"reached": 1, "hops": 11, "last_ttl": 11, "rtt_ms": 12},
                  detail={"last_ip": target, "target": target, "dest_ttl": 11})
    return mk("trace", t, "fail", port=port, labels={"path": path},
              metrics={"reached": 0, "hops": last_ttl, "last_ttl": last_ttl},
              detail={"last_ip": last_ip, "target": target}, error=f"no reply from {target}; path stops after {last_ip}")


def wifi(t: int, *, ok: bool = True, ssid: str = "ACME", target_ssid: str | None = "ACME", gw: bool = True,
         error: str | None = None) -> dict[str, Any]:
    on = bool(ssid) and (target_ssid is None or ssid == target_ssid)
    metrics: dict[str, float] = {"link_up": 1, "rssi_dbm": -50}
    if gw:
        metrics["gw_rtt_ms"] = 2.0
    detail: dict[str, Any] = {"on_target": on}
    if target_ssid:
        detail["target_ssid"] = target_ssid
    return mk("wifi_hb", t, "ok" if ok else "fail", port="wifi", labels={"ssid": ssid or "none", "band": "5"},
              metrics=metrics, detail=detail, error=None if ok else (error or "no reply from gateway over Wi-Fi"))


def dhcp_hb(t: int, *, ok: bool = True, server: str = "10.1.0.2", port: str = "c01") -> dict[str, Any]:
    return mk("dhcp_hb", t, "ok" if ok else "fail", port=port, labels={"server": server if ok else "none"},
              metrics={"offer_ms": 20, "offers": 1 if ok else 0}, error=None if ok else "no DHCP offer")


def app(t: int, *, ok: bool = True, name: str = "youtube", port: str = "c01") -> dict[str, Any]:
    return mk("app", t, "ok" if ok else "fail", port=port, labels={"app": name},
              metrics={"total_ms": 80, "apdex": 1} if ok else None, error=None if ok else "connect timed out")


def healthy(t0: int, t1: int, *, step: int = 10_000, ports: int = 4) -> list[dict[str, Any]]:
    """Everything fine from t0 to t1: gateway, dns_hb, dhcp_hb, wifi_hb, trace and app beats every `step`."""
    out: list[dict[str, Any]] = []
    for i, t in enumerate(range(t0, t1, step)):
        out += gateway(t, ports=ports)
        out += dns_hb(t + 200, ok=True, alt_ok=True)
        out.append(dhcp_hb(t + 400))
        out.append(wifi(t + 600))
        out.append(trace(t + 800, reached=True, port=f"c{i % ports + 1:02d}"))
        out.append(app(t + 1000, port=f"c{i % ports + 1:02d}"))
    return out
