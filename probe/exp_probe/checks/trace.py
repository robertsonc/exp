"""`trace` (beat, rotating port) and its control path -- 02-probe.md 5.5.

A paced ICMP TTL sweep (`heartbeat.trace`: target, pace_ms, max_hops, timeout_s) from inside the
port's namespace (``path=test``), then -- when `control_path` is on -- the same sweep from the host
namespace pinned to the management interface (``path=control``): the internet path that does not
traverse the event network, so the rules engine can say "it's the edge" vs "it's the ISP".

The scheduler runs the two sweeps one after the other and never two traces at once (two sweeps from
behind one public address get rate-limited and falsely blame the edge); this module additionally
serializes sweeps within the process with a lock as defence in depth (SR-18: traceroute pacing).

Outcome: destination reached -> ok (degraded when its rtt exceeds `tests.trace.thresholds.rtt_ms`,
default 250 ms); not reached -> fail with the last hop that answered; no client holds a lease ->
`error` "no client could run it". The sweep algorithm itself lives in exp_probe.icmp.

Ported from reference/exm/lib/exm/heartbeat.py (`trace`, `trace_ctl`, `_trace_probe`).
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Any

from exp_common.schema import Measurement

from ..icmp import IcmpUnavailable, TraceResult, open_icmp, trace_sweep
from ..netio import NetnsMissing
from ..scheduler import TestContext, register_test
from .common import clip, error_record, is_ipv4, num, pick_port, thresholds

log = logging.getLogger(__name__)

DEFAULT_SLOW_MS = 250.0
MAX_DETAIL_HOPS = 64
_SWEEP_LOCK = threading.Lock()


def _sweep(env: Any, target: str, max_hops: int, pace_s: float, timeout_s: float) -> TraceResult:
    ep = open_icmp(env)
    try:
        return trace_sweep(ep, target, max_hops, pace_s, timeout_s)
    finally:
        ep.close()


def resolve_target(ctx: TestContext, env: Any, name: str, dns: list[str]) -> str:
    """IPv4 literal for the trace/ping target. Hostnames are resolved with the port's own resolvers
    (never the daemon's resolv.conf, which belongs to the host namespace)."""
    if is_ipv4(name):
        return name
    from .dns import query_a
    for server in dns or []:
        r = query_a(env, server, name, 2.0)
        for a in r.answers:
            if is_ipv4(a):
                return a
    if not dns and env.ns is None:
        try:
            return socket.gethostbyname(name)
        except OSError:
            pass
    raise LookupError(f"cannot resolve {clip(name, 80)}")


def hops_detail(res: TraceResult) -> list[list[Any]]:
    return [[h.ttl, h.ip, num(h.rtt_ms)] for h in res.hops[:MAX_DETAIL_HOPS]]


def _record(ctx: TestContext, res: TraceResult, port_id: str, path: str, target: str) -> Measurement:
    labels = {"port": port_id, "path": path}
    detail: dict[str, Any] = {"hops": hops_detail(res), "last_ip": res.last_ip, "target": target}
    if res.unreachable:
        detail["unreachable"] = {"ip": res.unreachable["ip"], "code": res.unreachable["code"],
                                 "ttl": res.unreachable["ttl"]}
    metrics: dict[str, float] = {"reached": 1.0 if res.reached else 0.0, "hops": float(len(res.hops)),
                                 "last_ttl": float(res.last_ttl)}
    if res.reached:
        metrics["rtt_ms"] = num(res.rtt_ms)  # type: ignore[assignment]
        slow = thresholds(ctx, "trace", "rtt_ms", DEFAULT_SLOW_MS)
        if (res.rtt_ms or 0) > slow:
            return ctx.measure("trace", "degraded", labels=labels, metrics=metrics, detail=detail,
                               error=f"{target} answered after {res.rtt_ms:g} ms")
        return ctx.measure("trace", "ok", labels=labels, metrics=metrics, detail=detail)
    where = (f"path stops after {res.last_ip} (hop {res.last_ttl})" if res.last_ip else "no hop answered")
    if res.unreachable:
        where += f"; {res.unreachable['ip']} says unreachable (code {res.unreachable['code']})"
    return ctx.measure("trace", "fail", labels=labels, metrics=metrics, detail=detail,
                       error=clip(f"no reply from {target}; {where}", 500))


@register_test("trace", roles=("client", "wifi"))
def trace(ctx: TestContext) -> list[Measurement]:
    assert ctx.port is not None
    hb = ctx.cfg.heartbeat["trace"]
    control = ctx.path == "control"
    path = "control" if control else "test"
    if control:
        port, info, why = ctx.port, None, []
        env = ctx.netenv(port, control=True)
    else:
        port, info, why = pick_port(ctx)
        if port is None:
            reason = "; ".join(why)
            return [error_record(ctx, "trace", ("no lease: " if ctx.explicit else "no client could run it: ") + reason,
                                 labels={"path": path})]
        env = ctx.netenv(port)
        if not env.exists():
            return [error_record(ctx, "trace", f"namespace for port {port.id} is missing", port=port,
                                 labels={"path": path})]
    labels = {"path": path}
    try:
        target = resolve_target(ctx, env, hb["target"], info.dns if info else [])
    except LookupError as exc:
        return [error_record(ctx, "trace", str(exc), port=port, labels=labels)]
    try:
        with _SWEEP_LOCK:
            res = env.call(_sweep, env, target, int(hb["max_hops"]), float(hb["pace_ms"]) / 1000.0,
                           float(hb["timeout_s"]))
    except NetnsMissing:
        return [error_record(ctx, "trace", f"namespace for port {port.id} is missing", port=port, labels=labels)]
    except IcmpUnavailable as exc:
        return [error_record(ctx, "trace", str(exc), port=port, labels=labels)]
    except OSError as exc:
        return [error_record(ctx, "trace", f"trace failed: {exc.strerror or exc}", port=port, labels=labels)]
    if res.error:
        return [error_record(ctx, "trace", res.error, port=port, labels=labels)]
    return [_record(ctx, res, port.id, path, hb["target"])]
