"""`ping` (beat, rotating port) -- 02-probe.md 5.6: ICMP echo to each `heartbeat.ping` target.

A small fixed target set only (config allows <= 16). One record per target (``target`` is the
measurement target, ``port`` the only label). PING_ECHOES echoes per target, PING_GAP_S apart, replies
awaited PING_TIMEOUT_S after the last. Outcome: every echo lost -> fail; any loss, or a mean rtt above
`tests.ping.thresholds.rtt_ms` (default 250) -> degraded; else ok. Hostnames are resolved with the
port's own DHCP resolvers; a target that cannot be resolved is a `fail` of that target (DNS
trouble), not an `error`.

Without a raw ICMP socket the iputils `ping` binary is used inside the namespace (argv list, parsed
by `icmp.parse_ping_output`); without either: `error` "ICMP socket unavailable".

Ported from reference/exm/lib/exm/heartbeat.py (`_ping`, `_echo`) and apps.py (`_ping` summary parsing).
"""
from __future__ import annotations

import logging
from typing import Any

from exp_common.schema import Measurement

from ..icmp import IcmpUnavailable, PingResult, open_icmp, parse_ping_output, ping_many
from ..netio import NetnsMissing
from ..scheduler import TestContext, register_test
from .common import error_record, is_ipv4, num, pick_port, thresholds
from .trace import resolve_target

log = logging.getLogger(__name__)

PING_ECHOES = 4
PING_GAP_S = 0.15
PING_TIMEOUT_S = 1.0
DEFAULT_SLOW_MS = 250.0


def _echo(env: Any, ips: list[str]) -> dict[str, PingResult]:
    ep = open_icmp(env)
    try:
        return ping_many(ep, ips, PING_ECHOES, PING_GAP_S, PING_TIMEOUT_S)
    finally:
        ep.close()


def ping_via_command(ctx: TestContext, port: Any, ip: str) -> PingResult | None:
    argv = ["ping", "-n", "-c", str(PING_ECHOES), "-i", "0.2", "-W", "1"]
    if ctx.cfg.mode == "host":
        argv += ["-I", port.lease_iface]
    r = ctx.runner.run(ctx.ns_argv(argv + [ip]), PING_ECHOES * 0.2 + PING_TIMEOUT_S + 5)
    res = parse_ping_output(r.stdout)
    if res is not None:
        res.target = ip
    return res


def classify(res: PingResult, slow_ms: float) -> tuple[str, str | None]:
    if res.received == 0:
        return "fail", "100% loss"
    if res.loss_pct > 0:
        return "degraded", f"{res.loss_pct:g}% loss"
    if (res.rtt_ms or 0) > slow_ms:
        return "degraded", f"mean rtt {res.rtt_ms:g} ms"
    return "ok", None


@register_test("ping", roles=("client", "wifi"))
def ping(ctx: TestContext) -> list[Measurement]:
    assert ctx.port is not None
    targets: list[str] = list(ctx.cfg.heartbeat["ping"])
    if not targets:
        return []
    port, info, why = pick_port(ctx)
    if port is None or info is None:
        reason = "; ".join(why)
        return [error_record(ctx, "ping", ("no lease: " if ctx.explicit else "no client could run it: ") + reason,
                             target=targets[0])]
    env = ctx.netenv(port)
    if not env.exists():
        return [error_record(ctx, "ping", f"namespace for port {port.id} is missing", port=port, target=targets[0])]
    slow_ms = thresholds(ctx, "ping", "rtt_ms", DEFAULT_SLOW_MS)
    out: list[Measurement] = []
    ips: dict[str, str] = {}
    for t in targets:
        if is_ipv4(t):
            ips[t] = t
            continue
        try:
            ips[t] = resolve_target(ctx, env, t, info.dns)
        except LookupError as exc:
            out.append(ctx.measure("ping", "fail", labels={"port": port.id}, target=t,
                                   metrics={"loss_pct": 100.0}, error=str(exc)))
    if not ips:
        return out
    results: dict[str, PingResult] = {}
    try:
        got = env.call(_echo, env, sorted(set(ips.values())))
        results = {t: got[ip] for t, ip in ips.items()}
    except NetnsMissing:
        return [error_record(ctx, "ping", f"namespace for port {port.id} is missing", port=port, target=t)
                for t in ips]
    except IcmpUnavailable as exc:
        for t, ip in ips.items():
            res = ping_via_command(ctx, port, ip)
            if res is None:
                out.append(error_record(ctx, "ping", str(exc), port=port, target=t))
            else:
                results[t] = res
    except OSError as exc:
        return out + [error_record(ctx, "ping", f"ICMP failed: {exc.strerror or exc}", port=port, target=t)
                      for t in ips]
    for t, res in results.items():
        if res.sent == 0:
            out.append(error_record(ctx, "ping", f"cannot send to {t}: {res.error}", port=port, target=t))
            continue
        outcome, err = classify(res, slow_ms)
        metrics: dict[str, float] = {"loss_pct": res.loss_pct}
        kw: dict[str, Any] = {"error": err} if err else {}
        if res.rtt_ms is not None:
            metrics["rtt_ms"] = num(res.rtt_ms)  # type: ignore[assignment]
            kw["duration_ms"] = num(res.rtt_ms)
        out.append(ctx.measure("ping", outcome, labels={"port": port.id}, target=t, metrics=metrics, **kw))
    return out
