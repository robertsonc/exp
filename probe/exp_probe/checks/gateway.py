"""`gateway` (02-probe.md 5.1): one record per port, every beat.

Link state and carrier_changes are read inside the port's namespace; then ICMP echoes to the
DHCP-learned gateway from a raw socket inside that namespace. The kernel does the ARP, so a gateway
that never answers ARP shows up as loss with ``detail.neighbor_state`` FAILED/INCOMPLETE.

Echoes: GATEWAY_ECHOES sent GATEWAY_GAP_S apart, replies awaited GATEWAY_TIMEOUT_S after the last.
(The spec says "2 tries"; with only two samples loss could only be 0/50/100 and the contract's
``degraded when 0 < loss_pct < 50`` could never fire, so the sample is 4 echoes -- most conservative
reading consistent with the contract.) Outcome: no link or no reply -> fail; 0 < loss < 50 -> degraded;
loss >= 50 -> fail (the gateway is dropping half or more of what it is sent); else ok.

Ported from reference/exm/lib/exm/gateway.py (`_check`, `_gateway_of`) and heartbeat.py (`_echo`).
"""
from __future__ import annotations

import json
import logging
from typing import Any

from exp_common.schema import Measurement

from ..icmp import IcmpUnavailable, open_icmp, ping_many
from ..netio import NetnsMissing
from ..scheduler import TestContext, register_test
from .common import clip, error_record, link_state, num, port_info

log = logging.getLogger(__name__)

GATEWAY_ECHOES = 4
GATEWAY_GAP_S = 0.1
GATEWAY_TIMEOUT_S = 1.0


def _neighbor(ctx: TestContext, gw: str, iface: str) -> tuple[str | None, str | None]:
    r = ctx.runner.run(ctx.ns_argv(["ip", "-j", "neigh", "show", "to", gw, "dev", iface]), 5)
    if not r.ok:
        return None, None
    try:
        doc = json.loads(r.stdout)
    except ValueError:
        return None, None
    for ent in doc if isinstance(doc, list) else []:
        if isinstance(ent, dict) and ent.get("dst") == gw:
            mac = ent.get("lladdr")
            state = ent.get("state") or []
            return (mac if isinstance(mac, str) else None), (state[0] if state else None)
    return None, None


def _echo(env: Any, gw: str) -> Any:
    ep = open_icmp(env)
    try:
        return ping_many(ep, [gw], GATEWAY_ECHOES, GATEWAY_GAP_S, GATEWAY_TIMEOUT_S)[gw]
    finally:
        ep.close()


def classify(loss_pct: float) -> str:
    """Outcome of a gateway echo run (see module docstring)."""
    if loss_pct <= 0:
        return "ok"
    return "degraded" if loss_pct < 50 else "fail"


@register_test("gateway")
def gateway(ctx: TestContext) -> list[Measurement]:
    port = ctx.port
    assert port is not None
    labels = {"port": port.id, "iface": port.iface}
    env = ctx.netenv(port)
    if not env.exists():
        return [error_record(ctx, "gateway", f"namespace for port {port.id} is missing", labels=labels)]
    link = link_state(ctx, port)
    if link is None:
        return [error_record(ctx, "gateway", f"cannot read link state of {port.iface} in {port.ns}", labels=labels)]
    metrics: dict[str, float] = {"link_up": 1.0 if link.up else 0.0}
    if link.carrier_changes is not None:
        metrics["carrier_changes"] = float(link.carrier_changes)
    if not link.up:
        return [ctx.measure("gateway", "fail", labels=labels, metrics=metrics,
                            error=f"no link on {port.iface}")]
    info = port_info(ctx, port)
    gw = info.gateway
    if not info.bound or not gw:
        return [error_record(ctx, "gateway", f"port {port.id} has no gateway (no DHCP lease)", labels=labels)]
    try:
        res = env.call(_echo, env, gw)
    except NetnsMissing:
        return [error_record(ctx, "gateway", f"namespace for port {port.id} is missing", labels=labels)]
    except IcmpUnavailable as exc:
        return [error_record(ctx, "gateway", str(exc), labels=labels)]
    except OSError as exc:
        return [error_record(ctx, "gateway", f"ICMP failed: {exc.strerror or exc}", labels=labels)]
    if res.error and not res.received:
        return [error_record(ctx, "gateway", f"cannot send to {gw}: {res.error}", labels=labels)]
    metrics["loss_pct"] = res.loss_pct
    detail: dict[str, Any] = {"gateway_ip": gw}
    mac, state = _neighbor(ctx, gw, port.lease_iface)
    if mac:
        detail["gateway_mac"] = clip(mac, 17)
    if state:
        detail["neighbor_state"] = clip(state, 16)
    rtt = res.rtt_ms
    kw: dict[str, Any] = {}
    if rtt is not None:
        metrics["rtt_ms"] = num(rtt)  # type: ignore[assignment]
        kw["duration_ms"] = num(rtt)
    outcome = classify(res.loss_pct)
    if outcome == "fail":
        kw["error"] = f"no reply from {gw}" if not res.received else f"{res.loss_pct:g}% loss to {gw}"
    return [ctx.measure("gateway", outcome, labels=labels, metrics=metrics, detail=detail, **kw)]

