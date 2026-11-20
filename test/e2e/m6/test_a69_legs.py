"""A6.9: legs. On the harness, added delay on the gateway link, the edge link and the WAN side each moves only the matching
leg (and the right waterfall segment); the DNS leg reports the resolver IP and cold/warm times via the delegated zone, and
falls back to the probe measurement without it (12-speedtest-analytics.md section 11).

Delay model (lanctl delay): netem on ONE link (one direction, so +D ms RTT of everything beyond it). The box times hops
cumulatively, so a delay on a link moves the legs timed to a hop at or beyond it and none before:

    core --[gateway link]-- gateway --[edge link]-- edge --[WAN link]-- isp (edge+1) -- internet
    segment (what the waterfall adds): gateway = gw RTT, edge = edge RTT - gw RTT, WAN = edge1 RTT - edge RTT

    fault   | gateway RTT | edge RTT | edge1 RTT | device<->box | device<->internet | segment that grows
    gateway | +D          | +D       | +D        | +D           | -                 | gateway
    edge    | -           | +D       | +D        | -            | +D                | edge
    WAN     | -           | -        | +D        | -            | +D                | WAN
"""
from __future__ import annotations

import json
import time

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e
D = 60.0


def metrics(core: M.Core, tid: str) -> dict[str, float | None]:
    t = core.test_detail(tid)["test"]
    p = t["legs"]["path"]
    gw, ed, e1 = (p[k]["idle"] for k in ("gateway_ms", "edge_ms", "edge1_ms"))
    assert None not in (gw, ed, e1), p
    return {"gw": gw, "edge": ed, "edge1": e1, "seg_gw": gw, "seg_edge": ed - gw, "seg_wan": e1 - ed,
            "on_net": t["legs"]["local"]["idle_ms"], "internet": t["legs"]["internet"]["idle_ms"],
            "dns_cold": t["legs"]["dns"]["cold_ms"], "dns_warm": t["legs"]["dns"]["warm_ms"]}


def fresh_ring(core: M.Core) -> None:
    """The box reports the median of the LAST 5 MINUTES of its idle hop samples (venue-infrastructure health shared by all tests),
    so a fault that has lasted seconds cannot move it. Restarting the service starts an empty ring; a few fresh samples (one per
    5 s, the first at once) then describe the CURRENT state of the links."""
    core.col.ok("systemctl restart exp-speedtest.service", timeout=90)
    core.wait_healthy("speedtest")
    time.sleep(16)


def run(core, phone, tag):
    fresh_ring(core)
    r, tid = core.run_page(phone, name=tag, timeoutMs=120000, waitChecksMs=30000, shotFinal=f"a69-{tag}-final-390", settleMs=800)
    m = metrics(core, tid)
    m["wf"] = (r.get("checked") or r["first"])["wf"]
    return m


@pytest.mark.parametrize("where,moves,still", [
    ("gateway", {"gw", "edge", "edge1", "seg_gw", "on_net", "dns_cold"}, {"seg_edge", "seg_wan", "internet"}),
    ("edge", {"edge", "edge1", "seg_edge", "internet"}, {"gw", "seg_gw", "seg_wan", "on_net"}),
    ("wan", {"edge1", "seg_wan", "internet"}, {"gw", "edge", "seg_gw", "seg_edge", "on_net"}),
])
def test_a69_delay_moves_only_the_matching_leg(core: M.Core, where, moves, still, artifacts):
    phone = core.new_client(f"l9{where}"[:8])
    core.fake("mist", "POST", "/_fake/scenario", {"name": "healthy", "ip": phone.ip, "mac": phone.mac})
    base = run(core, phone, f"{where}-base")
    core.lanctl("delay", "--at", where, "--ms", str(int(D)))
    try:
        slow = run(core, phone, f"{where}-slow")
    finally:
        core.lanctl("delay-clear")
    delta = {k: (slow[k] - base[k]) for k in base if k != "wf" and slow[k] is not None and base[k] is not None}
    (artifacts / f"a69-{where}.json").write_text(json.dumps({"delay_ms": D, "base": base, "slow": slow, "delta": delta}, indent=1))
    print(f"A6.9 {where}: delta {json.dumps({k: round(v, 1) for k, v in delta.items()})}")
    for k in moves:
        assert delta[k] >= 0.6 * D, f"{where}: {k} should have moved by ~{D} ms, delta {delta[k]:.1f} ({delta})"
    for k in still:
        assert abs(delta[k]) <= 0.35 * D, f"{where}: {k} should not move, delta {delta[k]:.1f} ({delta})"
    if where == "gateway":                       # the DNS leg: cold goes through the delayed link to the box, warm is cached
        assert slow["dns_cold"] - slow["dns_warm"] >= 0.6 * D, slow
    assert slow["wf"], "the page draws a waterfall"


def test_a69_dns_leg_resolver_cold_warm_and_fallback(core: M.Core, phone: M.Client):
    # with the delegation: the browser's own resolver, seen by the box
    r, tid = core.run_page(phone, name="a69-dns", timeoutMs=120000)
    dns = core.test_detail(tid)["test"]["legs"]["dns"]
    assert dns["source"] == "browser" and dns["resolver_ip"] == M.GW_CORE, dns
    assert dns["cold_ms"] is not None and dns["warm_ms"] is not None and dns["cold_ms"] >= dns["warm_ms"], dns
    flags = core.test_detail(tid)["test"]["flags"]
    assert "dns_fallback" not in flags
    # without the delegation (the resolver answers NXDOMAIN for the zone): the probe's DNS line stands in, flagged
    core.lanctl("delegation", "off")
    try:
        r2, tid2 = core.run_page(phone, name="a69-nodeleg", timeoutMs=150000)
        t2 = core.test_detail(tid2)["test"]
        assert t2["legs"]["dns"]["source"] == "probe", t2["legs"]["dns"]
        assert t2["legs"]["dns"]["resolver_ip"] is None
        assert "dns_fallback" in t2["flags"], t2["flags"]
        assert t2["legs"]["local"]["status"] == "ok" and t2["legs"]["internet"]["status"] == "ok"
    finally:
        core.lanctl("delegation", "on")
