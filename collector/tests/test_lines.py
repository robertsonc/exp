"""The site lines board (CR-site-lines-board): per-port stations, untestable behind a stop, the ring / multi / arc /
spoke findings, the reference path, by-IP evidence, the headline, silence, the timeline. Scenarios follow the EGC
prototype's inject buttons. Records are synthetic but shaped like real ones (one record per port per check)."""
from __future__ import annotations

from typing import Any

import synth

from exp_collector.config import BoardPort
from exp_collector.lines import SCHEMA, site_lines, timeline
from exp_collector.rules import evaluate_records

T0 = 1_800_000_000_000
STEP = 10_000
NOW = T0 + 30 * STEP            # 5 min of history

# network -> probe, ports (c01..c03 wired); "control" is the out-of-band reference
NETS = {"event": "probe-ev", "vendor": "probe-vn", "admin": "probe-ad", "hpe": "probe-hp"}
REF = ("control", "probe-ct")


def _beat(probe: str, port: str, t: int, bad: set[str]) -> list[dict[str, Any]]:
    """One heartbeat of one port: gateway, DHCP, DNS, trace (by IP) and app (by name). `bad`: stations failing."""
    m = synth.mk
    ok = lambda s: "fail" if s in bad else "ok"  # noqa: E731
    return [
        m("gateway", t, ok("network"), port=port, probe=probe, metrics={"link_up": 1, "loss_pct": 100 if "network" in bad else 0,
                                                                       "rtt_ms": 0.5}, target="10.1.0.1"),
        {**synth.dhcp_hb(t + 100, ok="dhcp" not in bad, port=port), "probe": probe},
        *[{**d, "probe": probe} for d in synth.dns_hb(t + 200, ok="dns" not in bad, port=port)],
        {**synth.trace(t + 300, reached="internet" not in bad, port=port), "probe": probe},
        {**synth.app(t + 400, ok="apps" not in bad, port=port), "probe": probe},
    ]


def _site(fail: dict[tuple[str, str], set[str]] | None = None, *, since: int = NOW - 6 * STEP, until: int = NOW,
          silent: set[tuple[str, str]] = frozenset(), ports: int = 3, ref: bool = True) -> tuple[dict, dict]:
    """Records for every network and port; (probe, port) in `fail` fails those stations from `since` to `until`."""
    fail = fail or {}
    nets = dict(NETS)
    if ref:
        nets[REF[0]] = REF[1]
    evs, board = {}, {}
    for net, probe in nets.items():
        recs: list[dict[str, Any]] = []
        pids = [f"c{i + 1:02d}" for i in range(ports)]
        for t in range(T0, NOW + 1, STEP):
            for p in pids:
                if (probe, p) in silent and t > NOW - 10 * STEP:
                    continue
                bad = fail.get((probe, p), set()) if since <= t <= until else set()
                recs += _beat(probe, p, t, bad)
        evs[probe] = evaluate_records(recs, NOW, probe=probe, site="hall-b")
        board[probe] = [BoardPort(p, net, "wired", net == REF[0]) for p in pids]
    return evs, board


def _all(net: str, stations: set[str], ports: int = 3) -> dict[tuple[str, str], set[str]]:
    probe = REF[1] if net == REF[0] else NETS[net]
    return {(probe, f"c{i + 1:02d}"): set(stations) for i in range(ports)}


def doc(**kw: Any) -> dict[str, Any]:
    evs, board = _site(**kw)
    return site_lines(evs, board, "hall-b", NOW)


def test_all_good():
    d = doc()
    assert d["schema"] == SCHEMA and d["headline"]["h"] == "All good. Nobody push a change."
    assert not d["findings"] and [n["id"] for n in d["networks"]] == ["admin", "event", "hpe", "vendor", "control"]
    ev = next(n for n in d["networks"] if n["id"] == "event")
    assert ev["through"] == 3 and ev["closed_at"] is None and ev["stations"]["wifi"]["state"] == "na"
    assert d["cadence_s"] == 10.0


def test_one_network_loses_the_internet_and_the_stations_behind_are_untestable():
    d = doc(fail=_all("event", {"internet", "apps"}))
    f = d["findings"][0]
    assert (f["scope"], f["station"], f["networks"], f["phase"]) == ("arc", "internet", ["event"], "down")
    assert d["headline"]["h"].startswith("Event lost the internet.")
    ev = next(n for n in d["networks"] if n["id"] == "event")
    port = ev["ports"][0]["stations"]
    assert port["internet"]["state"] == "stopped" and port["apps"]["state"] == "untestable", "apps is behind the stop"
    assert ev["closed_at"] == "internet" and ev["through"] == 0
    assert "untestable, not failed" in d["headline"]["sub"]


def test_dns_on_two_networks_is_one_finding_and_by_ip_says_it_is_the_resolver():
    fail = {**_all("vendor", {"dns"}), **_all("admin", {"dns"})}
    d = doc(fail=fail)
    f = d["findings"][0]
    assert f["scope"] == "multi" and sorted(f["networks"]) == ["admin", "vendor"] and f["affected"] == 6
    assert f["evidence"] == {"by_ip_ok": 6, "n": 6, "kind": "names"}
    assert "Same failure, 2 networks" in d["headline"]["h"]
    assert "it is the resolver" in d["headline"]["why"]


def test_everyone_loses_the_internet_but_the_reference_passes_so_it_is_our_edge():
    fail = {}
    for net in NETS:
        fail.update(_all(net, {"internet", "apps"}))
    d = doc(fail=fail)
    f = d["findings"][0]
    assert f["scope"] == "ring" and f["station"] == "internet"
    assert d["headline"]["h"] == "No internet. Just us and the LAN."
    assert "reference reaches the same destinations" in d["headline"]["why"]


def test_everyone_and_the_reference_lose_the_internet_so_it_is_outside():
    fail = {}
    for net in (*NETS, REF[0]):
        fail.update(_all(net, {"internet", "apps"}))
    d = doc(fail=fail)
    assert d["headline"]["h"] == "The internet is down. For once it isn't us."
    assert not any(f.get("reference") for f in d["findings"]), "the reference is part of the ring, not its own finding"


def test_web_by_name_only_points_at_web_policy():
    d = doc(fail=_all("event", {"apps"}))
    f = d["findings"][0]
    assert f["station"] == "apps" and f["evidence"]["kind"] == "names"
    assert "HTTPS by name does not" in d["headline"]["why"]


def test_one_port_is_a_spoke_and_its_neighbours_pass():
    d = doc(fail={("probe-hp", "c02"): {"network"}})
    f = d["findings"][0]
    assert f["scope"] == "spoke" and f["ports"][0]["port"] == "c02"
    assert d["headline"]["h"] == "One port is having a bad day."
    assert "its 2 Hpe neighbours pass" in d["headline"]["sub"]


def test_the_reference_failing_alone_is_reported_beside_production():
    d = doc(fail=_all("control", {"dhcp"}))
    f = d["findings"][0]
    assert f["reference"] and f["station"] == "dhcp"
    assert d["headline"]["h"] == "The reference lost DHCP. Production is fine."


def test_a_recovered_fault_is_verifying_then_clean():
    d = doc(fail=_all("event", {"dns"}), since=NOW - 12 * STEP, until=NOW - 6 * STEP)
    f = d["findings"][0]
    assert f["phase"] == "verifying" and d["headline"]["chip"] == "VERIFYING"
    d2 = doc(fail=_all("event", {"dns"}), since=T0, until=T0 + 3 * STEP)        # long ago: clean
    assert not d2["findings"]


def test_a_silent_port_is_a_gap_not_a_fault():
    d = doc(silent={("probe-ad", "c01")})
    assert not d["findings"] and d["headline"]["h"] == "One port went quiet."
    ad = next(n for n in d["networks"] if n["id"] == "admin")
    assert ad["silent"] == 1 and ad["ports"][0]["silent"] is True


def test_same_records_same_board():
    evs, board = _site(fail=_all("vendor", {"dhcp"}))
    assert site_lines(evs, board, "hall-b", NOW) == site_lines(evs, board, "hall-b", NOW)


def test_timeline_swells_with_the_share_of_affected_ports():
    evs, board = _site(fail={("probe-ev", "c01"): {"dns"}, ("probe-ev", "c02"): {"dns"}})
    tl = timeline(evs, board, NOW - 20 * STEP, NOW, STEP)
    ev = next(n for n in tl["networks"] if n["network"] == "event")
    last = ev["points"][-1]
    assert last["state"] in ("stopped", "confirming") and abs(last["share"] - 2 / 3) < 0.01
    assert ev["points"][0]["state"] == "ok" and ev["points"][0]["share"] == 0.0
    vn = next(n for n in tl["networks"] if n["network"] == "vendor")
    assert all(p["state"] == "ok" for p in vn["points"])
