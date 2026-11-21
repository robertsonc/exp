"""A6.3: rate limits, internet-leg slots / queue / pause (admin switch and the runner's automatic pause from the fake
Orchestrator's WAN utilization), leg-token refusals, and a path timer that refuses client-chosen targets
(12-speedtest-analytics.md sections 4.4 and 10, SR-21/22)."""
from __future__ import annotations

import json
import time

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e
HARNESS = M.HARNESS


def _limits(core: M.Core, **kw):
    def f(cfg):
        cfg["limits"].update(kw)
    core.reconfigure("speedtest", f)


def test_a63_rate_limits(core: M.Core):
    a, b = core.new_client("rl1"), core.new_client("rl2")
    try:
        # per client address: at most N tests per 10 minutes
        _limits(core, tests_per_10min_per_ip=3, max_concurrent_per_ip=10, max_concurrent_tests=50)
        got = [a.create_session() for _ in range(3)]
        assert [g["status"] for g in got] == [201, 201, 201]
        r = a.create_session()
        assert r["status"] == 429 and r["json"]["error"]["code"] == "rate_limited", r["body"]
        assert r["json"]["error"]["details"]["limit"] == "tests_per_10min_per_ip"
        assert int(r["headers"]["retry-after"]) >= 1
        # another address is not affected
        assert b.create_session()["status"] == 201
        # per client address: concurrent tests
        _limits(core, tests_per_10min_per_ip=100, max_concurrent_per_ip=1, max_concurrent_tests=50)
        assert a.create_session()["status"] == 201
        r = a.create_session()
        assert r["status"] == 429 and r["json"]["error"]["details"]["limit"] == "max_concurrent_per_ip" and "retry-after" in r["headers"]
        assert b.create_session()["status"] == 201                       # b's own first concurrent test
        # per box: total concurrent tests
        _limits(core, tests_per_10min_per_ip=100, max_concurrent_per_ip=5, max_concurrent_tests=2)
        assert a.create_session()["status"] == 201 and b.create_session()["status"] == 201
        r = b.create_session()
        assert r["status"] == 429 and r["json"]["error"]["details"]["limit"] == "max_concurrent_tests", r["body"]
        assert "retry-after" in r["headers"]
    finally:
        core.reset_config("speedtest")


def test_a63_leg_token_refusals(core: M.Core):
    a, b = core.new_client("tk1"), core.new_client("tk2")
    try:
        _limits(core, leg_token_ttl_s=10, bytes_local=1_000_000, max_concurrent_per_ip=10, tests_per_10min_per_ip=100)
        s = a.create_session()
        assert s["status"] == 201
        # no token, garbage token, a token that is not ours
        assert a.http("GET", f"{core.page}/st/ping")["status"] == 401
        bad = a.http("GET", f"{core.page}/st/ping", headers={"X-Exp-Leg-Token": "expt_" + "A" * 60})
        assert bad["status"] == 401 and bad["json"]["error"]["code"] == "invalid_token", bad["body"]
        assert a.http("POST", f"{core.page}/st/up", data=b"x" * 1000)["status"] in (401, 411)
        # a valid token used from another address: bound to the observed client address
        stolen = b.leg(s, "GET", "/st/ping")
        assert stolen["status"] == 403 and stolen["json"]["error"]["code"] == "ip_mismatch", stolen["body"]
        # the owner works; the byte budget is enforced (refused, never clamped)
        assert a.leg(s, "GET", "/st/ping")["status"] in (200, 204)
        big = a.leg(s, "GET", "/st/down?bytes=2000000")
        assert big["status"] == 413 and big["json"]["error"]["code"] == "budget_exceeded", big["body"]
        ok = a.leg(s, "GET", "/st/down?bytes=600000")
        assert ok["status"] == 200 and ok["len"] == 600000
        again = a.leg(s, "GET", "/st/down?bytes=600000")
        assert again["status"] == 413, "the second 600 kB would exceed the 1 MB budget"
        up = a.leg(s, "POST", "/st/up", data=b"u" * 500_000)
        assert up["status"] == 413 or up["status"] == 200
        # expired: the token lives 10 s
        time.sleep(11.5)
        exp = a.leg(s, "GET", "/st/ping")
        assert exp["status"] == 401 and exp["json"]["error"]["code"] == "token_expired", exp["body"]
        # a view endpoint needs the view proof: wrong proof is the same 404 as an unknown session
        wrong = a.http("GET", f"{core.page}/st/api/v1/sessions/{s['sid']}", headers={"X-Exp-View-Proof": "expv_" + "B" * 43})
        unknown = a.http("GET", f"{core.page}/st/api/v1/sessions/st_" + "0" * 25 + "1", headers={"X-Exp-View-Proof": s["proof"]})
        assert wrong["status"] == unknown["status"] == 404 and wrong["body"] == unknown["body"]
    finally:
        core.reset_config("speedtest")


def test_a63_path_timer_refuses_client_chosen_targets(core: M.Core, phone: M.Client):
    """Whatever a client puts in the query of the path endpoint, the box times only its configured hops and the requesting
    client: a packet capture on the box sees no packet to the chosen address (pktwatch records everything outside the
    given subnets; the decoy sits outside all of them)."""
    core.col.put(HARNESS / "pktwatch.py", "/root/pktwatch.py")
    decoys = ["9.9.9.9", "203.0.113.77"]
    core.col.ok("rm -f /tmp/pw.json; (python3 /root/pktwatch.py /tmp/pw.json 10.9.0.0/24 10.1.0.0/24 10.255.0.0/16 172.30.46.0/24 127.0.0.0/8 "
                "> /tmp/pw.log 2>&1 &) ; sleep 1")
    s = phone.create_session()
    assert s["status"] == 201
    before = phone.view(s, "GET", "/path")
    assert before["status"] == 200
    for q in ("target=9.9.9.9", "addr=203.0.113.77", "ip=9.9.9.9&host=203.0.113.77", "gateway=9.9.9.9", "edge1=203.0.113.77"):
        r = phone.view(s, "GET", f"/path?{q}")
        assert r["status"] in (200, 400), r["body"]
        assert not any(d in r["body"] for d in decoys), r["body"]
    time.sleep(4)                                  # several path cycles
    after = phone.view(s, "GET", "/path")["json"]["path"]
    assert after["edge1_addr"] == "10.255.2.2" and after["gateway_ms"]["samples"] > 0 and after["device_icmp_ms"] is not None
    core.col.ok("pkill -INT -f pktwatch.py; sleep 1; true")
    seen = json.loads(core.col.ok("cat /tmp/pw.json"))
    flat = json.dumps(seen)
    for d in decoys:
        assert d not in flat, f"the box sent/received a packet to the client-chosen {d}: {flat[:400]}"


def test_a63_internet_slots_queue_and_pause(core: M.Core):
    a, b, c = core.new_client("sl1"), core.new_client("sl2"), core.new_client("sl3")
    try:
        _limits(core, max_concurrent_internet=2, max_concurrent_per_ip=5, tests_per_10min_per_ip=100)
        sa, sb, sc = a.create_session(), b.create_session(), c.create_session()
        assert [x["json"]["internet_leg"] for x in (sa, sb, sc)][:2] == ["ok", "ok"]
        ga, gb = a.view(sa, "POST", "/internet-slot", {"action": "acquire"}), b.view(sb, "POST", "/internet-slot", {"action": "acquire"})
        assert ga["json"]["state"] == "granted" and gb["json"]["state"] == "granted", (ga["body"], gb["body"])
        gc = c.view(sc, "POST", "/internet-slot", {"action": "acquire"})
        assert gc["json"]["state"] == "queued" and gc["json"]["queue_position"] == 1, gc["body"]      # FIFO: extras wait
        # releasing a slot lets the queue advance
        assert a.view(sa, "POST", "/internet-slot", {"action": "release"})["json"]["state"] == "released"
        gc2 = c.view(sc, "POST", "/internet-slot", {"action": "acquire"})
        assert gc2["json"]["state"] == "granted", gc2["body"]
        # the admin switch: effective at once for new sessions and slot requests
        core.col.ok("exp-speedtest pause-internet --on")
        time.sleep(2)
        sp = a.create_session()
        assert sp["json"]["internet_leg"] == "paused", sp["body"]
        pr = a.view(sp, "POST", "/internet-slot", {"action": "acquire"})
        assert pr["json"]["state"] == "paused" and pr["json"]["reason"] == "admin_pause", pr["body"]
        core.col.ok("exp-speedtest pause-internet --off")
        time.sleep(2)
        sr = b.create_session()
        assert sr["json"]["internet_leg"] in ("ok", "queued")
    finally:
        core.col.run("exp-speedtest pause-internet --off")
        core.reset_config("speedtest")


def test_a63_auto_pause_from_ec_wan_utilization(core: M.Core):
    """The runner polls the (fake) Orchestrator's WAN interface and pushes the utilization to the box over the localhost channel;
    above auto_pause_wan_util_pct (80) the internet leg pauses with reason wan_utilization, below it resumes."""
    a = core.new_client("ap1")
    try:
        _limits(core, max_concurrent_per_ip=100, tests_per_10min_per_ip=1000, max_concurrent_tests=1000)
        core.fake("orch", "POST", "/_fake/scenario", {"name": "healthy", "client_ip": a.ip})
        assert core.fake("orch", "POST", "/_fake/wan_load", {"rx_bps": 10_000_000, "tx_bps": 10_000_000})["util_pct"] < 80

        def internet_state():
            s = a.create_session()
            return s["json"]["internet_leg"] if s["status"] == 201 else s["status"]
        core.fake("orch", "POST", "/_fake/scenario", {"name": "saturated_wan", "client_ip": a.ip})
        t0 = time.time()
        M.wait_for(lambda: internet_state() == "paused", 90, 3, "internet leg auto-paused by the WAN utilization")
        paused_after = time.time() - t0
        s = a.create_session()
        slot = a.view(s, "POST", "/internet-slot", {"action": "acquire"})
        assert slot["json"]["state"] == "paused" and slot["json"]["reason"] == "wan_utilization", slot["body"]
        core.fake("orch", "POST", "/_fake/scenario", {"name": "healthy", "client_ip": a.ip})
        core.fake("orch", "POST", "/_fake/wan_load", {"rx_bps": 10_000_000, "tx_bps": 10_000_000})
        # the runner holds the previous minute bucket (hysteresis, ~2 min); the fake's buckets move on, so resume within ~3 min
        M.wait_for(lambda: internet_state() in ("ok", "queued"), 240, 5, "internet leg resumed")
        print(f"A6.3 auto-pause took {paused_after:.1f} s")
    finally:
        core.fake("orch", "POST", "/_fake/scenario", {"name": "healthy", "client_ip": a.ip})
        core.reset_config("speedtest")
