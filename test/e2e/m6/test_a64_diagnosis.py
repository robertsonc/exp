"""A6.4: diagnosis against ground truth (12-speedtest-analytics.md section 11; CR-m6-spec-resolutions: "drills as ground truth" =
harness faults + the vendor fakes' scenarios, M5 drills do not exist).

Each case injects ONE cause the way the harness can, runs a real phone test, waits for the final evidence and asserts the
collector's rule engine names it first:

* wifi_signal   : the fake Mist scenario `weak_rssi` (RSSI -83 dBm, SNR 9) + the phone's link throttled by CDP (the stand-in for the
                  airtime a real attenuated radio costs: the harness has no radio, the throttle is the page-side half of the fault);
* internet_path : `lanctl delay --at wan` (+ the fake Cloudflare's bandwidth cap = the netem rate) with the fake Orchestrator healthy;
* wan_saturation: the same WAN fault with the fake Orchestrator's `saturated_wan` scenario (92.5 % utilization) -- internet leg auto-pause
                  off for that case (it is asserted on separately: the runner's EC feed pauses the internet leg at the default threshold);
* policy_block  : EdgeConnect-style firewall DENY syslog lines for the client sent to the runner's receiver; the diagnosis cites the
                  security evidence whose event carries that very line;
* network_wide  : every probe port loses DNS (lanctl block-dns on core-tp0..2) -> the probe baseline fails at the same time.
"""
from __future__ import annotations

import json
import time

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e
SLOW_CF = {"down_bps": 9_000_000, "up_bps": 4_000_000}            # the WAN side is "slow": the internet leg under the 25 / 10 Mb/s targets
RULE = "deny-guest-to-mgmt"


def fw_lines(ip: str, n: int = 3) -> list[str]:
    now = time.time()
    return [M.ss.rfc3164_message(M.ss.ec_firewall(src=ip, dst="10.0.0.10", sport=51234 + i, dport=22, action="DENY", rule=RULE), ts=now - i,
                                 host="ec-core", tag="zbf") for i in range(n)]


def _dump_on_fail(full: dict, ok: bool) -> None:
    """Keep the whole final record of a failed diagnosis case in the artifacts (the assertion text alone is truncated by pytest)."""
    if not ok:
        (M.ARTIFACTS / f"a64-fail-{full['test']['id']}.json").write_text(json.dumps(full, indent=1, default=str))


def internet_leg_open(core: M.Core, stable_s: int = 25) -> None:
    """Wait until the box's internet leg has stayed un-paused for `stable_s` seconds in a row. After the saturated-WAN case the runner holds
    the WAN peak (hysteresis) and the metric can read 0 and then flip back to 1 once the next EC poll lands; a case that needs the leg
    (score below the "healthy" short-circuit, SLOW_CF) must not start inside that window - regression for the full-suite flake where the
    paused leg gave score 99 and diagnosis "none" although the evidence held the deny lines / failing probe."""
    state = {"since": None}

    def stable() -> bool:
        if core.st_status()["metrics"]["internet_leg_paused"] == 1:
            state["since"] = None
            return False
        state["since"] = state["since"] or time.time()
        return time.time() - state["since"] >= stable_s
    M.wait_for(stable, 420, 5, "the internet leg to stay open")


def run(core: M.Core, phone: M.Client, **opts):
    opts.setdefault("timeoutMs", 170000)
    r, tid = core.run_page(phone, name=opts.pop("name", "a64"), **opts)
    return r, tid, core.final(tid)


@pytest.fixture()
def slate(core: M.Core):
    core.clean_slate()
    yield core
    core.clean_slate()


def test_a64_wifi_signal(slate: M.Core):
    ph = slate.new_client("d-wifi")
    slate.identify(ph, "weak_rssi")
    # the attenuated radio: ~12 / 5 Mb/s over the air (CDP network conditions stand for it)
    r, tid, full = run(slate, ph, name="a64-wifi", throttle={"downKbps": 12000, "upKbps": 5000, "latencyMs": 20}, shotResults="a64-01-wifi-390")
    wifi = slate.ev(full, "wifi")["data"]["client"]
    assert wifi["rssi"] == -83 and wifi["snr"] == 9, wifi
    legs = full["test"]["legs"]
    assert legs["local"]["down_mbps"] < 25, legs["local"]
    cs = slate.causes(full)
    assert cs[0] == "wifi_signal", (cs, full["diagnosis"]["noc_text"])
    cites = {(c["kind"], c["ref"]) for c in full["diagnosis"]["cause"][0]["cites"]}
    assert ("wifi", "data.client.rssi") in cites and "RSSI" in full["diagnosis"]["noc_text"]
    assert "Wi-Fi" in full["diagnosis"]["user_text"] or "signal" in full["diagnosis"]["user_text"].lower(), full["diagnosis"]["user_text"]


def test_a64_internet_path_on_wan_delay(slate: M.Core):
    ph = slate.new_client("d-path")
    slate.identify(ph)
    slate.lanctl("delay", "--at", "wan", "--ms", "60")
    slate.cf_set(**SLOW_CF)
    r, tid, full = run(slate, ph, name="a64-path", shotResults="a64-02-internet-path-390")
    legs = full["test"]["legs"]
    assert legs["local"]["status"] == "ok" and legs["local"]["down_mbps"] > 50, legs["local"]
    assert legs["internet"]["status"] == "ok" and legs["internet"]["down_mbps"] < 25, legs["internet"]
    cs = slate.causes(full)
    assert cs[0] == "internet_path" and "wan_saturation" not in cs, (cs, full["diagnosis"]["noc_text"])
    assert slate.ev(full, "wan")["data"]["appliances"][0]["interfaces"][0]["util_pct"] < 50      # the fake EC says the WAN link is fine


def test_a64_wan_saturation_and_auto_pause(slate: M.Core):
    ph = slate.new_client("d-wan")
    slate.identify(ph, orch="saturated_wan")
    # (a) default threshold (80 %): the runner's EC WAN-utilization feed pauses the internet leg for everyone (fail-open feed, 12 section 4.5)
    def paused() -> bool:
        return slate.st_status()["metrics"]["internet_leg_paused"] == 1
    M.wait_for(paused, 90, 3, "the box's internet leg auto-paused by the EC WAN utilization")
    r, tid, full = run(slate, ph, name="a64-pause", timeoutMs=120000)
    assert full["test"]["legs"]["internet"]["status"] == "paused" and "internet_paused" in full["test"]["flags"], full["test"]
    assert full["test"]["legs"]["local"]["status"] == "ok"
    # the evidence still shows why (WAN > 85 %); the quick score rests on the on-network leg alone (a paused leg is not a fault of the user)
    assert slate.ev(full, "wan")["data"]["appliances"][0]["interfaces"][0]["util_pct"] > 85
    # (b) auto-pause off: the leg runs through the (delayed, capped) WAN and the diagnosis is wan_saturation, not internet_path
    slate.reconfigure("speedtest", lambda c: c["internet_leg"].update({"auto_pause_wan_util_pct": 100}))
    try:
        slate.lanctl("delay", "--at", "wan", "--ms", "60")
        slate.cf_set(**SLOW_CF)
        ph2 = slate.new_client("d-wan2")
        slate.identify(ph2, orch="saturated_wan")
        r2, tid2, full2 = run(slate, ph2, name="a64-wan", shotResults="a64-03-wan-390")
        assert full2["test"]["legs"]["internet"]["status"] == "ok", full2["test"]["legs"]["internet"]
        cs = slate.causes(full2)
        assert cs[0] == "wan_saturation" and "internet_path" not in cs, (cs, full2["diagnosis"]["noc_text"])
        assert slate.ev(full2, "wan")["data"]["appliances"][0]["interfaces"][0]["util_pct"] > 85
        assert "WAN util" in full2["diagnosis"]["noc_text"]
    finally:
        slate.reset_config("speedtest")
        slate.clean_slate()
        # the runner holds the WAN peak ~2 minutes (hysteresis on the way down): wait until the leg is open again for the next case
        M.wait_for(lambda: not paused(), 300, 5, "the held WAN peak to expire so the internet leg is open again")


def test_a64_policy_block_cites_the_syslog_line(slate: M.Core):
    internet_leg_open(slate)
    ph = slate.new_client("d-fw")
    slate.identify(ph)
    slate.cf_set(**SLOW_CF)
    # TCP: a single lost UDP datagram under the full-suite load made this case flaky (diagnosis "none"); the receiver takes both
    slate.syslog(*fw_lines(ph.ip), proto="tcp")
    r, tid, full = run(slate, ph, name="a64-fw", shotResults="a64-04-policy-390")
    cs = slate.causes(full)
    _dump_on_fail(full, cs[0] == "policy_block")
    assert cs[0] == "policy_block", (cs, full["diagnosis"]["noc_text"])
    cites = {(c["kind"], c["ref"]) for c in full["diagnosis"]["cause"][0]["cites"]}
    assert ("security", "data.events") in cites, cites
    sec = slate.ev(full, "security")
    assert sec["status"] in ("ok", "partial")
    denies = [e for e in sec["data"]["events"] if e["action"] in ("deny", "block", "drop")]
    assert denies, sec["data"]
    assert any(RULE in (e.get("rule", "") + e.get("raw", "")) and ph.ip in (e.get("src_ip", "") + e.get("raw", "")) for e in denies), denies
    assert any(str(ref).startswith("syslog:") for ref in (sec.get("raw_refs") or [])), sec.get("raw_refs")
    assert "rule " + RULE in full["diagnosis"]["noc_text"], full["diagnosis"]["noc_text"]


def test_a64_network_wide_when_a_probe_fails_too(slate: M.Core):
    internet_leg_open(slate)
    ph = slate.new_client("d-nw")
    slate.identify(ph)
    slate.cf_set(**SLOW_CF)
    ports = [f"core-tp{i}" for i in range(3)]
    for p in ports:
        slate.lanctl("block-dns", p)
    try:
        def probe_failing() -> bool:
            return slate.line_states().get("dns") in ("fail", "warn")
        M.wait_for(probe_failing, 150, 5, "the probe's DNS line failing")
        r, tid, full = run(slate, ph, name="a64-nw", shotResults="a64-05-network-wide-390")
        base = slate.ev(full, "baseline")["data"]
        assert base["severity"] in ("warn", "fail") and any(ln["key"] == "dns" and ln["state"] in ("warn", "fail") for ln in base["lines"]), base
        cs = slate.causes(full)
        _dump_on_fail(full, cs[0] == "network_wide")
        assert cs[0] == "network_wide", (cs, full["diagnosis"]["noc_text"])
    finally:
        slate.lanctl("restore")
        M.wait_for(lambda: slate.line_states().get("dns") == "ok", 180, 5, "the probe's DNS line recovered")
