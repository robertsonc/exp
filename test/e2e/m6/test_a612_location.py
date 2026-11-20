"""A6.12: location by correlation and the NAT guard (12-speedtest-analytics.md sections 3.1, 5.2, 11).

* the fake Mist resolves the client IP to its AP / zone / RSSI (wireless) and to its switch / port (wired);
* the DHCP-syslog fallback gives IP -> MAC and the subnet table gives the zone (the Mist API is down);
* with no connector the test is `zone: unresolved` but still carries the on-network, internet and DNS legs;
* NAT guard: the gateway NATs attendee traffic towards the box (`lanctl nat-core on`: the box sees 10.9.0.1, a translated source). The
  fake Mist is even told that address belongs to somebody else (a DIFFERENT device): resolution must fail closed (`zone: unresolved`,
  flag `nat_suspected`, reason outside_subnets / translated_address) and the test must never be bound to that wrong device. An
  ambiguous lookup (two MACs on one IP in the window) fails closed too.
"""
from __future__ import annotations

import time

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e
WRONG_MAC = "02:aa:bb:cc:dd:ee"
TRANSLATED = M.GW_CORE                      # what the box sees when the gateway masquerades attendee traffic


@pytest.fixture()
def slate(core: M.Core):
    core.clean_slate()
    yield core
    core.clean_slate()
    core.fake("mist", "POST", "/_fake/force", {"status": None, "count": 0})


def legs_present(full: dict) -> None:
    legs = full["test"]["legs"]
    assert legs["local"]["status"] == "ok" and legs["internet"]["status"] == "ok", legs
    assert legs["dns"]["resolver_ip"] and legs["path"]["gateway_ms"]["samples"] > 0 and legs["path"]["edge_ms"]["samples"] > 0, legs


def test_a612_mist_resolves_ap_zone_rssi(slate: M.Core):
    ph = slate.new_client("l-ap")
    slate.identify(ph)
    r, tid = slate.run_page(ph, name="a612-ap", timeoutMs=120000, shotResults="a612-01-located-390")
    full = slate.final(tid)
    d = slate.ev(full, "identity")["data"]
    assert d["resolved_by"] == "mist" and d["mac"] == ph.mac and d["ap_name"].startswith("hallb-ap-") and d["ap_mac"], d
    assert d["zone"] == "hall-b" and d["zone_source"] == "mist" and d["wired"] is False
    wifi = slate.ev(full, "wifi")["data"]
    assert wifi["client"]["ap_mac"] == d["ap_mac"] and isinstance(wifi["client"]["rssi"], (int, float)), wifi["client"]
    assert wifi["client"]["ssid"] == d["ssid"] and wifi["ap"]["mac"] == d["ap_mac"], wifi
    assert full["test"]["zone"] == "hall-b"
    legs_present(full)
    # the dashboard-side breakdown knows the AP (SQL ground truth is asserted in A6.8)
    assert any(x["key"] == d["ap_name"] for x in slate.dash().get("speedtests/aggregate", group_by="ap", metric="count")["items"])


def test_a612_mist_resolves_switch_and_port(slate: M.Core):
    ph = slate.new_client("l-sw")
    slate.identify(ph, "wired_port_errors")
    r, tid = slate.run_page(ph, name="a612-sw", timeoutMs=120000)
    full = slate.final(tid)
    d = slate.ev(full, "identity")["data"]
    assert d["resolved_by"] == "mist" and d["mac"] == ph.mac and d["wired"] is True, d
    assert d["switch_port"] == "ge-0/0/12" and d["switch_mac"], d
    wired = slate.ev(full, "wired")
    assert wired["status"] in ("ok", "partial") and wired["data"]["port"]["port_id"] == "ge-0/0/12", wired["data"]
    assert wired["data"]["client"]["port_id"] == ["ge-0/0/12"]
    legs_present(full)


def test_a612_dhcp_fallback_ip_to_mac_and_subnet_to_zone(slate: M.Core):
    ph = slate.new_client("l-dhcp")
    slate.identify(ph)
    slate.fake("mist", "POST", "/_fake/force", {"status": 503, "count": 400})
    slate.syslog(M.ss.rfc3164_message(M.ss.dhcp_isc("DHCPACK", ph.ip, ph.mac, hostname="dhcp-only"), ts=time.time() - 15, host="dhcp-core", tag="dhcpd"))
    r, tid = slate.run_page(ph, name="a612-dhcp", timeoutMs=120000)
    full = slate.final(tid)
    d = slate.ev(full, "identity")["data"]
    assert d["resolved_by"] == "dhcp" and d["mac"] == ph.mac, d
    assert d["zone"] == "hall-b" and d["zone_source"] == "subnet", d
    assert not d.get("ap_name"), "the DHCP fallback knows no AP"
    legs_present(full)


def test_a612_no_connector_unresolved_but_all_legs(slate: M.Core):
    def drop(cfg: dict) -> None:
        cfg["correlation"]["sources"].pop("mist", None)
        cfg["correlation"]["sources"].pop("ec", None)
        cfg["correlation"]["network"]["zone_subnets"] = []
    slate.reconfigure("runner", drop)
    slate.reconfigure("speedtest", lambda c: c["zone_labels"].update({"subnets": []}))
    try:
        ph = slate.new_client("l-none")
        r = ph.chromium({"name": "a612-none", "url": f"{slate.page}/", "timeoutMs": 120000})
        tid = r["submissions"][-1]["res"]["id"]
        full = slate.final(tid)
        d = slate.ev(full, "identity")["data"]
        assert d["resolved_by"] == "none" and d["zone"] == "unresolved" and not d.get("mac"), d
        assert full["test"]["zone"] == "unresolved"
        legs_present(full)
        assert slate.ev(full, "wifi")["status"] == "unavailable" and full["diagnosis"]["stage"] == "final"
    finally:
        slate.reset_config("runner")
        slate.reset_config("speedtest")


def nat_checks(slate: M.Core, ph: M.Client, tid: str, reason: str) -> None:
    full = slate.final(tid)
    d = slate.ev(full, "identity")["data"]
    assert d["resolved_by"] == "none" and d["zone"] == "unresolved" and d["zone_source"] == "unresolved", d
    assert d["nat_suspected"] is True and d["nat_reason"] == reason, d
    assert not any(k in d for k in ("mac", "device_key", "ap_name", "ssid", "hostname", "switch_port")), "never bound to a device"
    t = full["test"]
    assert t["zone"] == "unresolved" and "nat_suspected" in t["flags"], (t["zone"], t["flags"])
    assert not full.get("device_key")
    blob = str(full)
    assert WRONG_MAC not in blob and WRONG_MAC.replace(":", "") not in blob.lower(), "the wrong device's MAC leaked into the test"
    assert ph.mac not in blob.lower() and "f0:18:98:cc:dd:02" not in blob.lower(), "bound to a MAC although the lookup was not trustworthy"
    assert slate.ev(full, "wifi")["status"] in ("unavailable", "error") or not slate.ev(full, "wifi")["data"].get("client"), "no Wi-Fi evidence of a stranger"
    legs_present(full)
    assert full["diagnosis"]["stage"] == "final"


def test_a612_nat_guard_translated_source_fails_closed(slate: M.Core):
    ph = slate.new_client("l-nat")
    # the venue NATs: the box sees the gateway's core address for every attendee ...
    slate.lanctl("nat-core", "on")
    # ... and the fake Mist, asked about that address, names SOMEBODY ELSE (the dangerous case: a confident wrong answer)
    slate.fake("mist", "POST", "/_fake/reset")
    slate.fake("mist", "POST", "/_fake/scenario", {"name": "healthy", "ip": TRANSLATED, "mac": WRONG_MAC})
    slate.fake("orch", "POST", "/_fake/scenario", {"name": "healthy", "client_ip": TRANSLATED})
    r, tid = slate.run_page(ph, name="a612-nat", timeoutMs=120000, shotResults="a612-02-nat-390")
    full = slate.final(tid)
    assert full["test"]["client"].get("ip") == TRANSLATED, "the box really saw the translated source " + str(full["test"].get("client"))
    nat_checks(slate, ph, tid, "outside_subnets")
    # the translated address is also a configured translated/edge address, inside a (misconfigured) client subnet: translated_address
    def translated(cfg: dict) -> None:
        net = cfg["correlation"]["network"]
        net["client_subnets"] = ["10.1.0.0/24", "10.9.0.0/24"]
        net["translated_addresses"] = [TRANSLATED]
    slate.reconfigure("runner", translated)
    try:
        ph2 = slate.new_client("l-nat2")
        r2, tid2 = slate.run_page(ph2, name="a612-nat2", timeoutMs=120000)
        nat_checks(slate, ph2, tid2, "translated_address")
    finally:
        slate.reset_config("runner")
        slate.lanctl("nat-core", "off")
    # control: with the translation gone the very next test resolves normally (the guard is not a blanket refusal)
    ph3 = slate.new_client("l-nat3")
    slate.identify(ph3)
    r3, tid3 = slate.run_page(ph3, name="a612-after", timeoutMs=120000)
    d3 = slate.ev(slate.final(tid3), "identity")["data"]
    assert d3["resolved_by"] == "mist" and d3["mac"] == ph3.mac and d3["nat_suspected"] is False, d3


def test_a612_nat_guard_ambiguous_lookup_fails_closed(slate: M.Core):
    ph = slate.new_client("l-amb")
    slate.identify(ph, "nat_ambiguity")            # two MACs on one IP inside the window
    r, tid = slate.run_page(ph, name="a612-amb", timeoutMs=120000)
    full = slate.final(tid)
    assert slate.ev(full, "identity")["data"]["candidates"] == 2
    nat_checks(slate, ph, tid, "ambiguous")
