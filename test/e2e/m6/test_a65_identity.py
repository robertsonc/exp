"""A6.5: identity resolution via the fake Mist API and via the DHCP-syslog fallback; the unresolved path still produces a result
(12-speedtest-analytics.md sections 3.1, 5.2, 11).

* Mist: the client IP -> MAC (+ device_key = HMAC(per-org secret, MAC)), AP, SSID, band, zone through the zone map;
* DHCP fallback: the Mist API is down (503) -> IP -> MAC from a DHCP-ack syslog line in the window (ISC dhcpd and Kea formats),
  subnet -> zone; never a name;
* unresolved: Mist knows nobody with that IP (fails closed) AND no connector at all -> still a stored, diagnosed test with every leg.
"""
from __future__ import annotations

import time

import pytest
from exp_common import speedtest as st

import m6lib as M

pytestmark = pytest.mark.e2e


@pytest.fixture()
def slate(core: M.Core):
    core.clean_slate()
    yield core
    core.clean_slate()
    core.fake("mist", "POST", "/_fake/force", {"status": None, "count": 0})


def all_legs_present(full: dict) -> None:
    legs = full["test"]["legs"]
    assert legs["local"]["status"] == "ok" and legs["internet"]["status"] == "ok", legs
    assert legs["dns"]["source"] in ("browser", "probe") and legs["path"]["gateway_ms"]["samples"] > 0, legs
    assert full["diagnosis"]["stage"] == "final" and full["diagnosis"]["user_text"]


def test_a65_identity_via_mist(slate: M.Core):
    ph = slate.new_client("i-mist")
    slate.identify(ph)
    r, tid = slate.run_page(ph, name="a65-mist", timeoutMs=120000)
    full = slate.final(tid)
    ident = slate.ev(full, "identity")
    d = ident["data"]
    assert ident["status"] == "ok" and d["resolved_by"] == "mist" and d["mac"] == ph.mac and d["ip"] == ph.ip, d
    assert d["device_key"] == st.device_key(slate.expk, ph.mac), "device_key = HMAC(per-org secret, MAC)"
    assert d["zone"] == "hall-b" and d["zone_source"] == "mist" and d["ap_name"].startswith("hallb-ap-") and d["ssid"] and d["band"], d
    assert d["candidates"] == 1 and d["nat_suspected"] is False
    assert full["test"]["zone"] == "hall-b" and full["test"]["zone_source"] == "mist"
    assert full["device_key"] == d["device_key"]
    wifi = slate.ev(full, "wifi")["data"]["client"]
    assert wifi["mac"] == ph.mac and wifi["rssi"] is not None
    # the default (non-admin) view carries no raw identifier, only the join key
    plain = slate.test_detail(tid)
    pi = next(e for e in plain["evidence"] if e["kind"] == "identity")["data"]
    assert "mac" not in pi and "ip" not in pi and "hostname" not in pi and pi["device_key"] == d["device_key"], pi
    all_legs_present(full)


@pytest.mark.parametrize("fmt", ["isc", "kea"])
def test_a65_identity_via_dhcp_syslog_fallback(slate: M.Core, fmt: str):
    ph = slate.new_client(f"i-{fmt}")
    slate.identify(ph)
    slate.fake("mist", "POST", "/_fake/force", {"status": 503, "count": 400})       # the Mist API is down: not a "no match", an outage
    now = time.time()
    if fmt == "isc":
        line = M.ss.rfc3164_message(M.ss.dhcp_isc("DHCPACK", ph.ip, ph.mac, hostname="booth-laptop"), ts=now - 20, host="dhcp-core", tag="dhcpd")
    else:
        line = M.ss.dhcp_kea(ph.ip, ph.mac, ts=now - 20)
    slate.syslog(line)
    r, tid = slate.run_page(ph, name=f"a65-{fmt}", timeoutMs=120000)
    full = slate.final(tid)
    ident = slate.ev(full, "identity")
    d = ident["data"]
    assert d["resolved_by"] == "dhcp" and d["mac"] == ph.mac and d["ip"] == ph.ip, d
    assert d["device_key"] == st.device_key(slate.expk, ph.mac)
    assert d["zone"] == "hall-b" and d["zone_source"] == "subnet", "subnet -> zone"
    assert d["nat_suspected"] is False
    assert full["test"]["zone"] == "hall-b" and full["test"]["zone_source"] in ("subnet", "dhcp")
    assert not any(e["kind"] == "wifi" and e["status"] == "ok" for e in full["evidence"]), "Mist was down: no wifi evidence"
    assert any(str(x).startswith("syslog:dhcp:") for x in (ident.get("raw_refs") or [])), ident.get("raw_refs")
    all_legs_present(full)


def test_a65_unresolved_still_produces_a_result(slate: M.Core):
    # (1) Mist is configured but knows nobody with this IP: the guard fails closed (no_match), the test is NOT bound to a device
    ph = slate.new_client("i-none")
    slate.identify(ph, "no_client")
    r, tid = slate.run_page(ph, name="a65-nomatch", timeoutMs=120000)
    full = slate.final(tid)
    d = slate.ev(full, "identity")["data"]
    assert d["resolved_by"] == "none" and d["zone"] == "unresolved" and d["nat_suspected"] is True and d["nat_reason"] == "no_match", d
    assert "mac" not in d and "device_key" not in d
    assert full["test"]["zone"] == "unresolved" and "nat_suspected" in full["test"]["flags"], full["test"]
    all_legs_present(full)
    assert slate.ev(full, "baseline")["status"] in ("ok", "partial"), "an unresolved test still gets the probe baseline"
    assert slate.ev(full, "wan")["status"] in ("ok", "partial") and slate.ev(full, "security")["status"] in ("ok", "partial")
    # (2) no connector at all, no subnet table, no QR hint: unresolved, but a complete result
    def drop(cfg: dict) -> None:
        cfg["correlation"]["sources"].pop("mist", None)
        cfg["correlation"]["network"]["zone_subnets"] = []
    slate.reconfigure("runner", drop)
    slate.reconfigure("speedtest", lambda c: c["zone_labels"].update({"subnets": []}))
    try:
        ph2 = slate.new_client("i-nocon")
        r2 = ph2.chromium({"name": "a65-noconn", "url": f"{slate.page}/", "timeoutMs": 120000})
        tid2 = r2["submissions"][-1]["res"]["id"]
        full2 = slate.final(tid2)
        d2 = slate.ev(full2, "identity")["data"]
        assert d2["resolved_by"] == "none" and d2["zone"] == "unresolved" and d2["zone_source"] == "unresolved", d2
        assert d2.get("nat_suspected") is False, "no connector is not a NAT suspicion"
        assert full2["test"]["zone"] == "unresolved"
        all_legs_present(full2)
    finally:
        slate.reset_config("runner")
        slate.reset_config("speedtest")
