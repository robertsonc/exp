"""Identity resolution: NAT guard (A6.12), Mist ambiguity, DHCP fallback, subnet zones, device_key."""
from __future__ import annotations

import pytest
from exp_common import speedtest as st_helpers
from rthelpers import base_config, make_cfg, secret

from exp_runner import evidence as ev
from exp_runner.config import parse_config
from exp_runner.connectors import ClientCandidate, ClientLookup, IdentityProvider, SpeedtestRef, Window
from exp_runner.identity import IdentityResolver, nat_guard, subnet_zone
from exp_runner.ring import Ring
from exp_runner.syslog_parse import parse_line

NOW = 1_795_000_000.0
MAC = "f0:18:98:aa:bb:01"


def mkref(ip="10.60.14.77", zone_hint=None, zone="unresolved", zone_source="unresolved"):
    w = Window(NOW - 300, NOW + 120, ev._fmt(NOW - 300), ev._fmt(NOW + 120))
    return SpeedtestRef("st_01M7R3X9G0RBGD0H1DC76AJK35", "hall-b", NOW, NOW + 20, ip, w, zone_hint, zone, zone_source), w


class FakeProvider(IdentityProvider):
    def __init__(self, status="ok", candidates=None, raises=False):
        self.status, self.candidates, self.raises, self.calls = status, candidates or [], raises, 0

    def lookup_client(self, ip, window, budget):
        self.calls += 1
        if self.raises:
            raise RuntimeError("boom with secret-token-123")
        return ClientLookup(self.status, list(self.candidates))


@pytest.fixture()
def ring(tmp_path):
    r = Ring(tmp_path / "s.db").open()
    yield r
    r.close()


def dhcp(ring, ip, mac, host="alices-iphone", at=NOW - 100, event="DHCPACK"):
    if event == "DHCPACK":
        line = f"DHCPACK on {ip} to {mac} ({host}) via eth1"
    else:
        line = f"DHCPRELEASE of {ip} from {mac} ({host}) via eth1 (found)"
    p = parse_line(line, at)
    ring.insert_many([(p, "10.0.0.1", at)])


def resolver(ring, provider=None, cfg=None):
    return IdentityResolver(cfg or make_cfg(mist=True), ring, secret(), provider)


# ------------------------------------------------------------------------------------------ NAT guard
def test_translated_address_fails_closed_without_any_lookup(ring):
    prov = FakeProvider(candidates=[ClientCandidate(mac=MAC)])
    t, w = mkref(ip="10.0.0.2", zone_hint="hall-a", zone="hall-a", zone_source="qr")
    dhcp(ring, "10.0.0.2", MAC)
    i = resolver(ring, prov).resolve(t, w)
    assert (i.zone, i.zone_source, i.nat_suspected, i.nat_reason, i.resolved_by) == ("unresolved", "unresolved", True, "translated_address", "none")
    assert i.mac is None and i.device_key is None and prov.calls == 0
    assert i.evidence_status() == "partial"
    d = i.evidence_data()
    assert d["nat_suspected"] is True and "mac" not in d
    assert not ev.validation_errors(ev.envelope(t.id, "identity", "exp", i.evidence_status(), d, w.as_dict(), NOW))


def test_ip_outside_every_attendee_subnet_fails_closed(ring):
    t, w = mkref(ip="192.168.55.9")
    i = resolver(ring, FakeProvider(candidates=[ClientCandidate(mac=MAC)])).resolve(t, w)
    assert i.nat_suspected and i.nat_reason == "outside_subnets" and i.zone == "unresolved" and i.mac is None


def test_outside_subnets_only_when_real_ip_is_required(ring):
    doc = base_config()
    doc["correlation"]["network"]["require_real_client_ip"] = False
    cfg = parse_config(doc)
    t, w = mkref(ip="192.168.55.9")
    i = resolver(ring, cfg=cfg).resolve(t, w)
    assert not i.nat_suspected


def test_no_configured_subnets_means_guard_one_is_not_evaluable(ring):
    doc = base_config()
    doc["correlation"]["network"]["client_subnets"] = []
    t, w = mkref(ip="172.16.1.1")
    i = resolver(ring, cfg=parse_config(doc)).resolve(t, w)
    assert not i.nat_suspected
    assert nat_guard(parse_config(doc).network, "10.0.0.2") == "translated_address"


@pytest.mark.parametrize("count,reason", [(2, "ambiguous"), (5, "ambiguous"), (0, "no_match")])
def test_mist_zero_or_many_macs_fail_closed(ring, count, reason):
    cands = [ClientCandidate(mac=f"f0:18:98:aa:bb:{i:02x}") for i in range(count)]
    dhcp(ring, "10.60.14.77", MAC)                       # a DHCP binding must NOT rescue an ambiguous Mist answer
    t, w = mkref()
    i = resolver(ring, FakeProvider(candidates=cands)).resolve(t, w)
    assert i.nat_suspected and i.nat_reason == reason and i.candidates == count
    assert i.zone == "unresolved" and i.mac is None and i.device_key is None and i.username is None


def test_mist_single_client_binds_with_device_key_and_zone_map(ring):
    cand = ClientCandidate(mac="F0-18-98-AA-BB-01", hostname="alices-iphone", username="net-user", manufacture="Apple", os_family="iOS",
                           wired=False, ap_mac="5c:5b:35:00:01:a0", ap_name="lobby-ap-1", ssid="Summit", band="5", ref="mist:client:1")
    t, w = mkref()
    i = resolver(ring, FakeProvider(candidates=[cand])).resolve(t, w)
    assert i.resolved_by == "mist" and i.source == "mist" and i.mac == MAC and i.candidates == 1 and not i.nat_suspected
    assert i.device_key == st_helpers.device_key(secret(), MAC) and len(i.device_key) == 64
    assert (i.zone, i.zone_source) == ("hall-a", "mist")         # the ap_macs entry of the fixture zone_map
    assert i.evidence_status() == "ok" and i.raw_refs == ["mist:client:1"]
    assert not ev.validation_errors(ev.envelope(t.id, "identity", "mist", "ok", i.evidence_data(), w.as_dict(), NOW, i.raw_refs))
    # name prefix mapping
    cand2 = ClientCandidate(mac=MAC, ap_mac="aa:bb:cc:00:00:01", ap_name="hallb-ap-3")
    i2 = resolver(ring, FakeProvider(candidates=[cand2])).resolve(t, w)
    assert (i2.zone, i2.zone_source) == ("hall-b", "mist")
    # no zone_map hit: coarse subnet zone, source subnet
    i3 = resolver(ring, FakeProvider(candidates=[ClientCandidate(mac=MAC, ap_name="other")])).resolve(*mkref())
    assert i3.zone_source in ("subnet", "mist") and i3.zone != "unresolved"


def test_where_item_never_carries_mac_or_username(ring):
    cand = ClientCandidate(mac=MAC, username="alice", hostname="h", ap_name="hallb-ap-3", ssid="S", band="5")
    i = resolver(ring, FakeProvider(candidates=[cand])).resolve(*mkref())
    w = i.where_item()
    assert set(w) <= {"ip", "zone", "zone_source", "ap_name", "ssid", "band", "nat_suspected", "ttl_s"}
    assert "alice" not in str(w) and MAC not in str(w)


@pytest.mark.parametrize("status", ["unavailable", "error"])
def test_mist_unavailable_or_error_falls_back_to_dhcp(ring, status):
    dhcp(ring, "10.60.14.77", MAC)
    i = resolver(ring, FakeProvider(status=status)).resolve(*mkref())
    assert i.resolved_by == "dhcp" and i.mac == MAC and not i.nat_suspected and i.mist_status == status


def test_provider_exception_is_contained_and_not_logged_with_details(ring, caplog):
    caplog.set_level("DEBUG")
    dhcp(ring, "10.60.14.77", MAC)
    i = resolver(ring, FakeProvider(raises=True)).resolve(*mkref())
    assert i.resolved_by == "dhcp" and i.mist_status == "error"
    assert "secret-token-123" not in caplog.text


# ------------------------------------------------------------------------------- DHCP fallback
def test_dhcp_fallback_binds_mac_and_coarse_zone(ring):
    dhcp(ring, "10.60.14.77", MAC)
    i = resolver(ring).resolve(*mkref())
    assert (i.resolved_by, i.source, i.zone, i.zone_source) == ("dhcp", "syslog", "hallb-row12", "subnet")   # longest prefix
    assert i.mac == MAC and i.hostname == "alices-iphone" and i.device_key == st_helpers.device_key(secret(), MAC)
    assert i.evidence_status() == "partial" and i.raw_refs and i.raw_refs[0].startswith("syslog:dhcp:")


def test_dhcp_two_macs_in_the_window_is_ambiguous(ring):
    dhcp(ring, "10.60.14.77", MAC, at=NOW - 200)
    dhcp(ring, "10.60.14.77", "f0:18:98:aa:bb:02", at=NOW - 50)
    i = resolver(ring).resolve(*mkref())
    assert i.nat_suspected and i.nat_reason == "ambiguous" and i.mac is None and i.candidates == 2


def test_dhcp_lease_older_than_the_window_still_counts_but_a_release_does_not(ring):
    dhcp(ring, "10.60.14.77", MAC, at=NOW - 1800)
    assert resolver(ring).resolve(*mkref()).mac == MAC
    dhcp(ring, "10.60.14.77", MAC, at=NOW - 900, event="RELEASE")
    i = resolver(ring).resolve(*mkref())
    assert i.mac is None and i.resolved_by == "subnet"


def test_dhcp_for_another_ip_is_ignored(ring):
    dhcp(ring, "10.60.14.78", MAC)
    assert resolver(ring).resolve(*mkref()).mac is None


def test_no_secret_means_mac_without_device_key(ring):
    dhcp(ring, "10.60.14.77", MAC)
    r = IdentityResolver(make_cfg(), ring, None)
    i = r.resolve(*mkref())
    assert i.mac == MAC and i.device_key is None and "device_key" not in i.evidence_data()


def test_malformed_secret_omits_device_key(ring):
    dhcp(ring, "10.60.14.77", MAC)
    i = IdentityResolver(make_cfg(), ring, "expk_short").resolve(*mkref())
    assert i.mac == MAC and i.device_key is None


# ------------------------------------------------------------------- subnet / QR / unresolved
def test_subnet_only_then_qr_then_unresolved(ring):
    i = resolver(ring).resolve(*mkref())
    assert (i.resolved_by, i.zone, i.zone_source, i.mac) == ("subnet", "hallb-row12", "subnet", None)
    doc = base_config()
    doc["correlation"]["network"]["zone_subnets"] = []
    cfg = parse_config(doc)
    j = resolver(ring, cfg=cfg).resolve(*mkref(zone_hint="hall-a", zone="hall-a", zone_source="qr"))
    assert (j.resolved_by, j.zone, j.zone_source) == ("qr", "hall-a", "qr")
    k = resolver(ring, cfg=cfg).resolve(*mkref())
    assert (k.resolved_by, k.zone, k.zone_source) == ("none", "unresolved", "unresolved")
    assert k.evidence_status() == "unavailable"
    assert not ev.validation_errors(ev.envelope("st_01M7R3X9G0RBGD0H1DC76AJK35", "identity", "exp", "unavailable", k.evidence_data(),
                                                 mkref()[1].as_dict(), NOW))


def test_subnet_zone_longest_prefix():
    net = make_cfg().network
    assert subnet_zone(net, "10.60.14.5") == "hallb-row12" and subnet_zone(net, "10.60.99.1") == "hall-b"
    assert subnet_zone(net, "10.61.0.1") is None and subnet_zone(net, "not-an-ip") is None and subnet_zone(net, "::1") is None


def test_secret_provider_callable_is_reread_per_resolution(ring):
    dhcp(ring, "10.60.14.77", MAC)
    box = {"s": None}
    r = IdentityResolver(make_cfg(), ring, lambda: box["s"])
    assert r.resolve(*mkref()).device_key is None
    box["s"] = secret()
    assert r.resolve(*mkref()).device_key == st_helpers.device_key(secret(), MAC)
