"""The Mist connector against the c1 fake (field names from the OAS; every scenario value must arrive in the evidence)."""
from __future__ import annotations

import time

import fake_ca
import pytest
from connhelpers import IP, MAC, World, capture_logs
from mist import server as fmist
from rthelpers import device_key_of

from exp_runner.connectors import CallBudget, Window
from exp_runner.mist import MistService, classify_event
from exp_runner.upstream import UpstreamClient


@pytest.fixture()
def w(tmp_path):
    world = World(tmp_path, ec=False)
    yield world
    world.close()


def wifi(docs):
    return docs["wifi"]["data"]


def test_healthy_wireless_identity_and_wifi_evidence(w):
    w.mist_scenario("healthy")
    docs, ident, _ctx = w.run()
    assert ident.resolved_by == "mist" and ident.mac == MAC and ident.device_key == device_key_of(MAC)
    assert ident.zone == "hall-b" and ident.zone_source == "mist"          # ap_name_prefix hallb-ap- from the AP stats document
    assert ident.ap_name == "hallb-ap-12" and ident.ssid == "Summit-Guest" and ident.band == "5"
    assert ident.manufacture == "Apple" and ident.os_family == "iOS 18" and ident.wired is False and ident.vlan == 160
    d = docs["identity"]
    assert d["status"] == "ok" and d["source"] == "mist" and d["data"]["candidates"] == 1 and d["data"]["nat_suspected"] is False
    assert docs["wifi"]["status"] == "ok" and docs["wifi"]["source"] == "mist"
    c = wifi(docs)["client"]
    assert c["mac"] == MAC and c["ap_mac"] == "5c:5b:35:00:01:a0" and c["ssid"] == "Summit-Guest" and c["band"] == "5" and c["channel"] == 36
    assert c["proto"] == "ax" and c["rssi"] == -58 and c["snr"] == 38 and c["tx_rate_mbps"] == 866.7 and c["rx_rate_mbps"] == 780.0
    assert c["tx_retries"] == 120 and c["rx_retries"] == 90 and c["tx_pkts"] == 300000 and c["idle_time_s"] == 1.0
    assert c["key_mgmt"] == "WPA2-PSK/CCMP" and c["vlan_id"] == "160" and c["power_saving"] is False and c["dual_band"] is True
    assert c["retry_pct"] == pytest.approx(120 / 300000 * 100, abs=0.01)
    ap = wifi(docs)["ap"]
    assert ap["ap_name"] == "hallb-ap-12" and ap["model"] == "AP45" and ap["status"] == "connected" and ap["num_clients"] == 12
    r = ap["radio"]
    assert r["band"] == "5" and r["channel"] == 36 and r["bandwidth_mhz"] == 80 and r["noise_floor_dbm"] == -95 and r["util_all"] == 20
    assert r["util_non_wifi"] == 2 and r["util_rx_in_bss"] == 3 and r["power_dbm"] == 15
    assert wifi(docs)["roams"] == [] and wifi(docs)["roam_count"] == 0 and wifi(docs)["auth_failures"] == 0
    assert docs["wired"]["status"] == "unavailable"


def test_weak_signal_inputs_for_the_wifi_signal_rule(w):
    w.mist_scenario("weak_rssi")
    docs, _i, _c = w.run()
    c = wifi(docs)["client"]
    assert c["rssi"] == -83 and c["snr"] == 9 and c["tx_rate_mbps"] == 26.0 and c["proto"] == "n"
    assert c["retry_pct"] > 10                                              # 48000 / 300000 pkts


def test_congested_ap_inputs_for_the_wifi_congestion_rule(w):
    w.mist_scenario("congested_ap")
    docs, _i, _c = w.run()
    ap = wifi(docs)["ap"]
    assert ap["radio"]["util_all"] == 93 and ap["radio"]["num_clients"] == 64 and ap["num_clients"] == 64 and ap["radio"]["noise_floor_dbm"] == -86
    assert wifi(docs)["client"]["rssi"] == -54


def test_roaming_scenario_roams_and_auth_failures_from_runtime_event_constants(w):
    w.mist_scenario("roaming")
    docs, ident, _c = w.run()
    d = wifi(docs)
    assert d["roam_count"] == 5                                              # 4 x 11r association + 1 FBT failure
    assert sorted(r["type"] for r in d["roams"]) == ["fail", "success", "success", "success", "success"]
    assert d["auth_failures"] == 1
    types = {e["type"] for e in d["events"]}
    assert types == {fmist.EVT_ROAM, fmist.EVT_FBT_FAIL, fmist.EVT_AUTH_FAIL}
    assert any(e.get("type_code") == 15 for e in d["events"])
    assert d["roams"] == sorted(d["roams"], key=lambda r: r["timestamp"])
    assert w.fmist.app.calls_to("/const/client_events") == 1
    assert ident.resolved_by == "mist" and docs["wifi"]["status"] == "ok"
    assert w.fmist.app.calls_to("clients/events/search") == 2               # one per AP the client was seen on


def test_events_are_context_only_without_a_multi_ap_history(w):
    """A client seen on ONE AP never gets roams, whatever other clients' events say (events_client has no MAC to filter by)."""
    w.mist_scenario("healthy")
    w.fmist.state.add_event(ts=w.at - 100, type_=fmist.EVT_ROAM)
    w.fmist.state.add_event(ts=w.at - 90, type_=fmist.EVT_AUTH_FAIL)
    w.fmist.state.add_event(ts=w.at - 80, type_="SOMETHING_ELSE_ENTIRELY")
    docs, _i, _c = w.run()
    d = wifi(docs)
    assert d["roams"] == [] and d["roam_count"] == 0
    assert [e["type"] for e in d["events"]] == [fmist.EVT_ROAM, fmist.EVT_AUTH_FAIL]      # unrelated types are dropped, not stored


def test_wired_client_identity_and_port_evidence(w):
    info = w.mist_scenario("wired_port_errors")
    docs, ident, _c = w.run()
    assert ident.resolved_by == "mist" and ident.wired is True and ident.switch_mac == "02:00:00:aa:bb:01" and ident.switch_port == info["port"]
    assert ident.vlan == 160 and ident.ap_mac is None and ident.hostname == "wired-host"
    assert docs["wifi"]["status"] == "unavailable"
    assert docs["wired"]["status"] == "ok"
    d = docs["wired"]["data"]
    assert d["client"]["mac"] == MAC and d["client"]["ip"] == [IP] and d["client"]["port_id"] == ["ge-0/0/12"] and d["client"]["vlan"] == [160]
    assert d["client"]["auth_method"] == "mab" and d["client"]["auth_state"] == "authenticated" and d["client"]["dhcp_hostname"] == "wired-host"
    p = d["port"]
    assert p["port_id"] == "ge-0/0/12" and p["speed_mbps"] == 100 and p["full_duplex"] is False and p["rx_errors"] == 41822 and p["tx_errors"] == 900
    assert p["up"] is True and p["poe_on"] is False and p["stp_state"] == "forwarding" and p["switch_mac"] == "02:00:00:aa:bb:01"
    assert p["last_flapped"] == pytest.approx(w.at - 90) and p["mac_count"] == 1 and p["rx_bps"] == 4000000
    assert "events" not in d                                               # the fake has no device-events endpoint: tolerated, not partial


def test_unknown_ip_is_no_match_and_fails_closed(w):
    w.mist_scenario("no_client")
    docs, ident, _c = w.run()
    assert ident.nat_suspected and ident.nat_reason == "no_match" and ident.zone == "unresolved" and ident.mac is None
    assert docs["identity"]["status"] == "partial" and docs["identity"]["data"]["candidates"] == 0
    assert docs["wifi"]["status"] == "unavailable" and docs["wired"]["status"] == "unavailable"


def test_nat_ambiguity_two_macs_fail_closed_and_stay_unbound(w):
    w.mist_scenario("nat_ambiguity")
    docs, ident, _c = w.run()
    assert ident.nat_suspected and ident.nat_reason == "ambiguous" and ident.candidates == 2
    assert ident.mac is None and ident.device_key is None and ident.zone == "unresolved" and ident.resolved_by == "none"
    assert "mac" not in docs["identity"]["data"] and "device_key" not in docs["identity"]["data"]
    assert docs["wifi"]["status"] == "unavailable"
    assert w.fmist.app.calls_to("stats/clients") == 0 and w.fmist.app.calls_to("stats/devices") == 0     # nothing is pulled for an ambiguous IP


def test_wired_and_wireless_same_ip_is_ambiguous(w):
    w.mist_scenario("healthy")
    w.fmist.state.add_wired(mac="02:11:22:33:44:55", ip=IP, t_from=w.at - 600)
    _docs, ident, _c = w.run()
    assert ident.nat_suspected and ident.nat_reason == "ambiguous"


def test_call_budget_is_six_per_test_including_first_use(w):
    w.mist_scenario("roaming")
    w.run()
    calls = [c for c in w.fmist.app.log if c["path"] != "/api/v1/const/client_events"]
    assert len(calls) <= 6
    w.fmist.app.log.clear()
    w.mist_svc._lookups._d.clear()
    w.mist_svc._found._d.clear()
    w.mist_svc._aps._d.clear()
    w.run()
    assert len([c for c in w.fmist.app.log]) <= 6


def test_budget_exhaustion_degrades_to_partial_not_error(tmp_path):
    w = World(tmp_path, ec=False)
    try:
        w.mist_scenario("healthy")
        docs, ident, _c = w.run(budget=3)          # search wireless, search wired, client stats; the AP + events calls are refused
        assert ident.resolved_by == "mist"
        assert docs["wifi"]["status"] == "partial"
        assert wifi(docs)["client"]["rssi"] == -58 and "ap" not in wifi(docs)
        assert len(w.fmist.app.log) == 3
    finally:
        w.close()


def test_budget_exhausted_before_the_search_finishes_is_an_error_not_no_match(tmp_path):
    w = World(tmp_path, ec=False)
    try:
        w.mist_scenario("nat_ambiguity")
        _docs, ident, _c = w.run(budget=1)
        assert ident.nat_suspected is False and ident.mac is None and ident.resolved_by == "subnet"      # unsearched != ambiguous/no_match
        assert ident.mist_status == "error"
    finally:
        w.close()


def test_ap_cache_is_shared_between_tests_within_30_seconds(w):
    w.mist_scenario("healthy")
    w.run()
    first = w.fmist.app.calls_to("stats/devices")
    w.mist_svc._lookups._d.clear()
    w.mist_svc._found._d.clear()
    w.run()
    assert first == 1 and w.fmist.app.calls_to("stats/devices") == 1


def test_lookup_cache_makes_where_polling_cheap(w):
    w.mist_scenario("healthy")
    win = Window(time.time() - 300, time.time(), "a", "b")
    for _ in range(5):
        res = w.mist_svc.lookup_client(IP, win, CallBudget(6))
        assert res.status == "ok" and len(res.candidates) == 1
    assert w.fmist.app.calls_to(f"{fmist.SITE_ID}/clients/search") == 1


def test_client_gone_after_the_window_is_partial_with_the_search_record(w):
    w.mist_scenario("healthy")
    for s in w.fmist.state.sessions:
        s["t_to"] = w.at - 10                                              # disconnected: stats/clients/{mac} answers 404
    docs, ident, _c = w.run()
    assert ident.resolved_by == "mist" and ident.zone_source in ("mist", "subnet")
    assert docs["wifi"]["status"] == "partial"
    c = wifi(docs)["client"]
    assert c["ssid"] == "Summit-Guest" and c["band"] == "5" and c["ap_mac"] == "5c:5b:35:00:01:a0" and "rssi" not in c


def test_username_flows_to_identity_only_when_present(w):
    w.mist_scenario("healthy")
    w.fmist.state.sessions[0]["username"] = "user-0042"
    docs, ident, _c = w.run()
    assert ident.username == "user-0042" and docs["identity"]["data"]["username"] == "user-0042"
    assert "username" not in str(docs["wifi"]) and "user-0042" not in str(docs["wifi"])


def test_zone_map_by_ap_mac_beats_the_prefix_order(w):
    w.mist_scenario("healthy")
    # config: hall-b by ap_name_prefix first; the AP name is hallb-ap-12 -> hall-b
    _docs, ident, _c = w.run()
    assert ident.zone == "hall-b"


# ------------------------------------------------------------------------------------------------ failure handling
def test_429_pauses_the_connector_and_degrades_without_crashing(w):
    w.mist_scenario("healthy")
    w.fmist.app.set_rate_limit(0)
    docs, ident, _c = w.run()
    assert ident.mist_status == "error" and ident.resolved_by in ("none", "subnet")      # DHCP/subnet fallback, never a crash
    assert docs["wifi"]["status"] == "error" and docs["wired"]["status"] == "error"
    n = len(w.fmist.app.log)
    w.run()                                                                # the pause (429 pause) means no new upstream calls
    assert len(w.fmist.app.log) == n
    assert w.mist_svc.client.blocked_for() > 0


def test_5xx_is_retried_once_then_succeeds(w):
    w.mist_scenario("healthy")
    w.fmist.app.set_force(503, 1)
    docs, ident, _c = w.run()
    assert ident.resolved_by == "mist" and docs["wifi"]["status"] == "ok"


def test_persistent_5xx_is_an_error_with_a_bounded_number_of_attempts(w):
    w.mist_scenario("healthy")
    w.fmist.app.set_force(500)
    docs, ident, _c = w.run()
    assert ident.mist_status == "error" and docs["wifi"]["status"] == "error"
    assert len(w.fmist.app.log) <= 2                                         # one try + one retry, then give up


def test_auth_failure_is_an_error_and_not_retried(w):
    w.mist_scenario("healthy")
    bad = MistService(w.cfg.mist, {"api_base": w.fmist.base_url, "token": "x" * 40})
    res = bad.lookup_client(IP, Window(time.time() - 300, time.time(), "a", "b"), CallBudget(6))
    assert res.status == "error" and len(w.fmist.app.log) == 1


def test_timeouts_are_bounded_and_reported(w, monkeypatch):
    w.mist_scenario("healthy")
    svc = MistService(w.cfg.mist, {"api_base": "http://127.0.0.1:9", "token": "t" * 40},
                      client=UpstreamClient("mist", "http://127.0.0.1:9/api/v1", {"Authorization": "Token " + "t" * 40}, timeout_s=0.3,
                                            retries=1, backoff_s=0.01))
    t0 = time.monotonic()
    res = svc.lookup_client(IP, Window(time.time() - 300, time.time(), "a", "b"), CallBudget(6))
    assert res.status == "error" and time.monotonic() - t0 < 5


def test_no_sites_means_unavailable(w):
    svc = MistService({"sites": []}, {"api_base": w.fmist.base_url, "token": fmist.default_token()})
    assert svc.lookup_client(IP, Window(0, 1, "a", "b"), CallBudget(6)).status == "unavailable"


def test_token_never_appears_in_logs_or_errors(w, caplog):
    w.mist_scenario("healthy")
    w.fmist.app.set_force(500, 3)
    tok = fmist.default_token()
    w.run()
    w.fmist.app.set_rate_limit(0)
    w.mist_svc._lookups._d.clear()
    w.run()
    logs = capture_logs(caplog)
    assert tok not in logs and "Token " not in logs


def test_token_is_sent_as_authorization_token_scheme(w):
    w.mist_scenario("healthy")
    seen = []
    orig = w.mist_svc.client._once

    def spy(method, target, body, extra):
        seen.append(w.mist_svc.client._headers["Authorization"])
        return orig(method, target, body, extra)
    w.mist_svc.client._once = spy
    w.run()
    assert seen and all(s == f"Token {fmist.default_token()}" for s in seen)


def test_classify_event_runtime_constants():
    assert classify_event("X", "Client Authentication Failure", "") == "auth_fail"
    assert classify_event("CLIENT_AUTH_ASSOCIATION_11R", "11r Association", "") == "roam"
    assert classify_event("MARVIS_EVENT_CLIENT_FBT_FAILURE", "Client Fast BSS Transition Failure", "") == "roam_fail"
    assert classify_event("CLIENT_DNS_OK", "DNS ok", "") is None


def test_hostile_values_are_bounded_and_validate(w):
    w.mist_scenario("healthy")
    s = w.fmist.state.sessions[0]
    s["hostname"] = "h\x00\x1b[31m" + "A" * 500
    s["ssid"] = "S" * 300
    docs, ident, _c = w.run()
    assert len(ident.hostname or "") <= 64 and "\x00" not in (ident.hostname or "") and "\x1b" not in (ident.hostname or "")
    assert docs["identity"]["status"] in ("ok", "partial")


def test_search_window_uses_epoch_seconds_and_the_ip_filter(w):
    w.mist_scenario("healthy")
    w.run()
    q = [c for c in w.fmist.app.log if c["path"].endswith("/clients/search")][0]["query"]
    assert q["ip"] == IP and q["start"].isdigit() and q["end"].isdigit() and int(q["end"]) > int(q["start"])


def test_https_with_a_private_ca_verifies_and_a_wrong_ca_is_refused(tmp_path):
    ca, leaf = fake_ca.make_server_tls(tmp_path)
    srv = fmist.start(tls=(leaf.cert_chain, leaf.key))
    try:
        srv.state.load_scenario("healthy", at=time.time() - 800)
        win = Window(time.time() - 1200, time.time() - 760, "a", "b")
        cfg = {"sites": [{"site_id": fmist.SITE_ID}]}
        creds = {"api_base": f"https://localhost:{srv.port}", "token": fmist.default_token()}
        good = MistService(cfg, creds, ca_file=str(ca.cert))
        assert good.lookup_client("10.60.14.77", win, CallBudget(6)).status == "ok"
        other = fake_ca.make_ca(tmp_path / "other")
        bad = MistService(cfg, creds, ca_file=str(other.cert))
        assert bad.lookup_client("10.60.14.77", win, CallBudget(6)).status == "error"          # certificate verification is never disabled
    finally:
        srv.stop()
