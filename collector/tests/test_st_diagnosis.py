"""12 section 5.3: one test per cause, with evidence in the shapes of the c0 fixtures / c1 fakes scenarios, run through
the collector end to end (ingest -> evidence -> complete -> final diagnosis), plus tunables, ordering and text rules."""
from __future__ import annotations

import time

from colhelpers import check_schema_file
from exp_common import speedtest as st_helpers
from sthelpers import evidence, fixture, healthy_result, iso_to_s, result, wifi

from exp_collector.speedtest import diagnosis as dx
from exp_collector.speedtest.settings import Thresholds


def causes(out):
    return [c["id"] for c in out["diagnosis"]["cause"]]


def check_text(diag):
    assert 0 < len(diag["user_text"]) <= 280 and len(diag["noc_text"]) <= 600
    assert not any(ord(ch) < 32 for ch in diag["user_text"] + diag["noc_text"])


def at(t, delta):
    return iso_to_s(t["ended"]) + delta


# ----------------------------------------------------------------------------------------------- the causes
def test_wifi_signal(st):
    t = result(down=15.0)
    out = st.run(t, [wifi(t, rssi=-80, snr=14, util=30, clients=20), evidence("identity", t)])
    d = out["diagnosis"]
    assert causes(out)[0] == "wifi_signal" and d["stage"] == "final"
    assert d["cause"][0]["confidence"] >= 0.8
    assert "RSSI -80 dBm" in d["noc_text"] and "hallb-ap-12 ch 44/80 MHz" in d["noc_text"]
    assert {"kind": "wifi", "ref": "data.client.rssi"} in d["cause"][0]["cites"]
    assert "Wi-Fi signal is weak" in d["user_text"]
    check_text(d)


def test_wifi_signal_needs_a_slow_local_leg(st):
    t = result(down=420.0, up=300.0)                                  # weak signal but the leg is fine
    out = st.run(t, [wifi(t, rssi=-80, snr=14, util=30, clients=20)])
    assert "wifi_signal" not in causes(out)


def test_wifi_congestion_names_the_evidence(st):
    t = result(down=150.0)
    out = st.run(t, [wifi(t), evidence("identity", t)])               # the c0 wifi.ok: util 81, 74 clients, RSSI -61
    d = out["diagnosis"]
    assert causes(out)[0] == "wifi_congestion"
    assert "hallb-ap-12 ch 44/80 MHz, util 81 %, 74 clients; RSSI -61 dBm" in d["noc_text"]
    assert "very busy" in d["user_text"]


def test_wifi_congestion_by_client_count_alone(st):
    t = result(down=150.0)
    out = st.run(t, [wifi(t, util=40, clients=75)])
    assert causes(out)[0] == "wifi_congestion"


def test_wifi_roaming_by_roams_and_by_auth_failure(st):
    t = result(down=300.0, up=200.0)                                   # leg is fine: only the roams explain it
    roams = [{"timestamp": at(t, -20 + i), "type": "success", "ap_mac": "5c:5b:35:00:01:a0"} for i in range(3)]
    out = st.run(t, [wifi(t, rssi=-55, util=30, clients=10, roams=roams)])
    assert causes(out)[0] == "wifi_roaming"
    assert "3 roams" in out["diagnosis"]["noc_text"]
    t2 = result(down=300.0, up=200.0)
    ev = [{"timestamp": at(t2, -10), "type": "FAKE_CLIENT_AUTH_FAILURE", "text": "auth failure"}]
    out2 = st.run(t2, [wifi(t2, rssi=-55, util=30, clients=10, events=ev, auth_failures=1)])
    assert causes(out2)[0] == "wifi_roaming" and "auth failure" in out2["diagnosis"]["noc_text"]
    t3 = result(down=300.0, up=200.0)                                  # one roam, no auth failure: not roaming
    one = [{"timestamp": at(t3, -10), "type": "success"}]
    assert "wifi_roaming" not in causes(st.run(t3, [wifi(t3, rssi=-55, util=30, clients=10, roams=one)]))


def test_wifi_roaming_ignores_roams_outside_the_window(st):
    t = result(down=300.0, up=200.0)
    old = [{"timestamp": at(t, -3600 - i), "type": "success"} for i in range(4)]
    assert "wifi_roaming" not in causes(st.run(t, [wifi(t, rssi=-55, util=30, clients=10, roams=old)]))


def test_wired_port(st):
    t = result(down=30.0, up=20.0)
    ident = evidence("identity", t, wired=True)
    out = st.run(t, [evidence("wired", t), ident])                     # 100 Mb/s, half duplex, 1450 rx errors
    d = out["diagnosis"]
    assert causes(out)[0] == "wired_port" and d["cause"][0]["confidence"] >= 0.9
    assert "ge-0/0/12" in d["noc_text"] and "half duplex" in d["noc_text"] and "100 Mb/s" in d["noc_text"]
    assert "wired network port" in d["user_text"]


def test_wired_port_healthy_port_is_not_blamed(st):
    t = result(down=30.0, up=20.0)
    good = evidence("wired", t, port={"port_id": "ge-0/0/12", "up": True, "speed_mbps": 1000, "full_duplex": True,
                                      "rx_errors": 0, "tx_errors": 0})
    out = st.run(t, [good, evidence("identity", t, wired=True)])
    assert "wired_port" not in causes(out)


def test_device_limit(st):
    t = result(down=60.0, up=20.0)                                     # slow vs 5/80 expectation, signal is fine
    w = wifi(t, rssi=-52, snr=40, util=30, clients=10, proto="n", power_saving=True, tx_rate=72.0)
    out = st.run(t, [w])
    d = out["diagnosis"]
    assert causes(out)[0] == "device_limit"
    assert "power save on" in d["noc_text"] and "proto n" in d["noc_text"]
    assert "wifi_signal" not in causes(out) and "wifi_congestion" not in causes(out)
    assert "device" in d["user_text"]


def test_wan_saturation(st):
    t = result(down=400.0, up=300.0, i_down=10.0, i_up=4.0)
    out = st.run(t, [evidence("wan", t)])                              # EC WAN at 92.5 %
    d = out["diagnosis"]
    assert causes(out)[0] == "wan_saturation" and "internet_path" not in causes(out)
    assert "WAN util 92.5 %" in d["noc_text"]
    assert "internet link is very busy" in d["user_text"]


def test_wan_saturation_by_health_alone_and_not_when_local_is_slow(st):
    t = result(down=400.0, up=300.0, i_down=10.0, i_up=4.0)
    w = evidence("wan", t)
    w["data"]["wan_util_pct"] = 40.0
    w["data"]["appliances"][0]["interfaces"][0]["util_pct"] = 40.0
    w["data"]["appliances"][0]["health"]["loss"][0]["health_status"] = "CRITICAL"
    out = st.run(t, [w])
    assert causes(out)[0] == "wan_saturation" and "loss" in out["diagnosis"]["noc_text"]
    t2 = result(down=10.0, up=5.0)                                      # local slow too: the WAN is not the story
    assert "wan_saturation" not in causes(st.run(t2, [evidence("wan", t2)]))


def test_internet_path_quick_and_final(st):
    t = result(down=400.0, up=300.0, i_down=8.0, i_up=3.0)
    r = st.ingest(t)
    quick = r.json()["diagnosis"]
    assert quick["stage"] == "quick" and quick["cause"][0]["id"] == "internet_path"
    assert quick["cause"][0]["confidence"] <= 0.5
    calm = evidence("wan", t)
    calm["data"]["wan_util_pct"] = 30.0
    calm["data"]["appliances"][0]["interfaces"][0]["util_pct"] = 30.0
    st.put_ev(calm)
    st.complete(t["id"], ["wan"])
    final = st.get(f"/{t['id']}").json()["diagnosis"]
    assert final["stage"] == "final" and final["cause"][0]["id"] == "internet_path"
    assert final["cause"][0]["confidence"] > quick["cause"][0]["confidence"]
    assert "route to the internet" in final["user_text"] and "WAN not saturated" in final["noc_text"]


def test_internet_path_when_the_internet_leg_could_not_run(st):
    t = result(down=400.0, up=300.0, i_down=None, flags=["internet_unavailable"])
    quick = st.ingest(t).json()["diagnosis"]
    assert quick["cause"][0]["id"] == "internet_path"


def test_internet_down_is_not_healthy(st):
    """Regression (M6 e1, A6.7): with the internet leg unavailable the score rests on the fast on-network leg alone and is
    high; the diagnosis used to short-circuit to `none` ("looks healthy"). It must say the internet could not be reached."""
    t = result(down=800.0, up=700.0, loaded=15.0, i_down=None, cv=0.0, flags=["internet_unavailable"])
    assert t["score"]["total"] >= 80, t["score"]
    quick = st.ingest(t).json()["diagnosis"]
    assert quick["cause"][0]["id"] == "internet_path" and "internet could not be reached" in quick["user_text"], quick
    out = st.run(result(down=800.0, up=700.0, loaded=15.0, i_down=None, cv=0.0, flags=["internet_unavailable"]), [])
    d = out["diagnosis"]
    assert d["stage"] == "final" and causes(out)[0] == "internet_path"
    assert "could not be reached" in d["user_text"] and "unavailable" in d["noc_text"]
    check_text(d)
    ok = result(down=800.0, up=700.0, loaded=15.0, i_down=400.0, i_up=200.0, i_loaded=20.0, cv=0.0)   # control: a working internet leg
    assert causes(st.run(ok, [])) == ["none"]


def test_policy_block(st):
    t = result(down=300.0, up=200.0, i_down=40.0, i_up=20.0, i_loaded=300.0)
    out = st.run(t, [evidence("security", t)])
    d = out["diagnosis"]
    assert causes(out)[0] == "policy_block" and d["cause"][0]["confidence"] >= 0.85
    assert "31 deny/block" not in d["noc_text"] and "32 deny/block" in d["noc_text"]    # 31 deny + 1 block
    assert "guest-to-internet-deny-rtc" in d["noc_text"]
    assert "blocked by network policy" in d["user_text"]


def test_policy_block_from_ec_flow_drops(st):
    t = result(down=300.0, up=200.0, i_down=40.0, i_up=20.0, i_loaded=300.0)
    fl = evidence("flows", t)
    out = st.run(t, [fl])                                              # the c0 flows.ok has one firewall-dropped flow
    assert causes(out)[0] == "policy_block" and "EC firewall" in out["diagnosis"]["noc_text"]


def test_qos_shaping(st):
    t = result(down=300.0, up=200.0, i_down=12.0, i_up=4.0)
    fl = evidence("flows", t)
    fl["data"]["counts"]["flows_firewall_dropped"] = 0
    for f in fl["data"]["flows"]:
        f["firewall_dropped"] = 0
    fl["data"]["flows"][0].update(traffic_class=7, slow_duration=40, app_type="Bulk_Data_transfer")
    out = st.run(t, [fl])
    d = out["diagnosis"]
    assert causes(out)[0] == "qos_shaping" and "traffic class 7" in d["noc_text"] and "rate-limited" in d["user_text"]
    fl2 = evidence("flows", t)                                         # class 5, no firewall drop: nothing to see
    fl2["data"]["counts"]["flows_firewall_dropped"] = 0
    for f in fl2["data"]["flows"]:
        f["firewall_dropped"] = 0
    t2 = result(down=300.0, up=200.0, i_down=12.0, i_up=4.0)
    fl2["test_id"] = t2["id"]
    assert "qos_shaping" not in causes(st.run(t2, [fl2]))


def test_dns_from_resolver_logs_and_from_the_probe_line(st):
    t = result(down=300.0, up=200.0, i_down=12.0, i_up=4.0)
    dn = evidence("dns", t)
    dn["data"].update(failures=2, slow=3, slowest_ms=1800.0)
    out = st.run(t, [dn])
    assert causes(out)[0] == "dns" and "2 failed and 3 slow lookups, slowest 1800 ms" in out["diagnosis"]["noc_text"]
    t2 = result(down=300.0, up=200.0, i_down=12.0, i_up=4.0)
    t2["legs"]["dns"] = {"source": "probe", "cold_ms": None, "warm_ms": None, "resolver_ip": None}
    d2 = evidence("dns", t2)
    d2["data"].update(failures=0, slow=0, probe_dns={"state": "fail", "resolver": "10.0.0.53"})
    d2["data"].pop("slowest_ms")
    out2 = st.run(t2, [d2])
    assert "dns" in causes(out2) and "probe DNS line failing" in out2["diagnosis"]["noc_text"]


def test_dns_from_the_browser_cold_lookup(st):
    t = result(down=300.0, up=200.0, i_down=12.0, i_up=4.0)
    t["legs"]["dns"] = {"source": "browser", "cold_ms": 2400.0, "warm_ms": 3.0, "resolver_ip": "10.0.0.53"}
    quick = st.ingest(t).json()["diagnosis"]
    assert "dns" in [c["id"] for c in quick["cause"]]


def _degraded_probe(sev="fail", lines=None, throughput=None):
    def probe_state(probe, at_ms):
        return {"probe": probe, "newest_s": 4.0, "verdict": {"severity": sev},
                "lines": lines or [{"key": "network", "state": "fail", "detail": "gateway down"},
                                   {"key": "internet", "state": "fail", "detail": ""}]}
    return probe_state


def test_network_wide_uses_the_nearest_probe_at_the_same_time(st):
    st.app.speedtests.probe_state = _degraded_probe()
    t = result(down=30.0, up=20.0)
    quick = st.ingest(t).json()["diagnosis"]
    assert quick["cause"][0]["id"] == "network_wide"                  # legs only + the collector's own probe data
    assert "not just you" in quick["user_text"]
    out = st.get(f"/{t['id']}").json()
    assert out["diagnosis"]["noc_text"].startswith("network_wide")
    b = st.req("GET", f"/baseline?site=hall-b&zone=hallb-row12&at={t['ended']}", st.tokens["expr"])
    assert b.status == 200 and b.json()["severity"] == "fail" and b.json()["distance"] == "same_site"
    assert {ln["key"] for ln in b.json()["lines"]} == {"network", "internet"}


def test_network_wide_not_when_the_probe_is_fine_or_silent(st):
    st.app.speedtests.probe_state = _degraded_probe(sev="ok", lines=[{"key": "network", "state": "ok"}])
    t = result(down=30.0, up=20.0)
    assert "network_wide" not in [c["id"] for c in st.ingest(t).json()["diagnosis"]["cause"]]
    st.app.speedtests.probe_state = lambda p, a: {"probe": p, "newest_s": 900.0, "verdict": {"severity": "fail"}, "lines": []}
    t2 = result(down=30.0, up=20.0)
    assert "network_wide" not in [c["id"] for c in st.ingest(t2).json()["diagnosis"]["cause"]]
    assert st.req("GET", f"/baseline?site=hall-b&at={t2['ended']}", st.tokens["expr"]).status == 404


def test_none_when_the_score_is_good(st):
    t = healthy_result()
    assert t["score"]["total"] >= 80
    quick = st.ingest(t).json()["diagnosis"]
    assert [c["id"] for c in quick["cause"]] == ["none"] and quick["user_text"] == "Your connection looks healthy."
    out = st.run(healthy_result(), [wifi(t, rssi=-85, snr=10)])        # even bad evidence does not turn a good score
    assert causes(out) == ["none"]


def test_no_rule_fires_means_no_invented_cause(st):
    t = result(down=20.0, up=8.0)                                       # slow, nothing in the evidence explains it
    quick = st.ingest(t).json()["diagnosis"]
    assert quick["cause"] == [] and "checking" in quick["user_text"]
    out = st.run(t, [evidence("identity", t)])
    assert out["diagnosis"]["cause"] == [] and "could not pinpoint" in out["diagnosis"]["user_text"]
    assert st.get("").json()["items"][0]["cause"] is None


def test_unavailable_and_error_evidence_is_ignored(st):
    t = result(down=15.0)
    w = wifi(t, rssi=-85, snr=10, util=30, clients=20)
    w["status"] = "unavailable"
    assert causes(st.run(t, [w])) == []
    t2 = result(down=15.0)
    w2 = wifi(t2, rssi=-85, snr=10, util=30, clients=20)
    w2["status"] = "partial"                                            # partial evidence is still usable
    assert causes(st.run(t2, [w2]))[0] == "wifi_signal"


# -------------------------------------------------------------------------------- ordering, tunables, bounds
def test_causes_are_ordered_by_confidence_with_the_documented_tie_order(st):
    t = result(down=15.0, up=5.0)
    sec, dn = evidence("security", t), evidence("dns", t)
    dn["data"].update(failures=3, slow=3)
    out = st.run(t, [wifi(t, rssi=-80, snr=14, util=30, clients=20), sec, dn])
    cs = out["diagnosis"]["cause"]
    confs = [c["confidence"] for c in cs]
    assert confs == sorted(confs, reverse=True) and {"wifi_signal", "policy_block", "dns"} <= {c["id"] for c in cs}
    assert 0 <= min(confs) and max(confs) <= 1
    # equal confidence: the section 5.3 table order decides
    th = Thresholds()
    hits = [dx.Hit("dns", 0.7, "x", []), dx.Hit("wifi_signal", 0.7, "x", [])]
    hits.sort(key=lambda h: (-h.conf, dx._PRIORITY[h.cause]))
    assert [h.cause for h in hits] == ["wifi_signal", "dns"] and th.none_score == 80


def test_diagnosis_is_deterministic():
    base = result(down=15.0)
    ev = {"wifi": wifi(base, rssi=-80, snr=14, util=30, clients=20)}
    args = (base, ev, None, {"down_mbps": 25.0, "up_mbps": 10.0}, Thresholds(), "final", "2026-11-20T00:00:00.000Z")
    a, b = dx.diagnose(*args), dx.diagnose(*args)
    assert a == b and a["cause"][0]["id"] == "wifi_signal"


def test_every_diagnosis_validates_against_the_contract(st):
    t = result(down=15.0)
    out = st.run(t, [wifi(t, rssi=-80, snr=14, util=30, clients=20), evidence("security", t)])
    wrapper = {"$ref": "speedtest.schema.json#/$defs/diagnosis"}
    from colhelpers import REGISTRY
    from jsonschema import Draft202012Validator
    errs = list(Draft202012Validator(wrapper, registry=REGISTRY).iter_errors(out["diagnosis"]))
    assert not errs, errs[:2]
    assert check_schema_file is not None


def test_thresholds_are_tunable_through_the_collector_config(env):
    from sthelpers import make_stenv
    st = make_stenv(env, speedtests={"diagnosis": {"wifi_rssi_dbm": -90, "wifi_snr_db": 5, "local_slow_pct": 50}})
    t = result(down=15.0)
    out = st.run(t, [wifi(t, rssi=-80, snr=14, util=30, clients=20)])  # -80 is fine under a -90 threshold
    assert "wifi_signal" not in causes(out) and causes(out)[0] == "device_limit"
    cfg = st.app.speedtests.settings.thresholds
    assert cfg.wifi_rssi_dbm == -90 and cfg.wifi_clients == 60 and cfg.wan_util_pct == 85


def test_expectation_table_and_defaults_are_the_documented_ones():
    th = Thresholds()
    assert (th.none_score, th.wifi_rssi_dbm, th.wifi_snr_db, th.local_slow_pct) == (80, -72.0, 20.0, 50.0)
    assert (th.wifi_util_pct, th.wifi_clients, th.roams, th.wan_util_pct) == (70.0, 60, 2, 85.0)
    assert th.wifi_expect_mbps["5/80"] == 450.0 and th.qos_limited_classes == (7, 8, 9, 10)


def test_untrusted_evidence_text_cannot_inject_into_the_noc_text(st):
    t = result(down=15.0)
    w = wifi(t, rssi=-80, snr=14, util=30, clients=20, ap_name="AP\x01name")
    r = st.ingest(t)
    assert r.status == 201
    bad = st.put_ev(w)                                  # the schema refuses control characters in names at the door
    assert bad.status == 400 and bad.json()["error"]["code"] == "invalid_request"
    assert dx.clean("a\x00b\x1fc\x7fd", 10) == "abcd" and len(dx.clean("y" * 500, 64)) == 64
    ev = {"wifi": {"status": "ok", "kind": "wifi", "data": {"client": {"rssi": -80, "snr": 14, "band": "5"},
                                                              "ap": {"ap_name": "evil\x1b[2Jname\nline"}}}}
    d = dx.diagnose(t, ev, None, {"down_mbps": 25.0, "up_mbps": 10.0}, Thresholds(), "final", "2026-11-20T00:00:00Z")
    assert "\x1b" not in d["noc_text"] and "\n" not in d["noc_text"] and "evil[2Jnameline" in d["noc_text"]


def test_a_missing_score_still_diagnoses(st):
    t = result(i_down=None)
    t["legs"]["local"].pop("down_mbps")
    t["legs"]["local"].pop("up_mbps")
    t["score"] = None
    r = st.ingest(t)
    assert r.status == 201 and r.json()["diagnosis"]["cause"] == []
    assert fixture("speedtest/result.ok.json")["score"]["total"] == 78 and time.time() > 0
    assert st.get(f"/{t['id']}").json()["test"]["score"] is None


def test_dns_uses_the_probe_dns_line_when_the_leg_was_measured_by_the_probe(st):
    st.app.speedtests.probe_state = _degraded_probe(sev="warn", lines=[{"key": "dns", "state": "fail",
                                                                         "detail": "10.0.0.53 silent"}])
    t = result(down=300.0, up=200.0, i_down=12.0, i_up=4.0)
    t["legs"]["dns"] = {"source": "probe", "cold_ms": None, "warm_ms": None, "resolver_ip": None}
    t["flags"] = ["dns_fallback"]
    quick = st.ingest(t).json()["diagnosis"]
    ids_ = [c["id"] for c in quick["cause"]]
    assert "dns" in ids_ and {"kind": "baseline", "ref": "data.lines.dns"} in next(
        c for c in quick["cause"] if c["id"] == "dns")["cites"]
    t2 = result(down=300.0, up=200.0, i_down=12.0, i_up=4.0)                # the browser measured it: probe line ignored
    t2["legs"]["dns"] = {"source": "browser", "cold_ms": 20.0, "warm_ms": 2.0, "resolver_ip": "10.0.0.53"}
    assert "dns" not in [c["id"] for c in st.ingest(t2).json()["diagnosis"]["cause"]]


# ----------------------------------------------------------------- unmeasured internet leg (M6 p2)
_UNMEASURED_TEXT = {
    "paused": "internet check is paused",
    "queued": "still waiting for its turn",
    "skipped": "stopped before it finished",
    "off": "not tested at this event",
    "unavailable": "internet could not be reached",
}
# "off" = the box's shape for internet_leg.enabled=false: status unavailable + flag internet_off (not an outage)
NOT_OK = ["paused", "queued", "skipped", "off", "unavailable"]
TARGETS = {"down_mbps": 25.0, "up_mbps": 10.0}


def _set_leg(t, status):
    t["legs"]["internet"] = {"status": "unavailable" if status == "off" else status}
    t["flags"] = ["internet_off"] if status == "off" else []
    return t


def _unmeasured(status):
    t = result(down=800.0, up=700.0, loaded=15.0, cv=0.0)
    _set_leg(t, status)
    t["score"] = {"total": 99, "speed": 100, "responsiveness": 100, "stability": 100}
    return t


def _wan(t, util):
    w = evidence("wan", t)
    w["data"]["wan_util_pct"] = float(util)
    for a in w["data"].get("appliances", []):
        for i in a.get("interfaces", []):
            i["util_pct"] = float(util)
        for m in ("loss", "latency", "jitter"):
            for h in (a.get("health") or {}).get(m, []):
                h["health_status"] = "NORMAL"
    return w


import pytest  # noqa: E402


@pytest.mark.parametrize("status", NOT_OK)
def test_unmeasured_internet_wan_hot_is_wan_saturation(status):
    t = _unmeasured(status)
    d = dx.diagnose(t, {"wan": _wan(t, 90)}, None, {"down_mbps": 25.0, "up_mbps": 10.0}, Thresholds(), "final",
                    "2026-01-01T00:00:00Z")
    assert d["cause"][0]["id"] == "wan_saturation", d
    check_text(d)


@pytest.mark.parametrize("status", NOT_OK)
def test_unmeasured_internet_wan_below_threshold_is_none_with_status_text(status):
    t = _unmeasured(status)
    d = dx.diagnose(t, {"wan": _wan(t, 82)}, None, {"down_mbps": 25.0, "up_mbps": 10.0}, Thresholds(), "final",
                    "2026-01-01T00:00:00Z")
    if status == "unavailable":
        assert d["cause"][0]["id"] == "internet_path" and _UNMEASURED_TEXT[status] in d["user_text"], d
    else:
        assert [c["id"] for c in d["cause"]] == ["none"] and d["cause"][0]["confidence"] == 0.6, d
        assert _UNMEASURED_TEXT[status] in d["user_text"], d
        label = "switched off (internet_off)" if status == "off" else status
        assert f"internet leg {label}: local-only score 99" in d["noc_text"]
        assert {"kind": "legs", "ref": "internet.status"} in d["cause"][0]["cites"]
    assert "below target" not in d["user_text"]
    check_text(d)


def test_internet_ok_high_score_still_short_circuits():
    t = _unmeasured("ok")
    t["legs"]["internet"] = {"status": "ok", "down_mbps": 300.0, "up_mbps": 200.0}
    d = dx.diagnose(t, {"wan": _wan(t, 90)}, None, {"down_mbps": 25.0, "up_mbps": 10.0}, Thresholds(), "final",
                    "2026-01-01T00:00:00Z")
    assert [c["id"] for c in d["cause"]] == ["none"] and d["user_text"] == dx.USER_TEXT["none"]


# ------------------------------------------- unmeasured internet leg with a high local-only score (M6 e2 follow-up)
# A paused / queued / skipped / switched-off / unavailable internet leg with a local-only score of 100: the venue
# network is known good, so the local-side rules (band / port expectations, policy, DNS) must not fire on it; only
# the rules for the path beyond the venue network do (wan_saturation, qos_shaping, network_wide, internet_path).
def _wired_ok(t):
    port = {"port_id": "ge-0/0/12", "up": True, "speed_mbps": 1000, "full_duplex": True, "rx_errors": 0, "tx_errors": 0}
    return [evidence("wired", t, port=port), evidence("identity", t, wired=True)]


def _wifi_no_signal(t):
    w = wifi(t, rssi=-55, snr=40, util=30, clients=10)
    w["data"]["client"].pop("rssi", None)
    w["data"]["client"].pop("snr", None)
    return [w]


LOCAL_CASES = {
    "a_wifi_5ghz_good": lambda t: [wifi(t, rssi=-55, snr=40, util=30, clients=10)],
    "b_wired_1g_healthy": _wired_ok,
    "c_policy_block_evidence": lambda t: [evidence("security", t)],
    "d_wifi_without_rssi_snr": _wifi_no_signal,
}
LOCAL_SIDE = {"wifi_signal", "wifi_congestion", "wifi_roaming", "wired_port", "device_limit", "policy_block", "dns"}


def _local_only(status):
    """Local 200/150 Mb/s, 15 ms loaded, cv 0 and the internet leg not measured: a local-only score of 100."""
    t = _set_leg(result(down=200.0, up=150.0, loaded=15.0, cv=0.0), status)
    t["score"] = st_helpers.compute_score(t["legs"])
    assert t["score"]["total"] == 100, t["score"]
    return t


def _dx(t, evs, stage="final", baseline=None):
    return dx.diagnose(t, {e["kind"]: e for e in evs}, baseline, TARGETS, Thresholds(), stage, "2026-01-01T00:00:00Z")


def _ids(d):
    return [c["id"] for c in d["cause"]]


def _expect_unmeasured_none(d, status):
    if status == "unavailable":                                          # a real outage: internet_path, not "none"
        assert _ids(d) == ["internet_path"] and d["user_text"] == dx.USER_INTERNET_DOWN, d
    else:
        assert _ids(d) == ["none"] and d["cause"][0]["confidence"] == 0.6, d
        assert d["user_text"] == dx.USER_INTERNET_UNMEASURED[status], d
        assert _UNMEASURED_TEXT[status] in d["user_text"]
    assert d["user_text"] not in (dx.USER_UNKNOWN, dx.USER_PENDING_UNKNOWN)
    check_text(d)


@pytest.mark.parametrize("case", sorted(LOCAL_CASES))
def test_internet_ok_high_score_local_evidence_is_healthy(case):
    """Control for the cases below: with a measured internet leg the same evidence reads healthy."""
    t = result(down=200.0, up=150.0, loaded=15.0, i_down=400.0, i_up=200.0, i_loaded=15.0, cv=0.0)
    assert t["score"]["total"] == 100
    d = _dx(t, LOCAL_CASES[case](t))
    assert _ids(d) == ["none"] and d["cause"][0]["confidence"] == 0.9, d


@pytest.mark.parametrize("stage", ["quick", "final"])
@pytest.mark.parametrize("status", NOT_OK)
@pytest.mark.parametrize("case", sorted(LOCAL_CASES))
def test_unmeasured_high_score_local_side_rules_do_not_fire(case, status, stage):
    """Regression (a)-(d): paused gave device_limit 0.55 on good 5 GHz Wi-Fi, device_limit 0.5 (Wi-Fi text) on a
    healthy 1 Gb/s port, policy_block 0.85 from the c0 deny evidence, and cause [] + "below target" at score 100."""
    t = _local_only(status)
    d = _dx(t, LOCAL_CASES[case](t), stage)
    assert not LOCAL_SIDE & set(_ids(d)), d
    _expect_unmeasured_none(d, status)


@pytest.mark.parametrize("status", NOT_OK)
@pytest.mark.parametrize("case", sorted(LOCAL_CASES))
def test_unmeasured_high_score_wan_hot_is_wan_saturation_whatever_the_local_evidence(case, status):
    t = _local_only(status)
    d = _dx(t, LOCAL_CASES[case](t) + [_wan(t, 90)])
    assert _ids(d)[0] == "wan_saturation" and "internet_path" not in _ids(d), d
    assert not LOCAL_SIDE & set(_ids(d)), d
    assert "internet link is very busy" in d["user_text"] and "WAN util 90 %" in d["noc_text"], d
    check_text(d)


@pytest.mark.parametrize("status", NOT_OK)
@pytest.mark.parametrize("case", sorted(LOCAL_CASES))
def test_unmeasured_high_score_wan_below_threshold_is_none(case, status):
    t = _local_only(status)
    d = _dx(t, LOCAL_CASES[case](t) + [_wan(t, 82)])
    _expect_unmeasured_none(d, status)


def _shaped_flows(t):
    fl = evidence("flows", t)
    fl["data"]["counts"]["flows_firewall_dropped"] = 0
    for f in fl["data"]["flows"]:
        f["firewall_dropped"] = 0
    fl["data"]["flows"][0].update(traffic_class=7, slow_duration=40, app_type="Bulk_Data_transfer")
    return fl


@pytest.mark.parametrize("stage", ["quick", "final"])
@pytest.mark.parametrize("status", NOT_OK)
@pytest.mark.parametrize("case", sorted(LOCAL_CASES))
def test_unmeasured_high_score_qos_shaping_is_internet_side(case, status, stage):
    """Owner decision 2026-11-21: the EdgeConnect shaper on the client's WAN flows is a cause beyond the venue network,
    so it is evaluated with a high local-only score too (it used to be skipped there as local-side)."""
    t = _local_only(status)
    d = _dx(t, LOCAL_CASES[case](t) + [_shaped_flows(t)], stage)
    assert "qos_shaping" in _ids(d) and "none" not in _ids(d), d
    assert not LOCAL_SIDE & set(_ids(d)), d
    assert "rate-limited" in d["user_text"] and "traffic class 7" in d["noc_text"], d
    check_text(d)


def test_internet_ok_high_score_hides_qos_shaping_as_before():
    """Control: with a measured internet leg and score >= none_score the healthy short-circuit is unchanged (spec 5.3)."""
    t = result(down=200.0, up=150.0, loaded=15.0, i_down=400.0, i_up=200.0, i_loaded=15.0, cv=0.0)
    d = _dx(t, [_shaped_flows(t)])
    assert _ids(d) == ["none"] and d["cause"][0]["confidence"] == 0.9, d


@pytest.mark.parametrize("status", NOT_OK)
def test_unmeasured_low_score_still_runs_every_rule(status):
    """Below none_score nothing changed: the local-side rules run (here device_limit on good Wi-Fi, slow local)."""
    t = _set_leg(result(down=60.0, up=20.0), status)
    t["score"] = st_helpers.compute_score(t["legs"])
    assert t["score"]["total"] < 80, t["score"]
    d = _dx(t, [wifi(t, rssi=-52, snr=40, util=30, clients=10, proto="n", power_saving=True, tx_rate=72.0)])
    assert _ids(d)[0] == "device_limit", d


# --------------------------------------------------------------------------- internet_off (operator switch)
def test_internet_off_is_not_an_outage(st):
    """internet_leg.enabled=false is stored as status unavailable + flag internet_off: the result covers the venue
    network only; never "the internet could not be reached" (that is for flag internet_unavailable)."""
    t = result(down=800.0, up=700.0, loaded=15.0, i_down=None, cv=0.0, flags=["internet_off"])
    assert t["legs"]["internet"] == {"status": "unavailable"} and t["score"]["total"] >= 80
    quick = st.ingest(t).json()["diagnosis"]                            # the schema accepts the flag
    assert [c["id"] for c in quick["cause"]] == ["none"] and quick["cause"][0]["confidence"] == 0.6, quick
    assert "not tested at this event" in quick["user_text"] and "could not be reached" not in quick["user_text"]
    out = st.run(result(down=800.0, up=700.0, loaded=15.0, i_down=None, cv=0.0, flags=["internet_off"]), [])
    d = out["diagnosis"]
    assert d["stage"] == "final" and causes(out) == ["none"], d
    assert "internet_off" in d["noc_text"] and {"kind": "legs", "ref": "flags.internet_off"} in d["cause"][0]["cites"]
    check_text(d)


def test_internet_off_low_score_does_not_blame_the_internet(st):
    t = result(down=400.0, up=300.0, i_down=None, flags=["internet_off"])
    assert t["score"]["total"] < 80, t["score"]
    quick = st.ingest(t).json()["diagnosis"]
    assert "internet_path" not in [c["id"] for c in quick["cause"]], quick
    assert "could not be reached" not in quick["user_text"]
    down = result(down=400.0, up=300.0, i_down=None, flags=["internet_unavailable"])  # control: a real outage
    assert st.ingest(down).json()["diagnosis"]["cause"][0]["id"] == "internet_path"


def test_paused_text_holds_for_an_admin_pause_too():
    """status paused covers the automatic (busy WAN) and the admin pause; no reason travels in the result."""
    txt = dx.USER_INTERNET_UNMEASURED["paused"]
    assert "busy" not in txt and "try again" not in txt and "paused right now" in txt and "venue network only" in txt


# ------------------------------------------------------------------- internet down + network_wide (A6.7 text)
_FAILING_PROBE = {"probe": "core-tp0", "distance": "same_site", "severity": "fail",
                  "lines": [{"key": "network", "state": "ok"}, {"key": "internet", "state": "fail"}]}


@pytest.mark.parametrize("high", [True, False])
def test_internet_down_with_network_wide_says_the_internet_cannot_be_reached(high):
    if high:
        t = result(down=800.0, up=700.0, loaded=15.0, i_down=None, cv=0.0, flags=["internet_unavailable"])
    else:
        t = result(down=400.0, up=300.0, i_down=None, flags=["internet_unavailable"])
    assert (t["score"]["total"] >= 80) is high, t["score"]
    d = _dx(t, [], baseline=_FAILING_PROBE)
    assert _ids(d)[0] == "network_wide" and "internet_path" in _ids(d), d
    assert d["user_text"].startswith(dx.USER_NETWORK_WIDE_DOWN) and "slowdown" not in d["user_text"], d
    assert dx.USER_INTERNET_DOWN not in d["user_text"], d          # one "unreachable" sentence, not two
    assert "internet" in (d["user_text"] + d["noc_text"]).lower()
    check_text(d)


@pytest.mark.parametrize("flags", [["internet_off"], []])
def test_network_wide_text_unchanged_when_the_internet_is_not_down(flags):
    t = result(down=400.0, up=300.0, i_down=None if flags else 8.0, flags=flags)
    d = _dx(t, [], baseline=_FAILING_PROBE)
    assert _ids(d)[0] == "network_wide" and d["user_text"].startswith(dx.USER_TEXT["network_wide"]), d
