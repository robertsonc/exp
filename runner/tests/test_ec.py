"""The EdgeConnect connector against the c1 fake Orchestrator (pyedgeconnect field mapping; every scenario value must arrive)."""
from __future__ import annotations

import time

import pytest
from connhelpers import IP, World, capture_logs
from orchestrator import server as forch

from exp_runner import ec as ec_mod
from exp_runner.connectors import EvidenceResult
from exp_runner.ec import EcService, WanUtilMonitor, parse_flow, ts_utilization
from exp_runner.upstream import UpstreamClient


@pytest.fixture()
def w(tmp_path):
    world = World(tmp_path, mist=False)
    yield world
    world.close()


def flows(docs):
    return docs["flows"]["data"]


def wan(docs):
    return docs["wan"]["data"]


def test_flows_for_the_client_ip_top_by_bytes_with_every_documented_field(w):
    w.ec_scenario("healthy")
    docs, _i, _c = w.run()
    assert docs["flows"]["status"] == "ok" and docs["flows"]["source"] == "ec"
    d = flows(docs)
    assert d["appliance"] == "1.NE"
    assert [f["application"] for f in d["flows"]] == ["speedtest_http", "dns"]            # sorted by bytes, the other client's flow excluded
    f = d["flows"][0]
    assert f["ip1"] == IP and f["ip2"] == "203.0.113.50" and f["port1"] == 51000 and f["port2"] == 443 and f["protocol"] == "tcp"
    assert f["bytes_out_tx"] == 60_000_000 and f["bytes_in_rx"] == 190_000_000 and f["bytes_in_tx"] == 1_000 and f["bytes_out_rx"] == 0
    assert f["bytes_total"] == 250_001_000 and f["uptime_ms"] == 120_000 and f["overlay"] == "DefaultOverlay" and f["traffic_class"] == 3
    assert f["lan_vlan"] == 160 and f["lan_dscp"] == "trust-lan" and f["app_type"] == "Interactive" and f["outbound_tunnel"] == "to_dc"
    assert f["from_zone"] == 1 and f["to_zone"] == 2 and f["drop_reason"] == 0 and f["firewall_dropped"] == 0
    assert f["start_s"] == int(w.at - 120)
    assert d["counts"]["returned_flows"] == 2 and d["counts"]["matched_flows"] == 2 and d["counts"]["total_flows"] == 3


def test_qos_shaped_inputs_for_the_qos_rule(w):
    w.ec_scenario("qos_shaped")
    docs, _i, _c = w.run()
    f = flows(docs)["flows"][0]
    assert f["traffic_class"] == 7 and f["app_type"] == "Bulk_Data_transfer" and f["slow_duration"] == 40 and f["wan_dscp"] == "be"
    alarms = wan(docs)["appliances"][0]["alarms"]
    assert alarms[0]["alarm_name"] == "Shaper drops" and alarms[0]["severity"] == "warning" and alarms[0]["service_affect"] is False


def test_firewall_drop_inputs_for_the_policy_block_rule(w):
    w.ec_scenario("firewall_drop")
    docs, _i, _c = w.run()
    drops = [f for f in flows(docs)["flows"] if f["drop_reason"] == 1]
    assert len(drops) == 1 and drops[0]["firewall_dropped"] == 1 and drops[0]["port2"] == 22
    assert flows(docs)["counts"]["flows_firewall_dropped"] == 1
    assert docs["security"]["data"]["ec_dropped_flows"] == 1                        # merged into the syslog security evidence
    assert docs["security"]["source"] == "syslog"


def test_ec_dropped_flows_without_syslog_security_makes_an_ec_security_document(tmp_path):
    w = World(tmp_path, mist=False)
    try:
        w.corr.connectors = [c for c in w.connectors if c.name != "syslog"]
        w.ec_scenario("firewall_drop")
        docs, _i, _c = w.run()
        assert docs["security"]["source"] == "ec" and docs["security"]["status"] == "partial"
        assert docs["security"]["data"]["ec_dropped_flows"] == 1 and docs["security"]["data"]["events"] == []
    finally:
        w.close()


def test_saturated_wan_inputs_for_the_wan_saturation_rule(w):
    w.ec_scenario("saturated_wan")
    docs, _i, _c = w.run()
    assert docs["wan"]["status"] == "ok" and docs["wan"]["source"] == "ec"
    d = wan(docs)
    assert d["wan_util_pct"] == pytest.approx(92.5, abs=0.1)
    a = d["appliances"][0]
    assert a["ne_pk"] == "1.NE" and a["hostname"] == "ec-core" and a["state"] == 1
    wan0 = next(i for i in a["interfaces"] if i["ifname"] == "wan0")
    assert wan0["wan_if"] is True and wan0["util_pct"] == pytest.approx(92.5, abs=0.1) and wan0["rx_bps"] == 185_000_000
    assert wan0["tx_bps"] == 60_000_000 and wan0["max_wan_bandwidth_kbps"] == 200_000 and wan0["public_ip"] == "203.0.113.2"
    assert wan0["duplex"] == "full (auto)" and wan0["if_speed"] == "1000" and wan0["label"] == "2"
    lan0 = next(i for i in a["interfaces"] if i["ifname"] == "lan0")
    assert lan0["lan_if"] is True and "util_pct" not in lan0                                 # only WAN interfaces get a utilization
    h = a["health"]
    assert h["latency"][0]["health_status"] == "CRITICAL" and h["latency"][0]["major_mins"] == 14 and h["latency"][0]["critical_mins"] == 6
    assert h["latency"][0]["max"] == 38 and h["latency"][0]["tunnel_id"] == "to_dc" and h["loss"][0]["max"] == 0.0
    assert a["alarms"][0]["alarm_name"] == "Tunnel state" and a["alarms"][0]["severity"] == "major" and a["alarms"][0]["closed"] is False
    assert a["alarms"][0]["host_name"] == "ec-core" and a["alarms"][0]["type"] == "tunnel"
    assert a["timeseries"]["columns"] == ["time", "interface", "rx_bytes", "tx_bytes"] and a["timeseries"]["rows"]


def test_loss_scenario_reports_loss_health_and_alarm(w):
    w.ec_scenario("loss")
    docs, _i, _c = w.run()
    a = wan(docs)["appliances"][0]
    assert a["health"]["loss"][0]["max"] == 3.5 and a["health"]["loss"][0]["health_status"] == "CRITICAL" and a["health"]["jitter"][0]["max"] == 9
    assert a["health"]["mos"][0]["max"] == 3.2 and a["alarms"][0]["severity"] == "critical"
    assert wan(docs)["wan_util_pct"] < 20


def test_column_order_is_read_from_column_def_at_runtime(w):
    w.ec_scenario("saturated_wan")
    w.forch.app.interface_columns = ["tx_bytes", "interface", "time", "rx_bytes"]              # reordered
    docs, _i, _c = w.run()
    assert wan(docs)["wan_util_pct"] == pytest.approx(92.5, abs=0.1)


def test_unidentifiable_columns_keep_the_raw_series_and_are_partial(w):
    w.ec_scenario("saturated_wan")
    w.forch.app.interface_columns = ["time", "interface", "alpha", "beta"]
    docs, _i, _c = w.run()
    assert docs["wan"]["status"] == "partial" and "wan_util_pct" not in wan(docs)
    assert wan(docs)["appliances"][0]["timeseries"]["columns"] == ["time", "interface", "alpha", "beta"]


def test_health_list_shape_is_accepted(w):
    w.ec_scenario("loss")
    w.forch.app.health_shape = "list"
    docs, _i, _c = w.run()
    assert wan(docs)["appliances"][0]["health"]["loss"][0]["max"] == 3.5


def test_flows_outside_the_window_are_dropped(w):
    w.ec_scenario("healthy")
    w.forch.state.add_flow("1.NE", src_ip=IP, start_s=int(w.at - 4000), end_s=int(w.at - 3900), application="ancient", bytes_out_tx=9_999_999_999)
    docs, _i, _c = w.run()
    assert "ancient" not in [f["application"] for f in flows(docs)["flows"]]


def test_flows_are_bounded_to_the_configured_top_n(tmp_path):
    w = World(tmp_path, mist=False)
    try:
        w.ec_scenario("healthy")
        for n in range(80):
            w.forch.state.add_flow("1.NE", src_ip=IP, start_s=int(w.at - 100), application=f"app{n}", bytes_out_tx=1000 + n)
        w.ec_svc.max_flows = 50
        docs, _i, _c = w.run()
        fl = flows(docs)["flows"]
        assert len(fl) == 50 and fl[0]["application"] == "speedtest_http" and [f["bytes_total"] for f in fl] == sorted((f["bytes_total"] for f in fl), reverse=True)
    finally:
        w.close()


def test_wan_poll_value_and_hysteresis_for_the_auto_pause(w):
    w.forch.state.set_wan_load("1.NE", "wan0", 185_000_000, 60_000_000, t_from=time.time() - 400)
    mon = WanUtilMonitor(w.ec_svc)
    assert mon.value() == pytest.approx(92.5, abs=0.1)
    # the load drops now: the held peak of the previous bucket still counts for ~2 minutes (hysteresis on the way down)
    w.forch.state.set_wan_load("1.NE", "wan0", 20_000_000, 10_000_000, t_from=time.time() - 5)
    w.ec_svc._cache._d.clear()
    assert mon.value() > 50
    w.forch.state.set_wan_load("1.NE", "wan0", 20_000_000, 10_000_000, t_from=time.time() - 400)
    w.ec_svc._cache._d.clear()
    assert mon.value() == pytest.approx(10.0, abs=0.5)


def test_wan_poll_failure_returns_none_so_the_speedtest_fails_open(w):
    w.forch.app.set_force(503)
    assert WanUtilMonitor(w.ec_svc).value() is None
    w.forch.app.set_force(None)


def test_pause_source_is_registered_by_the_app_and_published(tmp_path):
    """The WAN value flows through PausePublisher to the speedtest channel (stubbed here)."""
    from exp_runner.channel import PausePublisher

    w = World(tmp_path, mist=False)
    try:
        w.ec_scenario("saturated_wan")

        class Chan:
            def __init__(self):
                self.got = []

            def put_pause(self, v, t):
                self.got.append(v)
        ch = Chan()
        pub = PausePublisher(ch)
        pub.set_source(WanUtilMonitor(w.ec_svc).value)
        assert pub.publish_once() and ch.got and ch.got[0] == pytest.approx(92.5, abs=0.2)
    finally:
        w.close()


# ------------------------------------------------------------------------------------------------ failure handling
def test_flows_5xx_is_error_without_crashing_the_other_kinds(w):
    w.ec_scenario("healthy")
    w.forch.app.set_force(500)
    docs, _i, _c = w.run()
    assert docs["flows"]["status"] == "error" and docs["flows"]["data"] == {}
    assert docs["wan"]["status"] == "error"
    assert docs["identity"]["status"] in ("ok", "partial", "unavailable")


def test_transient_5xx_retries_idempotent_reads(w):
    w.ec_scenario("healthy")
    w.forch.app.set_force(502, 1)
    docs, _i, _c = w.run()
    assert docs["flows"]["status"] == "ok"


def test_one_failing_call_makes_wan_partial_with_the_rest(w):
    w.ec_scenario("saturated_wan")
    orig = w.ec_svc.health

    def boom(ne, kind, hour, sc):
        if kind == "jitter":
            raise ec_mod.UpstreamError("http", "boom", 500)
        return orig(ne, kind, hour, sc)
    w.ec_svc.health = boom
    docs, _i, _c = w.run()
    assert docs["wan"]["status"] == "partial" and wan(docs)["wan_util_pct"] > 90 and "jitter" not in wan(docs)["appliances"][0]["health"]


def test_429_pauses_the_connector(w):
    w.ec_scenario("healthy")
    w.forch.app.set_force(429, 1)
    docs, _i, _c = w.run()
    assert docs["flows"]["status"] == "error" and w.ec_svc.client.blocked_for() > 0
    n = len(w.forch.app.log)
    w.run()
    assert len(w.forch.app.log) == n


def test_auth_failure_is_an_error_and_not_retried(w):
    bad = EcService(w.cfg.ec, {"url": w.forch.base_url, "api_key": "wrong-key"})
    w.ec_scenario("healthy")
    w.ec_svc.client = bad.client
    docs, _i, _c = w.run()
    assert docs["flows"]["status"] == "error"
    assert all(c["status"] == 401 for c in w.forch.app.log) and len(w.forch.app.log) == 1      # the first 401 skips the rest of the chain


def test_call_budget_bounds_the_connector(w):
    w.ec_scenario("saturated_wan")
    w.run()
    first = len(w.forch.app.log)
    assert 0 < first <= ec_mod.CALLS_PER_TEST


def test_budget_exhaustion_gives_partial_not_a_crash(w, monkeypatch):
    w.ec_scenario("saturated_wan")
    monkeypatch.setattr(ec_mod, "CALLS_PER_TEST", 4)
    docs, _i, _c = w.run()
    assert docs["flows"]["status"] == "ok" and docs["wan"]["status"] in ("partial", "ok")
    assert len(w.forch.app.log) <= 4


def test_api_key_never_appears_in_logs(w, caplog):
    w.ec_scenario("healthy")
    w.forch.app.set_force(500, 3)
    w.run()
    key = forch.default_credentials()[0]
    assert key not in capture_logs(caplog)


def test_key_is_sent_in_x_auth_token_only(w):
    w.ec_scenario("healthy")
    seen = []
    orig = w.ec_svc.client._once

    def spy(method, target, body, extra):
        seen.append((target, dict(w.ec_svc.client._headers)))
        return orig(method, target, body, extra)
    w.ec_svc.client._once = spy
    w.run()
    key = forch.default_credentials()[0]
    assert seen and all(h["X-Auth-Token"] == key and key not in t for t, h in seen)


def test_unconfigured_ec_is_skipped(tmp_path):
    from connhelpers import make_config
    w = World(tmp_path, mist=False, ec=False, cfg=make_config(mist=False, ec=False))
    try:
        docs, _i, _c = w.run()
        assert docs["flows"]["status"] == "unavailable" and docs["wan"]["status"] == "unavailable"
    finally:
        w.close()


def test_plain_http_is_loopback_only():
    with pytest.raises(ValueError):
        UpstreamClient("ec", "http://10.1.2.3/gms/rest", {"X-Auth-Token": "k"})
    with pytest.raises(ValueError):
        UpstreamClient("ec", "https://user:pw@orch.example/gms/rest", {})


# ---------------------------------------------------------------------------------------------------- unit tests
def test_parse_flow_rejects_short_or_garbled_rows():
    assert parse_flow([1, 2, 3]) is None and parse_flow("x") is None
    row = [0] * 63
    row[9], row[16] = "not-an-ip", "10.0.0.1"
    assert parse_flow(row) is None
    row[9] = "10.0.0.2"
    row[3], row[45] = "app\x00\x1bname" + "x" * 500, "host.example"
    f = parse_flow(row)
    assert f and len(f["application"]) <= 64 and "\x00" not in f["application"] and f["domain"] == "host.example"


def test_ts_utilization_reads_renamed_columns():
    cols = ["ts", "ifname", "rxBytes", "txBytes"]
    rows = [[1_800_000_000, "wan0", 60 * 50_000_000 // 8, 0]]
    util, ok = ts_utilization(cols, rows, {"wan0"}, 100_000, 1_799_999_990, 1_800_000_100)
    assert ok and util["wan0"]["util_pct"] == pytest.approx(50.0)


def test_ts_utilization_handles_ms_timestamps_and_unknown_interface_columns():
    cols = ["timestamp", "rx_bytes", "tx_bytes"]
    t = 1_800_000_000
    rows = [[(t + 60 * i) * 1000, 60 * 10_000_000 // 8 * (i + 1), 1000] for i in range(3)]
    util, ok = ts_utilization(cols, rows, None, 100_000, t - 10, t + 500)
    assert ok and util["*"]["rx_bps"] == 30_000_000 and util["*"]["util_pct"] == pytest.approx(30.0)
    assert ts_utilization(["a", "b"], [[1, 2]], None, 1, 0, 1) == ({}, False)


def test_evidence_result_type_is_unchanged():
    assert EvidenceResult("flows", "ec", "ok").data == {}
