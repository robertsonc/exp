"""Cross-connector behaviour: the collector's own diagnosis rules consume what the connectors produce, the baseline and SSE connectors,
the registry, the daemon wiring (pause source, baseline client) and credential hygiene across a whole pipeline run."""
from __future__ import annotations

import dataclasses
import json
import sys
import time

import pytest
from connhelpers import IP, World, capture_logs, make_config
from mist import server as fmist
from orchestrator import server as forch
from rthelpers import ROOT, base_config, runner_token, secret, st_result
from test_app_cli import wait_for
from test_channel import TOKEN, StubSpeedtest

from exp_runner import app as app_mod
from exp_runner.app import RunnerApp, default_connectors
from exp_runner.baseline import BaselineConnector, SseConnector, normalize_baseline
from exp_runner.collector_client import CollectorClient
from exp_runner.config import CredStore, Paths, parse_config
from exp_runner.connectors import SyslogConnector
from exp_runner.ec import EcConnector
from exp_runner.mist import MistConnector
from exp_runner.ring import Ring

sys.path.insert(0, str(ROOT / "collector"))
from exp_collector.speedtest import diagnosis as dx  # noqa: E402
from exp_collector.speedtest.settings import Thresholds  # noqa: E402

TARGETS = {"down_mbps": 25.0, "up_mbps": 10.0}


def diagnose(docs, down, up=5.0, internet_down=8.0):
    test = {"legs": {"local": {"down_mbps": down, "up_mbps": up}, "internet": {"status": "ok", "down_mbps": internet_down, "up_mbps": 3.0}}}
    out = dx.diagnose(test, docs, None, TARGETS, Thresholds(), "final", "2026-11-20T00:00:00.000Z")
    return [c["id"] for c in out["diagnosis"]["cause"]] if "diagnosis" in out else [c["id"] for c in out["cause"]]


@pytest.fixture()
def w(tmp_path):
    world = World(tmp_path)
    yield world
    world.close()


@pytest.mark.parametrize(("mist_s", "ec_s", "down", "expect"), [
    ("weak_rssi", "healthy", 15.0, "wifi_signal"),
    ("congested_ap", "healthy", 15.0, "wifi_congestion"),
    ("roaming", "healthy", 15.0, "wifi_roaming"),
    ("wired_port_errors", "healthy", 15.0, "wired_port"),
    ("healthy", "saturated_wan", 300.0, "wan_saturation"),
    ("healthy", "qos_shaped", 15.0, "qos_shaping"),
    ("healthy", "firewall_drop", 300.0, "policy_block"),
])
def test_connector_output_drives_the_collector_rule(w, mist_s, ec_s, down, expect):
    w.mist_scenario(mist_s)
    w.ec_scenario(ec_s)
    docs, _i, _c = w.run()
    assert expect in diagnose(docs, down), (expect, diagnose(docs, down))


def test_healthy_world_fires_no_fault_rule(w):
    w.mist_scenario("healthy")
    w.ec_scenario("healthy")
    docs, _i, _c = w.run()
    bad = {"wifi_signal", "wifi_congestion", "wifi_roaming", "wired_port", "wan_saturation", "qos_shaping", "policy_block"}
    assert not bad & set(diagnose(docs, 300.0, 200.0, 300.0))


def test_all_eight_kinds_are_present_and_valid_and_sources_are_allowed(w):
    w.mist_scenario("healthy")
    w.ec_scenario("healthy")
    docs, _i, _c = w.run()
    assert set(docs) == {"identity", "wifi", "wired", "flows", "wan", "security", "baseline", "dns"}
    assert docs["wifi"]["source"] == "mist" and docs["flows"]["source"] == "ec" and docs["baseline"]["source"] == "exp"
    assert docs["baseline"]["status"] == "ok" and docs["baseline"]["data"]["probe"] == "probe-a1"
    assert docs["identity"]["source"] == "mist"


def test_nat_ambiguity_never_binds_but_the_ip_scoped_sources_still_report(w):
    w.mist_scenario("nat_ambiguity")
    w.ec_scenario("healthy")
    docs, ident, _c = w.run()
    assert ident.nat_suspected and "mac" not in docs["identity"]["data"]
    assert docs["wifi"]["status"] == "unavailable" and docs["wired"]["status"] == "unavailable"
    assert docs["flows"]["status"] == "ok" and docs["baseline"]["status"] == "ok"          # keyed by IP / site, never by an ambiguous device


def test_baseline_receives_zone_ap_and_test_end_time(w):
    w.mist_scenario("healthy")
    seen = []
    orig = w.collector_client.baseline

    def spy(site, zone, ap, at):
        seen.append((site, zone, ap, at))
        return orig(site, zone, ap, at)
    w.collector_client.baseline = spy
    w.run()
    assert seen[0][:3] == ("hall-b", "hall-b", "hallb-ap-12") and seen[0][3].endswith("Z")


def test_baseline_unresolved_zone_is_not_sent_as_a_zone(w):
    w.mist_scenario("no_client")
    seen = []
    orig = w.collector_client.baseline
    w.collector_client.baseline = lambda site, zone, ap, at: (seen.append((zone, ap)), orig(site, zone, ap, at))[1]
    w.run()
    assert seen[0][1] is None and seen[0][0] != "unresolved"


def test_baseline_not_found_is_unavailable_and_collector_failure_is_error(w):
    w.fcoll.app.set_baseline(None)
    docs, _i, _c = w.run()
    assert docs["baseline"]["status"] == "unavailable" and docs["baseline"]["data"] == {}
    w.fcoll.app.set_baseline(None)
    w.collector_client.baseline = lambda *a: (_ for _ in ()).throw(__import__("exp_runner.collector_client", fromlist=["x"]).CollectorError("boom"))
    docs, _i, _c = w.run()
    assert docs["baseline"]["status"] == "error"


def test_baseline_without_a_collector_client_is_unavailable():
    c = BaselineConnector()
    assert c._client_fn() is None


def test_normalize_baseline_is_a_closed_bounded_copy():
    out = normalize_baseline({"probe": "probe-a1", "severity": "warn", "evil": "x", "distance": "same_ap", "at": "2026-01-01T00:00:00Z",
                              "lines": [{"key": "wifi", "state": "fail", "detail": "d" * 900, "extra": 1}, {"key": "bogus", "state": "ok"}],
                              "throughput": {"down_mbps": 10, "junk": 1}})
    assert "evil" not in out and out["lines"] == [{"key": "wifi", "state": "fail", "detail": "d" * 200}] and out["throughput"] == {"down_mbps": 10.0}
    assert normalize_baseline({"probe": "Bad Slug!", "severity": "ok"}) is None and normalize_baseline({"probe": "p", "severity": "nope"}) is None


def test_sse_connector_reports_unavailable_with_the_reason_and_produces_no_evidence():
    c = SseConnector()
    assert c.configured() is False and c.kinds == () and c.status()["status"] == "unavailable" and "no local vendor" in c.status()["reason"]


# --------------------------------------------------------------------------------------------------------- registry
def write_creds(d, collector=None, mist=None, ec=None):
    d.mkdir(exist_ok=True)
    if collector:
        (d / "collector_token").write_text(collector)
    ints = {}
    if mist:
        ints["mist"] = {"api_base": mist.base_url, "token": fmist.default_token()}
    if ec:
        ints["ec"] = {"url": ec.base_url, "api_key": forch.default_credentials()[0]}
    (d / "integrations.json").write_text(json.dumps(ints))
    (d / "integrations.json").chmod(0o600)


def test_default_connectors_register_what_is_configured_and_credentialed(tmp_path, w):
    d = tmp_path / "creds"
    write_creds(d, mist=w.fmist, ec=w.forch)
    cfg = make_config(True, True)
    conns, provider = default_connectors(cfg, CredStore(d), Ring(tmp_path / "x.db").open())
    assert [type(c) for c in conns] == [SyslogConnector, MistConnector, EcConnector, BaselineConnector] and provider is not None
    # no credentials -> no Mist/EC connector and no identity provider (the runner degrades, it does not crash)
    d2 = tmp_path / "creds2"
    d2.mkdir()
    conns, provider = default_connectors(cfg, CredStore(d2), Ring(tmp_path / "y.db").open())
    assert [type(c) for c in conns] == [SyslogConnector, BaselineConnector] and provider is None


def test_sse_enabled_in_config_registers_the_placeholder_and_health_fact(tmp_path):
    doc = base_config()
    doc["correlation"]["sources"]["sse"] = {"enabled": True}
    cfg = parse_config(doc)
    conns, _p = default_connectors(cfg, CredStore(None), Ring(tmp_path / "z.db").open())
    assert any(isinstance(c, SseConnector) for c in conns)


def test_daemon_end_to_end_with_mist_ec_baseline_and_pause(tmp_path, monkeypatch):
    """RunnerApp wiring: Mist identity + wifi, EC flows/wan, the correlator's collector client for the baseline, the pause source."""
    monkeypatch.setattr(app_mod, "WHERE_POLL_S", 0.2)
    w = World(tmp_path / "w")
    stub = StubSpeedtest()
    try:
        w.mist_scenario("congested_ap")
        w.ec_scenario("saturated_wan")
        cfg = make_config(True, True)
        cfg = dataclasses.replace(cfg, syslog=dataclasses.replace(cfg.syslog, listen=(("udp", 0), ("tcp", 0)), bind="127.0.0.1"), poll_interval_s=1,
                                  ec={**cfg.ec, "wan_util": {"enabled": True, "interval_s": 0.3}}, channel_url=f"http://127.0.0.1:{stub.server_address[1]}/local/v1")
        cdir = tmp_path / "creds"
        write_creds(cdir, collector=runner_token(w.fcoll.app.tokens), mist=w.fmist, ec=w.forch)
        (cdir / "device_key_secret").write_text(secret())
        (cdir / "speedtest_channel_token").write_text(TOKEN)
        paths = dataclasses.replace(Paths.resolve(str(tmp_path / "s"), str(tmp_path / "r"), None, None), creds_dir=cdir)
        app = RunnerApp(cfg, paths, CredStore(cdir), client_factory=lambda c, tok: CollectorClient(f"http://127.0.0.1:{w.fcoll.port}", None, tok)).start()
        try:
            doc = st_result(1, now=time.time())
            t, _ = w.fcoll.app.store(doc, "spd-core", "hall-b")
            assert wait_for(lambda: t.state == "final", timeout=30), "evidence was not completed"
            ev = t.evidence
            assert ev["identity"]["data"]["resolved_by"] == "mist" and ev["wifi"]["status"] == "ok" and ev["wifi"]["data"]["ap"]["radio"]["util_all"] == 93
            assert ev["flows"]["status"] == "ok" and ev["wan"]["data"]["wan_util_pct"] > 90 and ev["baseline"]["status"] == "ok"
            assert wait_for(lambda: stub.pause, timeout=10) and stub.pause[0]["wan_util_pct"] > 90 and stub.pause[0]["source"] == "ec"
            snap = app.snapshot()
            assert {"mist", "ec", "baseline", "syslog"} <= {p["source"] for p in snap["metrics"]["pullers"]}
        finally:
            app.stop()
    finally:
        stub.shutdown()
        w.close()


def test_no_credential_value_appears_in_any_log_line_across_a_failing_pipeline(w, caplog):
    w.mist_scenario("healthy")
    w.ec_scenario("healthy")
    w.fmist.app.set_force(500, 4)
    w.forch.app.set_force(503, 4)
    w.run()
    w.fmist.app.set_rate_limit(0)
    w.mist_svc._lookups._d.clear()
    w.forch.app.set_force(401, 2)
    w.run()
    logs = capture_logs(caplog)
    secrets = [fmist.default_token(), forch.default_credentials()[0], forch.default_credentials()[2], w.runner_tok]
    assert logs and not any(s in logs for s in secrets)
    assert "Authorization" not in logs and "X-Auth-Token" not in logs


def test_budget_dict_is_per_test_and_sources_are_independent(w):
    w.mist_scenario("healthy")
    w.ec_scenario("healthy")
    _d, _i, ctx = w.run()
    assert ctx.budgets["mist"].used <= 6 and ctx.budgets["ec"].used > 6 and ctx.budgets["ec"].limit >= ctx.budgets["ec"].used
    assert IP
