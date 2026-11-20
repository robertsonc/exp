"""The daemon end to end (real receiver + fake collector + stub channel) and the CLI."""
from __future__ import annotations

import dataclasses
import json
import os
import signal
import subprocess
import sys
import time

import fake_st_collector as fst
import syslog_sender as ss
from exp_common import ids as exp_ids
from rthelpers import ROOT, base_config, runner_token, secret, st_result
from test_channel import TOKEN, StubSpeedtest

from exp_runner import app as app_mod
from exp_runner import cli
from exp_runner import health as health_mod
from exp_runner.app import RunnerApp
from exp_runner.collector_client import CollectorClient
from exp_runner.config import CredStore, Paths, parse_config

BIN = ROOT / "runner" / "bin" / "exp-runner"


def wait_for(fn, timeout=15.0, step=0.1):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return fn()


def creds(tmp_path, runner_tok, channel=False):
    d = tmp_path / "creds"
    d.mkdir()
    (d / "collector_token").write_text(runner_tok)
    (d / "device_key_secret").write_text(secret())
    if channel:
        (d / "speedtest_channel_token").write_text(TOKEN)
    return d


def ephemeral(cfg, channel_port=None):
    sl = dataclasses.replace(cfg.syslog, listen=(("udp", 0), ("tcp", 0)), bind="127.0.0.1")
    kw = {"syslog": sl, "poll_interval_s": 1}
    if channel_port:
        kw["channel_url"] = f"http://127.0.0.1:{channel_port}/local/v1"
    return dataclasses.replace(cfg, **kw)


def test_daemon_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(app_mod, "WHERE_POLL_S", 0.2)
    fake = fst.start()
    stub = StubSpeedtest()
    try:
        cfg = ephemeral(parse_config(base_config()), stub.server_address[1])
        paths = Paths.resolve(str(tmp_path / "state"), str(tmp_path / "run"), None, None)
        paths = dataclasses.replace(paths, creds_dir=creds(tmp_path, runner_token(fake.app.tokens | {"runner": fake.app.tokens["runner"]}), True))
        app = RunnerApp(cfg, paths, CredStore(paths.creds_dir),
                        client_factory=lambda c, tok: CollectorClient(f"http://127.0.0.1:{fake.port}", None, tok)).start()
        try:
            port = wait_for(lambda: app.receiver and app.receiver.ports.get("udp"))
            now = time.time()
            at = now - 880                                       # the test ran 15 minutes ago; message timestamps place the lines in its window
            ss.send_udp("127.0.0.1", port, [ss.rfc3164_message(ss.dhcp_isc("DHCPACK", "10.60.14.77", "f0:18:98:aa:bb:01", "alices-iphone"), ts=at - 5),
                                            ss.rfc3164_message(ss.ec_firewall(src="10.60.14.77"), ts=at),
                                            ss.rfc3164_message(ss.ec_firewall(src="10.60.14.77"), ts=at + 1)])
            assert wait_for(lambda: app.ring.count() >= 3)
            doc = st_result(1, now=now)
            t, _ = fake.app.store(doc, "spd-core", "hall-b")
            assert wait_for(lambda: t.state == "final"), "evidence was not completed"
            assert t.evidence["identity"]["data"]["resolved_by"] == "dhcp"
            assert t.evidence["security"]["data"]["counts"]["drop"] == 2
            # the where-cache loop answers the page's question without a MAC
            stub.wanted = ["10.60.14.77"]
            assert wait_for(lambda: stub.where)
            assert "f0:18:98" not in json.dumps(stub.where) and stub.where[0]["items"][0]["zone"] == "hallb-row12"
            snap = app.snapshot()
            assert snap["status"] == "ok", snap["detail"]
            assert snap["metrics"]["correlations_per_hour"] == 1 and snap["metrics"]["syslog_ring_lines"] >= 3
            assert any(p["source"] == "syslog" for p in snap["metrics"]["pullers"])
            app.monitor.write_once()
            doc = health_mod.read_health(paths.health_file)
            assert doc["status"] == "ok" and doc["metrics"]["drills_active"] == 0
        finally:
            app.stop()
    finally:
        stub.shutdown()
        fake.stop()


def test_health_is_degraded_without_credentials_and_recovers_when_they_appear(tmp_path):
    fake = fst.start()
    try:
        cfg = ephemeral(parse_config(base_config()))
        cdir = tmp_path / "creds"
        cdir.mkdir()
        paths = dataclasses.replace(Paths.resolve(str(tmp_path / "s"), str(tmp_path / "r"), None, None), creds_dir=cdir)
        app = RunnerApp(cfg, paths, CredStore(cdir), client_factory=lambda c, tok: CollectorClient(f"http://127.0.0.1:{fake.port}", None, tok)).start()
        try:
            snap = app.snapshot()
            assert snap["status"] == "degraded" and "collector_token" in snap["detail"]
            (cdir / "collector_token").write_text(runner_token(fake.app.tokens))
            (cdir / "device_key_secret").write_text(secret())
            assert wait_for(lambda: app.correlator is not None and app.correlator.feed_ok is not None, timeout=10)
            assert wait_for(lambda: app.snapshot()["status"] == "ok", timeout=5), app.snapshot()["detail"]
            assert app.resolver.secret == secret()          # a credential that appears later is picked up without a restart
        finally:
            app.stop()
    finally:
        fake.stop()


def test_refused_token_degrades_health(tmp_path):
    fake = fst.start()
    try:
        cfg = ephemeral(parse_config(base_config()))
        d = creds(tmp_path, exp_ids.new_token("expr"))
        paths = dataclasses.replace(Paths.resolve(str(tmp_path / "s"), str(tmp_path / "r"), None, None), creds_dir=d)
        app = RunnerApp(cfg, paths, CredStore(d), client_factory=lambda c, tok: CollectorClient(f"http://127.0.0.1:{fake.port}", None, tok)).start()
        try:
            assert wait_for(lambda: app.correlator is not None and app.correlator.auth_failed)
            s = app.snapshot()
            assert s["status"] == "degraded" and "token" in s["detail"]
        finally:
            app.stop()
    finally:
        fake.stop()


def test_correlation_disabled_idles_and_reports_ok(tmp_path):
    doc = base_config()
    doc["correlation"]["enabled"] = False
    cfg = parse_config(doc)
    paths = Paths.resolve(str(tmp_path / "s"), str(tmp_path / "r"), None, None)
    app = RunnerApp(cfg, paths, CredStore(None)).start()
    try:
        assert app.snapshot()["status"] == "ok" and app.receiver is None
    finally:
        app.stop()


# ------------------------------------------------------------------------------------------- health
def test_read_health_missing_stale_and_garbage(tmp_path):
    p = tmp_path / "health.json"
    assert health_mod.read_health(p)["status"] == "fail"
    health_mod.write_snapshot(p, {"schema": health_mod.SNAPSHOT_SCHEMA, "at": 100.0, "started": 50.0, "status": "ok", "detail": "", "metrics": {}, "facts": {}})
    assert health_mod.read_health(p, now=110.0)["status"] == "ok"
    assert health_mod.read_health(p, now=400.0)["status"] == "fail"
    p.write_text("not json")
    assert health_mod.read_health(p)["status"] == "fail"
    p.write_text(json.dumps({"schema": health_mod.SNAPSHOT_SCHEMA, "at": time.time(), "status": "weird"}))
    assert health_mod.read_health(p)["status"] == "fail"


def test_health_document_validates_against_the_contract(tmp_path):
    from exp_common import config as exp_config
    doc = health_mod.health_doc("ok", "", 5, {"correlations_per_hour": 2})
    assert exp_config.iter_errors(doc, "health") == []
    assert set(health_mod.METRIC_KEYS) <= set(doc["metrics"])


# --------------------------------------------------------------------------------------------- CLI
def run_cli(*args, env=None, timeout=60):
    e = {**os.environ, "PYTHONPATH": ""}
    e.pop("CREDENTIALS_DIRECTORY", None)
    e.update(env or {})
    return subprocess.run([sys.executable, str(BIN), *args], capture_output=True, text=True, timeout=timeout, env=e)


def write_cfg(tmp_path, doc=None):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(doc or base_config()))
    return p


def test_cli_version():
    r = run_cli("version")
    assert r.returncode == 0 and r.stdout.startswith("exp-runner ") and "\n" == r.stdout[-1]
    assert cli.main(["version"]) == 0


def test_cli_invalid_config_is_refused_with_reasons(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"schema": "exp.runner.config/1"}))
    r = run_cli("run", "--config", str(p), "--state-dir", str(tmp_path / "s"), "--run-dir", str(tmp_path / "r"))
    assert r.returncode == 78 and "refusing to start" in r.stderr and "runner_id" in r.stderr
    h = run_cli("health", "--json", "--config", str(p), "--run-dir", str(tmp_path / "r"))
    assert h.returncode == 1 and json.loads(h.stdout)["status"] == "fail"


def test_cli_health_without_daemon_fails_and_with_snapshot_passes(tmp_path):
    cfg = write_cfg(tmp_path)
    r = run_cli("health", "--json", "--config", str(cfg), "--run-dir", str(tmp_path / "r"))
    d = json.loads(r.stdout)
    assert r.returncode == 1 and d["status"] == "fail" and d["schema"] == "exp.health/1" and len(r.stdout) < 64 * 1024
    (tmp_path / "r").mkdir()
    health_mod.write_snapshot(tmp_path / "r" / "health.json", {"schema": health_mod.SNAPSHOT_SCHEMA, "at": time.time(), "started": time.time() - 9,
                                                              "status": "degraded", "detail": "collector unreachable",
                                                              "metrics": {"correlations_per_hour": 4}, "facts": {"inventory": []}})
    r2 = run_cli("health", "--json", "--config", str(cfg), "--run-dir", str(tmp_path / "r"))
    d2 = json.loads(r2.stdout)
    assert r2.returncode == 0 and d2["status"] == "degraded" and d2["metrics"]["correlations_per_hour"] == 4 and 8 <= d2["uptime_s"] <= 12
    r3 = run_cli("health", "--config", str(cfg), "--run-dir", str(tmp_path / "r"))
    assert r3.returncode == 0 and r3.stdout.startswith("degraded")


def test_cli_selftest_reports_each_check(tmp_path):
    cfg = write_cfg(tmp_path)
    r = run_cli("selftest", "--config", str(cfg), "--state-dir", str(tmp_path / "s"), "--run-dir", str(tmp_path / "r"),
                "--creds-dir", str(tmp_path / "nocreds"))
    assert "ok   config" in r.stdout and "ok   syslog ring" in r.stdout and "FAIL credentials" in r.stdout and r.returncode == 1
    d = creds(tmp_path, exp_ids.new_token("expr"))
    r2 = run_cli("selftest", "--config", str(cfg), "--state-dir", str(tmp_path / "s"), "--run-dir", str(tmp_path / "r"), "--creds-dir", str(d))
    assert "ok   credentials" in r2.stdout and r2.returncode == 0, r2.stdout


def test_cli_run_starts_writes_health_and_stops_cleanly_on_sigterm(tmp_path):
    doc = base_config()
    doc["correlation"]["enabled"] = False
    cfg = write_cfg(tmp_path, doc)
    env = {**os.environ, "PYTHONPATH": ""}
    p = subprocess.Popen([sys.executable, str(BIN), "run", "--config", str(cfg), "--state-dir", str(tmp_path / "s"), "--run-dir", str(tmp_path / "r")],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        snap = tmp_path / "r" / "health.json"
        assert wait_for(snap.exists, timeout=20)
        h = run_cli("health", "--json", "--config", str(cfg), "--run-dir", str(tmp_path / "r"))
        assert h.returncode == 0 and json.loads(h.stdout)["status"] == "ok"
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=20)
        assert p.returncode == 0 and out == "", (out, err)
    finally:
        if p.poll() is None:
            p.kill()


def test_cli_run_with_full_correlation_and_no_creds_is_degraded_not_crashing(tmp_path):
    doc = base_config()
    doc["correlation"]["sources"]["syslog"]["listen"] = ["udp:15514"]
    cfg = write_cfg(tmp_path, doc)
    env = {**os.environ, "PYTHONPATH": ""}
    p = subprocess.Popen([sys.executable, str(BIN), "run", "--config", str(cfg), "--state-dir", str(tmp_path / "s"), "--run-dir", str(tmp_path / "r"),
                          "--creds-dir", str(tmp_path / "creds")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        def degraded():
            r = run_cli("health", "--json", "--config", str(cfg), "--run-dir", str(tmp_path / "r"))
            try:
                return json.loads(r.stdout)["status"] == "degraded"
            except ValueError:
                return False
        assert wait_for(degraded, timeout=25)
        assert p.poll() is None
        p.send_signal(signal.SIGTERM)
        p.communicate(timeout=20)
        assert p.returncode == 0
    finally:
        if p.poll() is None:
            p.kill()
