"""CLI (run / health / version / pause-internet / selftest), exp.health/1, stand-alone `run` as a real process, TLS provided."""
from __future__ import annotations

import http.client
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import fakes_common as fc
import pytest
from exp_common import config as exp_config
from exp_common import tlspin
from stbox import Box, free_port, submission, tls_ctx, wait_for

from exp_speedtest import cli, health
from exp_speedtest.daemon import RedirectApp
from exp_speedtest.httpd import HttpServer

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "speedtest" / "bin" / "exp-speedtest"


def run_cli(*args: str, env: dict | None = None, timeout: float = 20) -> subprocess.CompletedProcess:
    e = {**os.environ, "PYTHONPATH": "", **(env or {})}
    return subprocess.run([sys.executable, str(BIN), *args], capture_output=True, text=True, timeout=timeout, env=e)  # noqa: S603


def test_version_and_help():
    r = run_cli("version")
    assert r.returncode == 0 and r.stdout.startswith("exp-speedtest ")
    assert run_cli("--version").returncode == 0
    r = run_cli("--help")
    assert r.returncode == 0 and "pause-internet" in r.stdout and "health" in r.stdout
    assert run_cli("nonsense").returncode == 2


def test_selftest_passes():
    r = run_cli("selftest")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "FAIL" not in r.stdout and "PASS dns-leg authority" in r.stdout and "icmp backend:" in r.stdout


def test_run_refuses_an_invalid_config_with_exit_78(tmp_path: Path):
    bad = tmp_path / "c.json"
    bad.write_text(json.dumps({"schema": "exp.speedtest.config/1", "speedtest_id": "x"}))
    r = run_cli("run", "--config", str(bad), "--state-dir", str(tmp_path / "s"), "--run-dir", str(tmp_path / "r"))
    assert r.returncode == 78 and "refusing to start" in r.stderr and "site" in r.stderr
    r = run_cli("run", "--config", str(tmp_path / "missing.json"), "--state-dir", str(tmp_path / "s"))
    assert r.returncode == 78
    bad.write_text("{not json")
    assert run_cli("run", "--config", str(bad)).returncode == 78


def test_run_refuses_a_non_loopback_channel_address(tmp_path: Path, box: Box):
    doc = dict(box.config().raw)
    doc["local_channel"] = {"listen": "127.0.0.1:8480"}
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps(doc))
    from exp_speedtest.config import SpeedtestConfig, SpeedtestConfigError
    doc["local_channel"] = {"listen": "10.0.0.5:8480"}
    cfg.write_text(json.dumps(doc))
    assert run_cli("run", "--config", str(cfg)).returncode == 78
    with pytest.raises(SpeedtestConfigError):
        SpeedtestConfig({**doc, "local_channel": {"listen": "192.168.1.1:8480"}})


def test_health_without_a_daemon_fails_with_exit_1(tmp_path: Path, box: Box):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps(box.config().raw))
    r = run_cli("health", "--json", "--config", str(cfg), "--run-dir", str(tmp_path / "norun"), "--state-dir", str(tmp_path / "s"))
    assert r.returncode == 1
    doc = json.loads(r.stdout)
    assert doc["status"] == "fail" and "not running" in doc["detail"]
    exp_config.validate(doc, "exp.health/1")
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    r = run_cli("health", "--json", "--config", str(bad), "--run-dir", str(tmp_path / "norun"))
    assert r.returncode == 1 and "config invalid" in json.loads(r.stdout)["detail"]


def test_health_of_a_running_daemon_is_ok_or_degraded_and_matches_the_schema(box: Box):
    box.daemon.write_status()
    doc = health.collect(box.config(), None, box.paths)
    exp_config.validate(doc, "exp.health/1")
    assert doc["status"] in ("ok", "degraded") and health.exit_code(doc) == 0, doc["detail"]
    assert doc["facts"]["url"] == f"http://127.0.0.1:{box.http_port}" and doc["facts"]["tls_mode"] == "none"
    assert "tls_fingerprint_sha256" not in doc["facts"], "only when tls.mode = provided"
    assert set(doc["metrics"]) >= {"tests_per_hour", "active_tests", "queue_depth", "internet_leg_paused", "local_leg_gbps_p95",
                                    "rejected_per_hour"}
    assert len(health.render(doc)) < 64 * 1024
    assert "token" not in health.render(doc).lower().replace("tokens", "")


def test_health_degraded_and_fail_conditions(box: Box):
    box.daemon.write_status()
    base = box.daemon.status_doc()

    def collect(**mut):
        doc = json.loads(json.dumps(base))
        for k, v in mut.items():
            node = doc
            *parents, last = k.split("__")
            for p in parents:
                node = node[p]
            node[last] = v
        box.paths.run_dir.mkdir(parents=True, exist_ok=True)
        (box.paths.status_file).write_text(json.dumps(doc))
        return health.collect(box.config(), None, box.paths)
    assert collect(forwarder__state="unreachable")["status"] == "degraded"
    assert collect(listening__dns=False)["status"] == "degraded"
    assert collect(listening__channel=False)["status"] == "degraded"
    assert collect(path__backend="none")["status"] == "degraded"
    assert collect(forwarder__depth=4000)["status"] == "degraded"
    d = collect(forwarder__state="auth_failed")
    assert d["status"] == "fail" and health.exit_code(d) == 1
    assert collect(forwarder__state="tls_pin_mismatch")["status"] == "fail"
    assert collect(listening__http=False)["status"] == "fail"
    assert collect(ts=time.time() - 60)["status"] == "fail", "a stale status file means the daemon is gone"


def test_pause_internet_cli_toggles_the_running_daemon(box: Box):
    r = run_cli("pause-internet", "--on", "--state-dir", str(box.paths.state_dir))
    assert r.returncode == 0 and "paused" in r.stdout
    box.clock.advance(2)
    assert box.core.internet.state() == ("paused", "admin_pause")
    assert box.get("/st/api/v1/config").json()["internet_leg"]["paused"] is True
    r = run_cli("pause-internet", "--off", "--state-dir", str(box.paths.state_dir))
    assert r.returncode == 0 and "resumed" in r.stdout
    box.clock.advance(2)
    assert box.core.internet.state()[0] == "ok"
    assert run_cli("pause-internet", "--state-dir", str(box.paths.state_dir)).returncode == 2
    assert run_cli("pause-internet", "--on", "--off").returncode == 2
    r = run_cli("pause-internet", "--on", "--state-dir", "/proc/nonexistent/x")
    assert r.returncode == 1


def test_standalone_run_as_a_real_process_end_to_end(tmp_path: Path, box: Box):
    """`exp-speedtest run` from a local config + creds directory (no manager), then health, then SIGTERM."""
    doc = dict(box.config().raw)
    doc["serve"] = {**doc["serve"], "port": free_port()}
    doc["local_channel"] = {"listen": f"127.0.0.1:{free_port()}"}
    doc["dns_leg"] = {**doc["dns_leg"], "port": free_port(udp_too=True)}
    sa = tmp_path / "standalone"
    sa.mkdir()
    cfg = sa / "config.json"
    cfg.write_text(json.dumps(doc))
    creds, state, run = sa / "creds", sa / "state", sa / "run"
    creds.mkdir()
    (creds / "collector_token").write_text(box.fake.app.tokens["speedtest"]["spd-core"]["token"])
    (creds / "runner_channel_token_sha256").write_text("0" * 64)
    args = ["--config", str(cfg), "--creds-dir", str(creds), "--state-dir", str(state), "--run-dir", str(run),
            "--assets-dir", str(sa / "assets")]
    proc = subprocess.Popen([sys.executable, str(BIN), "run", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,  # noqa: S603
                            env={**os.environ, "PYTHONPATH": ""})
    try:
        port = doc["serve"]["port"]

        def up() -> bool:
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                c.request("GET", "/st/api/v1/config")
                return c.getresponse().status == 200
            except OSError:
                return False
        assert wait_for(up, 20), proc.stderr.read() if proc.poll() is not None else "did not start"
        assert wait_for((run / "status.json").exists, 5)
        r = run_cli("health", "--json", *args)
        assert r.returncode == 0, r.stdout
        h = json.loads(r.stdout)
        assert h["status"] in ("ok", "degraded") and h["facts"]["url"] == f"http://127.0.0.1:{port}"
        assert oct((state / "speedtest.db").stat().st_mode & 0o777) == "0o600"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_main_dispatch_in_process(capsys):
    assert cli._dispatch(cli.build_parser().parse_args(["version"])) == 0
    assert capsys.readouterr().out.startswith("exp-speedtest ")


# ------------------------------------------------------------------------------------------------ TLS provided
def test_tls_provided_serves_https_with_a_pinnable_cert_and_reports_the_fingerprint(tmp_path: Path):
    b = Box(tmp_path, cfg_over={"tls": {"mode": "provided"}})
    b.start_fake()
    b.write_creds()
    cert, key = b.cert_key
    (b.paths.creds_dir / "tls.crt").write_bytes(cert.read_bytes())
    (b.paths.creds_dir / "tls.key").write_bytes(key.read_bytes())
    b._seed_payload()
    from exp_speedtest.daemon import Daemon
    b.daemon = Daemon(b.config(), b.paths, pinger=b.pinger, clock=b.clock)
    b.daemon.start()
    try:
        c = http.client.HTTPSConnection("127.0.0.1", b.http_port, context=tls_ctx(), timeout=5)
        c.request("GET", "/st/api/v1/config")
        r = c.getresponse()
        cfg = json.loads(r.read())
        assert r.status == 200 and cfg["tls_mode"] == "provided"
        resp = tlspin.request("GET", f"https://127.0.0.1:{b.http_port}/st/api/v1/config", fc.tlspin.fingerprint_of_pem_file(cert))
        assert resp.status == 200
        # the whole flow over TLS (download uses pread+send, not sendfile)
        key_ = __import__("exp_common.speedtest", fromlist=["x"])
        from stbox import SENTINEL_ID
        k = key_.new_view_key()
        proof = key_.view_proof(k, SENTINEL_ID)
        c.request("POST", "/st/api/v1/sessions", body=json.dumps({"consent": {"text_version": 3}, "view_verifier": key_.view_verifier(proof)}))
        doc = json.loads(c.getresponse().read())
        c.request("GET", "/st/down?bytes=3000000", headers={"X-Exp-Leg-Token": doc["leg_token"]})
        r = c.getresponse()
        assert len(r.read()) == 3_000_000
        c.request("POST", f"/st/api/v1/sessions/{doc['session_id']}/result", body=json.dumps(submission()),
                  headers={"X-Exp-View-Proof": proof})
        r = c.getresponse()
        r.read()
        assert r.status == 202
        c.close()
        b.daemon.write_status()
        h = health.collect(b.config(), None, b.paths)
        assert h["facts"]["url"].startswith("https://") and h["facts"]["tls_fingerprint_sha256"] == tlspin.fingerprint_of_pem_file(cert)
        exp_config.validate(h, "exp.health/1")
        plain = http.client.HTTPConnection("127.0.0.1", b.http_port, timeout=3)
        with pytest.raises((OSError, http.client.HTTPException)):
            plain.request("GET", "/")
            plain.getresponse().read()
    finally:
        b.stop()


def test_tls_provided_without_certificate_creds_refuses_to_start(tmp_path: Path):
    b = Box(tmp_path, cfg_over={"tls": {"mode": "provided"}})
    b.start_fake()
    b.write_creds()
    b._seed_payload()
    from exp_common.creds import CredentialError

    from exp_speedtest.daemon import Daemon
    d = Daemon(b.config(), b.paths, pinger=b.pinger, clock=b.clock)
    with pytest.raises(CredentialError):
        d.start()
    d.store.close()
    b.stop()


def test_redirect_listener_uses_the_configured_hostname_never_the_host_header():
    srv = HttpServer("127.0.0.1", 0, RedirectApp("speed.summit.example", 443), name="t-redirect")
    srv.start()
    try:
        def get(target: str, host: str = "evil.example") -> http.client.HTTPResponse:
            c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=3)
            c.request("GET", target, headers={"Host": host})
            r = c.getresponse()
            r.read()
            return r
        r = get("/st/r/st_ABC?x=1")
        assert r.status == 301 and r.getheader("Location") == "https://speed.summit.example/st/r/st_ABC?x=1"
        assert get("/").getheader("Location") == "https://speed.summit.example/"
        inj = get("/%0d%0aSet-Cookie:x")
        assert inj.status == 400 and inj.getheader("Location") is None and inj.getheader("Set-Cookie") is None
        assert get("/a%20b").getheader("Location") == "https://speed.summit.example/a%20b"
        assert get("/a<b>").getheader("Location") == "https://speed.summit.example/", "unsafe characters never reach Location"
    finally:
        srv.stop()
    srv2 = HttpServer("127.0.0.1", 0, RedirectApp("speed.summit.example", 8443), name="t-redirect2")
    srv2.start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv2.port, timeout=3)
        c.request("GET", "/x")
        assert c.getresponse().getheader("Location") == "https://speed.summit.example:8443/x"
    finally:
        srv2.stop()


def test_dns_leg_bind_failure_degrades_instead_of_dying(tmp_path: Path):
    import socket
    b = Box(tmp_path)
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind(("127.0.0.1", b.dns_port))
    try:
        b.start()
        assert b.daemon.dns is None and b.core.dns_active is False
        s = b.new_session()
        assert s.doc["dns_nonces"] == [] and s.doc["dns_zone"] is None
        b.daemon.write_status()
        h = health.collect(b.config(), None, b.paths)
        assert h["status"] == "degraded" and "DNS-leg" in h["detail"]
    finally:
        blocker.close()
        b.stop()


def test_http_bind_failure_is_fatal(tmp_path: Path):
    import socket
    b = Box(tmp_path)
    b.start_fake()
    b.write_creds()
    b._seed_payload()
    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    blocker.bind(("127.0.0.1", b.http_port))
    blocker.listen(1)
    from exp_speedtest.daemon import Daemon
    d = Daemon(b.config(), b.paths, pinger=b.pinger, clock=b.clock)
    try:
        with pytest.raises(OSError):
            d.start()
    finally:
        blocker.close()
        d.store.close()
        b.stop()
