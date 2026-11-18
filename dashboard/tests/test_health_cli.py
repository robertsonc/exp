"""health --json, CLI behaviour, config refusal, process-level run, both entry-script layouts."""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from exp_common import config as cfg
from exp_common import tlspin

from conftest import ROOT, Client, free_port

BIN = ROOT / "dashboard" / "bin" / "exp-dashboard"


def cli(world, *args: str, timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BIN), *args, "--config", str(world.config_path), "--state-dir", str(world.state_dir),
         "--creds-dir", str(world.creds), "--run-dir", str(world.run_dir), "--tls-cert", str(world.cert),
         "--tls-key", str(world.key)], capture_output=True, text=True, timeout=timeout, check=False,
        env={**os.environ, "PYTHONPATH": ""})


def test_health_json_matches_contract(world):
    t0 = time.time()
    p = cli(world, "health", "--json")
    assert time.time() - t0 < 5
    assert p.returncode == 0, p.stdout + p.stderr
    assert len(p.stdout) <= 64 * 1024
    doc = json.loads(p.stdout)
    cfg.validate(doc, "health.schema.json")
    assert doc["schema"] == "exp.health/1" and doc["status"] == "ok"
    assert set(doc["metrics"]) >= {"sessions_active", "requests_per_min", "sse_clients", "collectors_total",
                                   "collectors_reachable", "login_failures_1h"}
    assert doc["metrics"]["collectors_total"] == 3 and doc["metrics"]["collectors_reachable"] == 3
    assert doc["facts"]["tls_fingerprint_sha256"] == tlspin.fingerprint_of_pem_file(world.cert)
    assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", doc["facts"]["tls_fingerprint_sha256"])
    assert doc["facts"]["url"] == "https://10.32.98.30"
    assert doc["uptime_s"] >= 0 and doc["version"]


def test_health_metrics_move(world):
    c = world.as_user("vera")
    c.get("/api/v1/probes")
    world.client().post("/auth/login", json_body={"username": "vera", "password": "bad"})
    m = json.loads(cli(world, "health", "--json").stdout)["metrics"]
    assert m["sessions_active"] == 1 and m["login_failures_1h"] == 1 and m["requests_per_min"] >= 3


def test_health_degraded_when_collector_down_and_no_secrets(world):
    world.fakes["col-c"].stop()
    world.as_user("vera").get("/api/v1/probes")
    p = cli(world, "health", "--json")
    doc = json.loads(p.stdout)
    assert doc["status"] == "degraded" and "col-c" in doc["detail"] and p.returncode == 1
    blob = p.stdout + p.stderr
    from conftest import DASH_TOKEN
    for secret in (DASH_TOKEN, world.noc_token, "alice-pass-1", world.hashes["alice"]):
        assert secret not in blob
    assert not re.search(r"exp[aeidn]_[A-Za-z0-9_-]{20}", blob)


def test_health_when_service_not_running(world):
    world.app.stop()
    world.app = None
    p = cli(world, "health", "--json")
    doc = json.loads(p.stdout)
    assert p.returncode == 1 and doc["status"] == "fail" and "not running" in doc["detail"]
    cfg.validate(doc, "health.schema.json")
    assert doc["facts"]["tls_fingerprint_sha256"] and doc["facts"]["url"]


def test_health_socket_is_private(world):
    sock = world.run_dir / "health.sock"
    assert sock.is_socket() and (sock.stat().st_mode & 0o777) == 0o600


def test_version_and_selftest(world):
    v = subprocess.run([sys.executable, str(BIN), "version"], capture_output=True, text=True, timeout=30)
    assert v.returncode == 0 and v.stdout.strip() == (ROOT / "VERSION").read_text().strip()
    p = cli(world, "selftest")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "FAIL" not in p.stdout and "ok   pbkdf2" in p.stdout


def test_selftest_fails_without_certificate(world):
    p = subprocess.run([sys.executable, str(BIN), "selftest", "--config", str(world.config_path), "--state-dir",
                        str(world.state_dir), "--creds-dir", str(world.creds), "--tls-cert", "/nonexistent.pem",
                        "--tls-key", "/nonexistent.key"], capture_output=True, text=True, timeout=30)
    assert p.returncode == 1 and "FAIL tls-certificate" in p.stdout


def test_invalid_config_refuses_to_start(world, tmp_path):
    doc = json.loads(world.config_path.read_text())
    doc["auth"]["session_hours"] = 100000
    del doc["collectors"][0]["site"]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc))
    for sub in ("run", "health", "selftest"):
        p = subprocess.run([sys.executable, str(BIN), sub, "--config", str(bad), "--state-dir", str(tmp_path / "s"),
                            "--creds-dir", str(world.creds), "--run-dir", str(tmp_path / "r")],
                           capture_output=True, text=True, timeout=30)
        if sub == "selftest":
            assert p.returncode == 1
        else:
            assert p.returncode == 78 and "refusing to start" in p.stderr, (sub, p.stderr)
    missing = subprocess.run([sys.executable, str(BIN), "run", "--config", str(tmp_path / "nope.json")],
                             capture_output=True, text=True, timeout=30)
    assert missing.returncode == 78 and "refusing to start" in missing.stderr
    junk = tmp_path / "junk.json"
    junk.write_text("{not json")
    p = subprocess.run([sys.executable, str(BIN), "run", "--config", str(junk)], capture_output=True, text=True,
                       timeout=30)
    assert p.returncode == 78


def test_duplicate_collector_ids_refused(world, tmp_path):
    doc = json.loads(world.config_path.read_text())
    doc["collectors"].append(dict(doc["collectors"][0]))
    bad = tmp_path / "dup.json"
    bad.write_text(json.dumps(doc))
    p = subprocess.run([sys.executable, str(BIN), "run", "--config", str(bad), "--state-dir", str(tmp_path / "s")],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 78 and "duplicate collector_id" in p.stderr


def test_run_refuses_without_certificate(world, tmp_path):
    world.app.stop()
    world.app = None
    p = subprocess.run([sys.executable, str(BIN), "run", "--config", str(world.config_path), "--state-dir",
                        str(tmp_path / "s2"), "--creds-dir", str(world.creds), "--run-dir", str(tmp_path / "r2")],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 1 and "cannot start" in p.stderr


def test_run_as_a_process_serves_and_stops_on_sigterm(world, tmp_path):
    world.app.stop()
    world.app = None
    https, http = free_port(), free_port()
    doc = json.loads(world.config_path.read_text())
    doc["listen"] = {"https": f"127.0.0.1:{https}", "http_redirect": f"127.0.0.1:{http}"}
    cfgp = tmp_path / "proc.json"
    cfgp.write_text(json.dumps(doc))
    proc = subprocess.Popen([sys.executable, str(BIN), "run", "--config", str(cfgp), "--state-dir", str(tmp_path / "ps"),
                             "--creds-dir", str(world.creds), "--run-dir", str(tmp_path / "pr"), "--tls-cert",
                             str(world.cert), "--tls-key", str(world.key)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        c = Client(https)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                if c.get("/healthz").status == 200:
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise AssertionError("dashboard process did not come up")
        assert c.login("vera", "vera-pass-1").status == 200
        assert c.get("/api/v1/probes").json()["items"]
        # sessions persisted in the state dir of the process
        assert (tmp_path / "ps" / "sessions.db").exists()
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=20)
        assert proc.returncode == 0, err
        assert "vera-pass-1" not in out + err and "exp" not in re.findall(r"exp[aeidn]_[A-Za-z0-9_-]{20}", out + err)
        assert not (tmp_path / "pr" / "health.sock").exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()


def test_entry_script_works_in_tarball_layout(tmp_path):
    root = tmp_path / "exp-dashboard-9.9.9"
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    (root / "vendor").mkdir()
    shutil.copy(BIN, root / "bin" / "exp-dashboard")
    shutil.copytree(ROOT / "dashboard" / "exp_dashboard", root / "lib" / "exp_dashboard",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "shared" / "python" / "exp_common", root / "lib" / "exp_common",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "shared" / "schemas", root / "lib" / "exp_common" / "schemas")
    (root / "VERSION").write_text("9.9.9\n")
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "EXP_SCHEMAS_DIR")}
    v = subprocess.run([sys.executable, str(root / "bin" / "exp-dashboard"), "version"], capture_output=True,
                       text=True, timeout=30, env=env)
    assert v.stdout.strip() == "9.9.9", v.stderr
    p = subprocess.run([sys.executable, str(root / "bin" / "exp-dashboard"), "hash-password", "--iterations",
                        "100000"], input="pw\n", capture_output=True, text=True, timeout=30, env=env)
    assert p.stdout.startswith("pbkdf2_sha256$100000$")
    # packaged static files live inside the package
    assert (root / "lib" / "exp_dashboard" / "static" / "index.html").is_file()


def test_entry_script_is_executable_with_the_agreed_shebang():
    assert os.access(BIN, os.X_OK)
    assert BIN.read_text().splitlines()[0] == "#!/usr/bin/python3"


def test_requirements_apt_is_within_the_allowlist():
    allowed = {"busybox", "busybox-static", "iproute2", "iputils-ping", "iperf3", "curl", "openssl",
               "ca-certificates", "ethtool", "iw", "wpasupplicant", "tcpdump"}
    lines = [x.strip() for x in (ROOT / "dashboard" / "requirements.apt").read_text().splitlines() if x.strip()]
    assert set(lines) <= allowed
    _ = Path
