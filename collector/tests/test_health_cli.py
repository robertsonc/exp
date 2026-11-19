"""`exp-collector health --json` (exp.health/1), days_to_full, version/selftest/vm-args/reflector, run + SIGTERM."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from colhelpers import FakeVM, check_schema_file, https, ingest, rec, wait_for
from exp_common import tlspin

from exp_collector.health import METRIC_KEYS, days_to_full, empty_metrics, evaluate

EXE = str(Path(__file__).resolve().parents[1] / "bin" / "exp-collector")


def cli(env, *args: str, cfg: Path | None = None, timeout: float = 30, extra_env: dict | None = None):
    path = cfg or (env.tmp / "config.json")
    path.write_text(json.dumps(env.cfg_doc))
    argv = [sys.executable, EXE, *args, "--config", str(path), "--state-dir", str(env.state),
            "--run-dir", str(env.run), "--creds-dir", str(env.creds)]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, **(extra_env or {})})


def health(env, timeout: float = 5.0) -> tuple[int, dict]:
    t0 = time.monotonic()
    r = cli(env, "health", "--json", timeout=timeout)
    assert time.monotonic() - t0 < 5
    assert len(r.stdout.encode()) <= 64 * 1024
    return r.returncode, json.loads(r.stdout)


def test_health_json_ok_validates_and_has_every_contract_key(env, vm):
    app = env.start()
    port = app.address[1]
    ingest(port, env.ingest_token, [rec(), rec(), rec()])
    assert wait_for(lambda: app.vm.up and vm.count() >= 3, 10)
    assert wait_for(lambda: app.monitor.metrics["vm_up"] == 1, 5)
    time.sleep(0.8)                                       # let the monitor write a fresh snapshot
    code, doc = health(env)
    check_schema_file("health.schema.json", doc)
    assert doc["status"] == "ok" and code == 0, doc
    assert set(METRIC_KEYS) <= set(doc["metrics"])
    m = doc["metrics"]
    assert m["probes_total"] == 3 and m["probes_reporting"] == 1 and m["vm_up"] == 1
    assert m["vm_backlog_points"] == 0 and m["ingest_records_per_s"] > 0 and m["storage_free_gb"] > 0
    assert m["days_to_full"] is None                      # no growth history yet
    assert doc["facts"]["listen"] == "10.32.98.25:8443"   # the configured listen (config fixture)
    assert doc["facts"]["tls_fingerprint_sha256"] == tlspin.fingerprint_of_pem_file(env.cert)
    assert doc["uptime_s"] >= 0 and doc["version"] == "0.1.0"
    blob = json.dumps(doc)
    for secret in (env.ingest_token, env.dash_token):
        assert secret not in blob
    _check_component_facts(doc["facts"])


def _check_component_facts(facts: dict) -> None:
    """The manager rejects a whole status report when a component's facts are malformed
    (CR-wp4-status-component-facts), so the facts of a real health run must satisfy status.schema.json."""
    from colhelpers import REGISTRY
    from jsonschema import Draft202012Validator
    v = Draft202012Validator({"$ref": "status.schema.json#/$defs/component/properties/facts"}, registry=REGISTRY)
    errs = [f"{list(e.path)}: {e.message[:120]}" for e in v.iter_errors(facts)]
    assert not errs, errs
    assert {"listen", "tls_fingerprint_sha256"} <= set(facts)
    import re
    assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", facts["tls_fingerprint_sha256"])
    assert re.fullmatch(r"[^:]+:\d{1,5}", facts["listen"])


def test_health_degraded_when_vm_down_and_exit_nonzero(env, vm):
    vm.mode = "503"
    app = env.start()
    ingest(app.address[1], env.ingest_token, [rec()])
    assert wait_for(lambda: app.vm.backlog_points >= 1 and app.monitor.collect()["vm_up"] == 0, 10)
    time.sleep(0.8)
    code, doc = health(env)
    check_schema_file("health.schema.json", doc)
    assert doc["status"] == "degraded" and code == 1
    assert "VictoriaMetrics" in doc["detail"] and doc["metrics"]["vm_backlog_points"] >= 1
    vm.mode = "up"
    assert wait_for(lambda: health(env)[1]["status"] == "ok", 30)


def test_health_fails_when_the_daemon_is_not_running(env):
    code, doc = health(env)                                # no snapshot at all
    check_schema_file("health.schema.json", doc)
    assert code == 1 and doc["status"] == "fail" and "not running" in doc["detail"]
    assert set(METRIC_KEYS) <= set(doc["metrics"])


def test_health_fails_on_stale_snapshot(env):
    app = env.start()
    assert wait_for(lambda: health(env)[0] == 0, 20)
    snap = json.loads((env.run / "health.json").read_text())
    app.monitor.stop()                                     # snapshot removed on stop; write an old one by hand
    snap["written_at"] = time.time() - 120
    (env.run / "health.json").write_text(json.dumps(snap))
    code, doc = health(env)
    assert code == 1 and doc["status"] == "fail"


def test_health_rejects_symlinked_or_garbage_snapshot(env):
    (env.run / "real.json").write_text("{}")
    os.symlink(env.run / "real.json", env.run / "health.json")
    assert health(env)[1]["status"] == "fail"
    os.unlink(env.run / "health.json")
    (env.run / "health.json").write_text("not json")
    assert health(env)[1]["status"] == "fail"


def test_health_invalid_config_is_fail_not_crash(env, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    r = subprocess.run([sys.executable, EXE, "health", "--json", "--config", str(bad)], capture_output=True,
                       text=True, timeout=10)
    doc = json.loads(r.stdout)
    assert r.returncode == 1 and doc["status"] == "fail" and "invalid config" in doc["detail"]
    check_schema_file("health.schema.json", doc)


def test_evaluate_thresholds():
    m = empty_metrics()
    m["storage_free_gb"] = 100.0
    assert evaluate(m, []) == ("ok", "")
    assert evaluate(m, ["x"])[0] == "degraded"
    m["storage_free_gb"] = 1.0
    assert evaluate(m, [])[0] == "degraded"
    m["storage_free_gb"] = 0.1
    assert evaluate(m, [])[0] == "fail"
    m["storage_free_gb"] = 100.0
    m["days_to_full"] = 1.5
    assert evaluate(m, [])[0] == "degraded"


def test_days_to_full_free_over_24h_average_growth():
    now = 1_000_000.0
    gb = 1024.0 ** 3
    # 10 GB growth over 12 h -> 20 GB/day; 100 GB free -> 5 days
    samples = [(now - 12 * 3600, 50 * gb), (now - 6 * 3600, 55 * gb), (now, 60 * gb)]
    assert days_to_full(100 * gb, samples, now) == pytest.approx(5.0)
    assert days_to_full(100 * gb, [(now - 3600, 60 * gb), (now, 60 * gb)], now) is None      # no growth
    assert days_to_full(100 * gb, [(now - 3600, 61 * gb), (now, 60 * gb)], now) is None      # shrinking
    assert days_to_full(100 * gb, [(now, 60 * gb)], now) is None                            # too little history
    assert days_to_full(100 * gb, [(now - 60, 1 * gb), (now, 2 * gb)], now) is None         # window < 10 min
    old = [(now - 30 * 3600, 0.0), (now - 25 * 3600, 1.0 * gb), (now - 3600, 60 * gb), (now, 60 * gb)]
    assert days_to_full(100 * gb, old, now) is None                                         # >24 h samples ignored


def test_days_to_full_is_reported_by_the_monitor(env):
    app = env.start()
    now = time.time()
    gb = 1024.0 ** 3
    app.monitor._samples = [(now - 3600, 1 * gb), (now - 1, 1.5 * gb)]
    app.monitor._last_sample = now                        # suppress a new sample
    m = app.monitor.collect()
    assert m["days_to_full"] is not None and m["days_to_full"] > 0


def test_version_and_reflector_disabled_stub(env):
    r = subprocess.run([sys.executable, EXE, "version"], capture_output=True, text=True, timeout=10)
    assert r.stdout.strip() == "exp-collector 0.1.0" and r.returncode == 0
    env.cfg_doc["reflector"]["enabled"] = False
    r = cli(env, "reflector")
    assert r.returncode == 0 and r.stdout.strip() == "reflector disabled"
    env.cfg_doc["reflector"]["enabled"] = True
    r = cli(env, "reflector")
    assert r.returncode == 0 and "not implemented" in r.stdout


def test_selftest_passes_on_a_good_environment(env, tmp_path):
    fake_vm = tmp_path / "victoria-metrics"
    fake_vm.write_text("#!/bin/sh\nexit 0\n")
    fake_vm.chmod(0o755)
    env.cfg_doc["listen"] = "127.0.0.1:8443"
    r = cli(env, "selftest", "--vm-binary", str(fake_vm))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "FAIL" not in r.stdout and "sqlite store + dedupe" in r.stdout
    r = cli(env, "selftest", "--vm-binary", str(tmp_path / "missing"))
    assert r.returncode == 1 and "FAIL victoria-metrics binary" in r.stdout


def test_selftest_detects_wildcard_and_bad_key(env, tmp_path):
    env.cfg_doc["listen"] = "0.0.0.0:8443"
    os.chmod(env.key, 0o644)
    r = cli(env, "selftest")
    assert r.returncode == 1 and "FAIL listen address" in r.stdout and "FAIL tls key/cert" in r.stdout


def test_vm_args_come_from_validated_config_not_the_unit(env):
    env.cfg_doc["retention"]["metrics_days"] = 45
    env.cfg_doc["vm"] = {"listen": "127.0.0.1:18428", "memory_allowed_pct": 33}
    r = cli(env, "vm-args")
    assert r.returncode == 0
    assert r.stdout.split() == ["-httpListenAddr=127.0.0.1:18428", "-retentionPeriod=45d",
                                f"-storageDataPath={env.state}/vm", "-memory.allowedPercent=33",
                                "-search.maxQueryDuration=10s", "-search.maxSeries=500"]


def test_vm_exec_execs_the_binary_with_those_args(env, tmp_path):
    out = tmp_path / "argv.txt"
    fake = tmp_path / "vm"
    fake.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {out}\n")
    fake.chmod(0o755)
    r = cli(env, "vm-exec", "--binary", str(fake))
    assert r.returncode == 0, r.stderr
    assert out.read_text().split() == cli(env, "vm-args").stdout.split()
    r = cli(env, "vm-exec", "--binary", str(tmp_path / "nope"))
    assert r.returncode == 1


def test_vm_exec_refuses_invalid_config_and_vm_must_be_loopback(env, tmp_path):
    env.cfg_doc["vm"] = {"listen": "10.0.0.5:8428"}
    r = cli(env, "vm-args")
    assert r.returncode == 78 and "refusing to start" in r.stderr


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d.pop("collector_id"), "collector_id"),
    (lambda d: d.update(schema="exp.collector.config/2"), "schema"),
    (lambda d: d.update(listen="not a hostport"), "listen"),
    (lambda d: d["ingest"].update(max_records=5000), "max_records"),
    (lambda d: d["ingest"].update(max_body_mb=64), "max_body_mb"),
    (lambda d: d["retention"].update(records_days=0), "records_days"),
])
def test_invalid_config_refuses_to_start_with_the_reason(env, mutate, needle):
    mutate(env.cfg_doc)
    r = cli(env, "run")
    assert r.returncode == 78, r.stderr
    assert "refusing to start" in r.stderr and needle in r.stderr


def test_duplicate_probe_in_config_refused(env):
    env.cfg_doc["probes"].append(dict(env.cfg_doc["probes"][0]))
    r = cli(env, "run")
    assert r.returncode == 78 and "listed twice" in r.stderr


def test_run_end_to_end_as_a_process_and_sigterm_shutdown(env, vm):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    env.cfg_doc["listen"] = f"127.0.0.1:{port}"
    env.cfg_doc["vm"] = {"listen": f"127.0.0.1:{vm.port}", "memory_allowed_pct": 40}
    cfg = env.tmp / "config.json"
    cfg.write_text(json.dumps(env.cfg_doc))
    p = subprocess.Popen([sys.executable, EXE, "run", "--config", str(cfg), "--state-dir", str(env.state),
                          "--run-dir", str(env.run), "--creds-dir", str(env.creds)],
                         stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert wait_for(lambda: p.poll() is not None or _up(port), 20), "collector did not come up"
        assert p.poll() is None
        r = ingest(port, env.ingest_token, [rec(), rec()])
        assert r.status == 200 and r.json()["accepted"] == 2
        assert wait_for(lambda: vm.count() == 2, 10)
        time.sleep(0.5)
        assert wait_for(lambda: (env.run / "health.json").exists(), 8)
        assert wait_for(lambda: health(env)[0] == 0, 20)
        assert os.stat(env.state / "records.db").st_mode & 0o077 == 0
        p.send_signal(signal.SIGTERM)
        assert p.wait(timeout=30) == 0
    finally:
        if p.poll() is None:
            p.kill()
        p.communicate(timeout=10)
    assert not (env.run / "health.json").exists()
    from exp_collector.store import Store
    s2 = Store(env.state / "records.db").open()
    assert s2.count_records() == 2
    s2.close()


def _up(port: int) -> bool:
    try:
        return https(port, "GET", "/healthz", timeout=2).status == 200
    except OSError:
        return False


def test_run_refuses_to_start_without_tls_material(env):
    os.unlink(env.key)
    env.cfg_doc["listen"] = "127.0.0.1:18443"
    r = cli(env, "run")
    assert r.returncode == 1 and "cannot start" in r.stderr


def test_unit_fakevm_fixture_sanity():
    v = FakeVM()
    v.stop()


# ------------------------------------------------------------ per-probe rows (CR-wp5-fleet-api-gaps item 2)
def test_health_reports_per_probe_rows(env, vm):
    app = env.start()
    port = app.address[1]
    ingest(port, env.ingest_token, [rec(), rec(), rec(test="probe_self", metrics={"clock_offset_ms": 3.25})])
    assert wait_for(lambda: app.vm.up and vm.count() >= 3, 10)
    app.monitor.stop()
    app.monitor.write_snapshot()
    code, doc = health(env)
    check_schema_file("health.schema.json", doc)
    rows = doc["metrics"]["probes"]
    assert [r["probe_id"] for r in rows] == ["probe-a1"]            # only probes that delivered
    r = rows[0]
    assert r["records_per_min"] == 3 and r["clock_offset_ms"] in (3.2, 3.3)
    assert r["last_seen"].endswith("Z")
    assert set(r) == {"probe_id", "last_seen", "records_per_min", "clock_offset_ms"}


def test_probe_rows_window_and_bounds(env):
    from exp_collector.config import ProbeEntry
    app = env.start()
    ing = app.ingestor
    clock = [1_000_000.0]
    ing._now = lambda: clock[0]
    ing._note_seen("probe-a1", [type("M", (), {"ts": "2026-01-01T00:00:00.000Z", "agent_ver": None,
                                              "test": "ping", "metrics": {}})()] * 5, 0)
    assert ing.probe_rows()[0]["records_per_min"] == 5
    assert ing.probe_rows()[0]["clock_offset_ms"] is None
    clock[0] += 61
    assert ing.probe_rows()[0]["records_per_min"] == 0               # the 60 s window moved on
    # bounds: <= limit rows and <= max_bytes of JSON, sorted by id
    probes = {f"p{i:04d}": ProbeEntry(f"p{i:04d}", "hall-b", "") for i in range(600)}
    object.__setattr__(ing.config, "probes", probes)
    for pid in probes:
        ing.last_seen[pid] = clock[0]
    rows = ing.probe_rows()
    assert len(rows) == 500 and rows[0]["probe_id"] == "p0000"
    assert len(json.dumps(rows, separators=(",", ":"))) < 52000
    assert len(ing.probe_rows(limit=3)) == 3
    assert len(ing.probe_rows(max_bytes=1000)) < 12


def test_health_document_with_500_probes_stays_under_64kib(env):
    from exp_collector.config import ProbeEntry
    app = env.start()
    app.monitor.stop()                                    # no background snapshot may overwrite ours
    ing = app.ingestor
    probes = {f"probe-{i:03d}-long-name-x": ProbeEntry(f"probe-{i:03d}-long-name-x", "hall-b", "") for i in range(500)}
    object.__setattr__(ing.config, "probes", probes)
    now = time.time()
    for pid in probes:
        ing.last_seen[pid] = now
        ing.clock_offset_ms[pid] = -12.3456
    app.monitor.write_snapshot()
    code, doc = health(env)
    assert len(json.dumps(doc)) < 64 * 1024
    assert 400 <= len(doc["metrics"]["probes"]) <= 500
    check_schema_file("health.schema.json", doc)
