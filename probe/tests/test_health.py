"""`exp-probe health --json` (exp.health/1): healthy criteria of 02-probe.md section 9."""
from __future__ import annotations

import json

import fake_collector
import fakes_common
from conftest import make_config
from exp_common import config as exp_config
from fakes import FakeClock, FakeIp, Link

from exp_probe import cli, health, lease
from exp_probe.selftel import Stats, StatusWriter, build_measurement
from exp_probe.shipper import Shipper
from exp_probe.spool import Spool

PORTS = [{"id": "c01", "iface": "t0", "role": "client"}, {"id": "c02", "iface": "t1", "role": "client"}]
COLLECTOR = {"url": "https://10.32.98.25:8443", "tls_fingerprint_sha256": "AA:" * 31 + "AA", "fallback": []}
BOUND = {"interface": "t0", "ip": "10.1.0.31", "mask": "24", "router": "10.1.0.1", "dns": "10.1.0.2", "lease": "600"}


class Env:
    def __init__(self, paths, collector=COLLECTOR, ports=PORTS, now=1_795_000_000.0):
        self.paths = paths
        self.cfg = make_config(probe_id="probe-a1", ports=ports, collector=collector)
        self.ip = FakeIp()
        self.clock = FakeClock(now)
        for i, p in enumerate(ports):
            self.ip.ns[f"exp-{p['id']}"] = {"lo": Link("lo", up=True), p["iface"]: Link(p["iface"], up=True, rx=10_000 * (i + 1))}
            if p["role"] == "client":
                lease.hook(self.cfg, "bound", {**BOUND, "interface": p["iface"]}, self.ip, paths)
        self.spool = Spool(paths.state_dir / "spool.db", clock=self.clock)
        self.stats = Stats(self.clock)
        self.ship = {"state": "ok", "collector_reachable": True, "last_ok": now - 1, "detail": ""}
        self.writer = StatusWriter(paths, self.cfg, self.stats, self.spool, lambda: self.ship, self.clock)
        self.ip.calls.clear()
        self.ip.mutations.clear()

    def beat(self, outcome="ok", port="c01", test="gateway"):
        m = build_measurement(self.cfg, test, outcome, labels={"port": port},
                              error="boom" if outcome in ("error", "fail") else None)
        self.stats.record(m)
        self.spool.add(m.to_dict())

    def health(self):
        self.writer.write(force=True)
        return health.collect(self.cfg, None, self.ip, self.paths, self.clock())


def test_healthy_probe_document_matches_the_contract(paths):
    e = Env(paths)
    for _ in range(3):
        e.beat()
    e.beat("fail", "c02", "dns_hb")
    doc = e.health()
    assert exp_config.iter_errors(doc, "health") == []
    assert doc["schema"] == "exp.health/1" and doc["status"] == "ok" and doc["detail"] == ""
    m, f = doc["metrics"], doc["facts"]
    for key in ("measurements_per_min", "by_test_per_min", "fail_per_min", "error_per_min", "spool_depth", "spool_bytes",
                "push_lag_s", "clock_offset_ms", "skipped_per_hour", "ports"):
        assert key in m, key
    assert m["measurements_per_min"] == 4 and m["by_test_per_min"] == {"gateway": 3, "dns_hb": 1} and m["fail_per_min"] == 1
    assert m["spool_depth"] == 4
    assert f == {"collector_reachable": True, "collector_url": COLLECTOR["url"], "mode": "netns",
                 "shipper_state": "ok", "tls_pin_mismatch": False, "auth_failed": False}
    p = {x["id"]: x for x in m["ports"]}
    assert p["c01"]["iface"] == "t0" and p["c01"]["link"] == "up" and p["c01"]["leased"] is True
    assert p["c01"]["ip"] == "10.1.0.31" and p["c01"]["gateway"] == "10.1.0.1" and p["c01"]["role"] == "client"
    assert p["c01"]["last"] == {"network": "ok"} and p["c02"]["last"] == {"dns": "fail"}
    for k in ("rx_pps", "tx_pps", "rx_bps", "tx_bps", "rx_errors", "tx_errors", "rx_drops", "tx_drops"):
        assert k in p["c01"]
    # counters are read INSIDE each namespace
    assert ["ip", "-n", "exp-c01", "-s", "-j", "link", "show", "dev", "t0"] in e.ip.calls
    assert e.ip.mutations == []


def test_rates_are_deltas_since_the_daemons_last_sample(paths):
    e = Env(paths)
    snap = health.counters_snapshot(e.ip, e.cfg, e.clock())
    e.writer.counters = lambda: snap
    e.ip.ns["exp-c01"]["t0"].rx += 80_000                   # 80 kB more received
    e.clock.advance(10)
    e.ship["last_ok"] = e.clock() - 1
    doc = e.health()
    c01 = next(x for x in doc["metrics"]["ports"] if x["id"] == "c01")
    assert c01["rx_bps"] == 80_000 * 8 / 10 and c01["rx_pps"] == 80_000 / 100 / 10
    e.ip.ns["exp-c01"]["t0"].rx = 5                           # counter reset (link reset): null, never negative
    doc = health.collect(e.cfg, None, e.ip, e.paths, e.clock())
    assert next(x for x in doc["metrics"]["ports"] if x["id"] == "c01")["rx_bps"] is None


def test_daemon_not_running_is_a_failure(paths):
    e = Env(paths)
    doc = health.collect(e.cfg, None, e.ip, paths, e.clock())
    assert doc["status"] == "fail" and "daemon is not running" in doc["detail"] and health.exit_code(doc) == 1
    e.writer.write(force=True)
    e.clock.advance(120)
    doc = health.collect(e.cfg, None, e.ip, paths, e.clock())
    assert doc["status"] == "fail" and "status is" in doc["detail"]


def test_missing_namespace_or_port_is_a_failure(paths):
    e = Env(paths)
    del e.ip.ns["exp-c02"]
    doc = e.health()
    assert doc["status"] == "fail" and "namespace exp-c02 is missing" in doc["detail"]
    e2 = Env(paths)
    del e2.ip.ns["exp-c01"]["t0"]
    assert "port c01 (t0) is not present in exp-c01" in e2.health()["detail"]


def test_port_without_lease_needs_an_explanation(paths):
    e = Env(paths)
    lease.hook(e.cfg, "deconfig", {"interface": "t0"}, e.ip, paths)
    doc = e.health()
    assert doc["status"] == "fail" and "no lease and no recent error" in doc["detail"]
    e.beat("error", "c01", "dhcp_hb")                          # a recent error record explains it
    doc = e.health()
    assert doc["status"] == "degraded" and "boom" in doc["detail"] and health.exit_code(doc) == 0
    e.clock.advance(300)
    e.ship["last_ok"] = e.clock() - 1
    e.writer.write(force=True)
    assert health.collect(e.cfg, None, e.ip, paths, e.clock())["status"] == "fail"       # explanation went stale


def test_collector_down_but_spool_accepting_is_degraded_and_healthy(paths):
    e = Env(paths)
    e.ship.update(state="unreachable", collector_reachable=False, last_ok=e.clock() - 1000)
    for _ in range(5):
        e.beat()
    doc = e.health()
    assert doc["status"] == "degraded" and "collector unreachable; spooling" in doc["detail"]
    assert doc["facts"]["collector_reachable"] is False and health.exit_code(doc) == 0


def test_no_collector_configured_is_degraded_not_failed(paths):
    e = Env(paths, collector=None)
    e.ship.update(state="no_collector", collector_reachable=None, last_ok=None)
    doc = e.health()
    assert doc["status"] == "degraded" and "collector_url" not in doc["facts"] and health.exit_code(doc) == 0
    # regression (e2e m2): a null collector_url made the document invalid exp.health/1, so the agent refused the
    # first probe start (the manager compiles a probe without collector until the collector has reported)
    from exp_common import config as exp_config

    exp_config.validate(doc, "health.schema.json")


def test_shipper_stuck_with_backlog_fails(paths):
    e = Env(paths)
    m = build_measurement(e.cfg, "gateway", "ok", labels={"port": "c01"}, ts="2026-11-17T00:00:00.000Z")
    e.spool.add(m.to_dict())
    e.ship.update(state="ok", last_ok=e.clock() - 500)
    doc = e.health()
    assert doc["status"] == "fail" and "has not pushed" in doc["detail"]
    assert doc["metrics"]["push_lag_s"] > 120


def test_invalid_config_still_answers(paths):
    doc = health.collect(None, "probe.json: invalid config: mode must be netns|host", FakeIp(), paths)
    assert doc["status"] == "fail" and "config invalid" in doc["detail"] and exp_config.iter_errors(doc, "health") == []


def test_tls_pin_mismatch_is_reported_by_health(paths, tmp_path):
    srv = fake_collector.start(tls=True, state_dir=tmp_path / "col")
    try:
        e = Env(paths, collector={"url": f"https://127.0.0.1:{srv.port}", "tls_fingerprint_sha256": "AA:" * 31 + "AA",
                                  "fallback": []})
        e.beat()
        from exp_probe.config import Collector
        s = Shipper(Collector(e.cfg.collector.url, e.cfg.collector.fingerprint), e.spool,
                    lambda: fakes_common.fixture_token("expi", "probe-a1"), clock=e.clock)
        e.writer.shipper_status = s.status
        s.step()
        assert srv.app.requests == 0                           # NO request reached the server
        doc = e.health()
        assert doc["status"] == "fail" and "tls_pin_mismatch" in doc["detail"] and health.exit_code(doc) == 1
        assert doc["facts"]["tls_pin_mismatch"] is True and doc["facts"]["shipper_state"] == "tls_pin_mismatch"
        assert doc["facts"]["collector_reachable"] is False and doc["metrics"]["spool_depth"] == 1
    finally:
        srv.stop()


def test_auth_failed_is_reported(paths):
    e = Env(paths)
    e.ship.update(state="auth_failed", detail="collector refused the ingest token (401)", collector_reachable=True)
    doc = e.health()
    assert doc["status"] == "fail" and "auth_failed" in doc["detail"] and doc["facts"]["auth_failed"] is True


def test_output_is_bounded_and_secret_free(paths):
    e = Env(paths, ports=[{"id": f"c{i:02d}", "iface": f"t{i}", "role": "client"} for i in range(1, 65)])
    text = health.render(e.health())
    assert len(text.encode()) <= 64 * 1024 and "expi_" not in text and "expa_" not in text


def test_cli_health_json_and_exit_code(paths, tmp_path, capsys):
    e = Env(paths)
    e.writer.write(force=True)
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(e.cfg.raw))
    argv = ["health", "--json", "--config", str(cfgfile), "--state-dir", str(paths.state_dir),
            "--run-dir", str(paths.run_dir)]
    capsys.readouterr()
    rc = cli.main(argv, runner=e.ip)
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema"] == "exp.health/1" and rc == (0 if doc["status"] != "fail" else 1)
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert cli.main(["health", "--json", "--config", str(bad), "--run-dir", str(paths.run_dir)], runner=e.ip) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "fail"


def test_health_answers_within_its_budget_even_if_ip_hangs(paths):
    import time

    from exp_probe.runner import CmdResult

    class Slow(FakeIp):
        def run(self, argv, timeout=10, **kw):
            if "-s" in argv:
                time.sleep(1.0)
                return CmdResult(tuple(argv), 124, "", "", True)
            return super().run(argv, timeout, **kw)
    e = Env(paths, ports=[{"id": f"c{i:02d}", "iface": f"t{i}", "role": "client"} for i in range(1, 25)])
    slow = Slow()
    slow.ns = e.ip.ns
    e.writer.write(force=True)
    t0 = time.monotonic()
    doc = health.collect(e.cfg, None, slow, paths, e.clock())
    assert time.monotonic() - t0 < 5.0 and doc["status"] == "fail"
