"""Daemon wiring: measure -> spool (BEFORE any send) -> shipper -> collector; status file; clean stop."""
from __future__ import annotations

import json
import threading
import time

import fake_collector
import fakes_common
import pytest
from conftest import make_config
from fakes import FakeIp, Link

from exp_probe import scheduler
from exp_probe.daemon import Daemon


@pytest.fixture
def registered_gateway():
    saved = dict(scheduler.REGISTRY)
    scheduler.REGISTRY.clear()
    scheduler.register_test("gateway", lambda ctx: [ctx.measure("gateway", "ok", metrics={"rtt_ms": 1.0, "link_up": 1.0},
                                                                labels={"iface": ctx.port.iface})])
    yield
    scheduler.REGISTRY.clear()
    scheduler.REGISTRY.update(saved)


def build(paths, tmp_path, srv, **kw):
    creds = tmp_path / "creds"
    creds.mkdir(exist_ok=True)
    (creds / "ingest_token").write_text(fakes_common.fixture_token("expi", "probe-a1") + "\n")
    cfg = make_config(probe_id="probe-a1", site="hall-b", ports=[{"id": "c01", "iface": "t0", "role": "client"},
                                                                {"id": "c02", "iface": "t1", "role": "client"}],
                      collector={"url": f"https://127.0.0.1:{srv.port}", "tls_fingerprint_sha256": srv.fingerprint,
                                 "fallback": []}, **kw)
    ip = FakeIp()
    for n, p in (("exp-c01", "t0"), ("exp-c02", "t1")):
        ip.ns[n] = {"lo": Link("lo"), p: Link(p, up=True)}
    return Daemon(cfg, ip, paths, creds_dir=str(creds), workers=2)


def test_measurement_is_spooled_before_it_is_sent_then_delivered(paths, tmp_path, registered_gateway):
    srv = fake_collector.start(tls=True, state_dir=tmp_path / "col")
    try:
        d = build(paths, tmp_path, srv)
        depth_at_notify = []
        orig = d.shipper.notify
        d.shipper.notify = lambda: (depth_at_notify.append(d.spool.stat()["depth"]), orig())
        t = (int(time.time() // 10) + 1) * 10.0
        d.scheduler.tick(t)
        assert d.pool.wait_idle(5)
        assert depth_at_notify and all(x >= 1 for x in depth_at_notify)          # on disk before the shipper is woken
        # nothing sent yet; both ports spooled (a probe_self record may ride along on a 60 s boundary)
        assert srv.app.requests == 0 and d.spool.stat()["depth"] >= 2
        d.shipper.step()
        got = [r for r in srv.app.records if r["test"] == "gateway"]
        assert sorted(r["labels"]["port"] for r in got) == ["c01", "c02"]
        assert all(r["probe"] == "probe-a1" and r["site"] == "hall-b" and r["agent_ver"] for r in got)
        assert d.spool.stat()["depth"] == 0
        d.pool.shutdown()
    finally:
        srv.stop()


def test_invalid_measurement_is_dropped_not_spooled(paths, tmp_path, registered_gateway):
    srv = fake_collector.start(tls=True, state_dir=tmp_path / "col")
    try:
        d = build(paths, tmp_path, srv)
        from exp_common.schema import Measurement
        bad = Measurement(probe="probe-a1", test="gateway", outcome="ok", labels={"probe": "spoof"}, id="x")
        d.emitter([bad])
        assert d.spool.stat()["depth"] == 0 and d.emitter.invalid == 1
        d.pool.shutdown()
    finally:
        srv.stop()


def test_run_writes_status_and_stops_cleanly(paths, tmp_path, registered_gateway):
    srv = fake_collector.start(tls=True, state_dir=tmp_path / "col")
    try:
        d = build(paths, tmp_path, srv)
        th = threading.Thread(target=d.run)
        th.start()
        deadline = time.time() + 5
        while not paths.status_file.exists() and time.time() < deadline:
            time.sleep(0.05)
        doc = json.loads(paths.status_file.read_text())
        assert doc["schema"] == "exp.probe.status/1" and doc["probe_id"] == "probe-a1"
        assert doc["shipper"]["state"] in ("idle", "ok", "no_collector")
        d.stop.set()
        th.join(10)
        assert not th.is_alive()
        assert not paths.status_file.exists()                                    # a stopped daemon must not look alive
    finally:
        srv.stop()
