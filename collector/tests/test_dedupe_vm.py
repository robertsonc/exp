"""Acceptance 2 (dedupe survives a restart) and 3 (VM down: ingest keeps accepting, the backlog is
persisted in SQLite and drains oldest-first on recovery)."""
from __future__ import annotations

import time

from colhelpers import FakeVM, ingest, rec, wait_for

from exp_collector.store import Store
from exp_collector.vmwriter import VMWriter, point_to_line


def test_replaying_a_spool_after_restart_stores_nothing_twice(env, vm):
    app = env.start()
    batch = [rec(test="dns", metrics={"rtt_ms": float(i)}) for i in range(20)]
    r = ingest(app.address[1], env.ingest_token, batch)
    assert r.json()["accepted"] == 20
    assert wait_for(lambda: vm.count() == 20, 6)
    app.stop()
    env.apps.clear()
    app2 = env.start()                       # restart: new process-equivalent, same state dir
    r = ingest(app2.address[1], env.ingest_token, batch + [rec()])   # probe replays its spool + 1 new
    body = r.json()
    assert (body["accepted"], body["duplicates"], body["rejected"]) == (1, 20, [])
    assert app2.store.count_records() == 21
    # duplicates are not re-sent to VM either
    time.sleep(1.6)
    assert vm.count() == 21


def test_same_id_for_different_probes_is_not_a_duplicate(env):
    app = env.start()
    a = rec(probe="probe-a1")
    b = dict(a, probe="probe-a2")
    assert ingest(app.address[1], env.ingest_token, [a]).json()["accepted"] == 1
    assert ingest(app.address[1], env.ingest_token2, [b]).json()["accepted"] == 1
    assert app.store.count_records() == 2


def test_duplicate_inside_one_batch(env):
    app = env.start()
    a = rec()
    r = ingest(app.address[1], env.ingest_token, [a, a, a])
    assert (r.json()["accepted"], r.json()["duplicates"]) == (1, 2)


def test_vm_down_ingest_keeps_accepting_and_backlog_drains(env, vm):
    app = env.start()
    port = app.address[1]
    vm.mode = "503"                                   # VM is down
    sent: list[dict] = []
    for _ in range(6):
        batch = [rec(test="dns", metrics={"rtt_ms": float(len(sent) + i)}) for i in range(10)]
        sent += batch
        r = ingest(port, env.ingest_token, batch)
        assert r.status == 200 and r.json()["accepted"] == 10      # still accepted
        time.sleep(0.4)
    # END STATE while VM is down: every record is in SQLite, the points are in vm_backlog, none in VM
    assert app.store.count_records() == 60
    assert wait_for(lambda: app.vm.backlog_points >= 1, 5)
    assert vm.count() == 0
    assert not app.vm.up
    assert wait_for(lambda: app.monitor.collect()["vm_up"] == 0, 3)
    # recovery
    vm.mode = "up"
    assert wait_for(lambda: vm.count() == 60, 30), (vm.count(), app.vm.backlog_points)
    assert wait_for(lambda: app.vm.backlog_points == 0, 10)
    assert app.store.backlog_points() == 0 and app.store.backlog_peek() == []
    assert app.vm.up
    # no gaps: every sample made it, exactly once per (value, timestamp)
    got = sorted((ln["values"][0], ln["timestamps"][0]) for ln in vm.lines)
    want = sorted((float(r["metrics"]["rtt_ms"]),
                   int(__import__("exp_common.schema", fromlist=["x"]).iso_to_ms(r["ts"]))) for r in sent)
    assert got == want


def test_backlog_survives_a_collector_restart(env, vm):
    app = env.start()
    vm.mode = "503"
    ingest(app.address[1], env.ingest_token, [rec(metrics={"rtt_ms": 1.0}) for _ in range(5)])
    assert wait_for(lambda: app.store.backlog_points() == 5, 8)
    app.stop()
    env.apps.clear()
    vm.mode = "up"
    app2 = env.start()
    assert app2.vm.backlog_points == 5                # picked up from SQLite at start
    assert wait_for(lambda: vm.count() == 5, 15)
    assert wait_for(lambda: app2.store.backlog_points() == 0, 10)


def test_backlog_drains_oldest_first(tmp_path, vm):
    store = Store(tmp_path / "t.db").open()
    try:
        for i in range(5):
            store.backlog_append(point_to_line("exp_x_v", {"probe": "p"}, float(i), 1000 + i) + "\n")
        w = VMWriter(vm.url, store, flush_interval=0.05)
        w.start()
        assert wait_for(lambda: vm.count() == 5, 10)
        w.stop()
        assert [ln["values"][0] for ln in vm.lines] == [0.0, 1.0, 2.0, 3.0, 4.0]
        assert store.backlog_points() == 0
    finally:
        store.close()


def test_vm_permanent_rejection_drops_chunk_instead_of_blocking(tmp_path, vm):
    store = Store(tmp_path / "t.db").open()
    try:
        vm.mode = "400"
        w = VMWriter(vm.url, store, flush_interval=0.05)
        w.start()
        w.enqueue_lines([point_to_line("exp_x_v", {"probe": "p"}, 1.0, 1000)])
        assert wait_for(lambda: w.points_dropped == 1, 5)
        assert store.backlog_points() == 0 and w.up
        w.stop()
    finally:
        store.close()


def test_vm_connection_refused_then_restart_on_same_port(env):
    vm1 = FakeVM()
    port = vm1.port
    env.vm_url = vm1.url
    app = env.start()
    vm1.stop()                                         # VM process gone entirely: connection refused
    ingest(app.address[1], env.ingest_token, [rec(metrics={"rtt_ms": 3.0})])
    assert wait_for(lambda: app.vm.backlog_points == 1, 8)
    assert not app.vm.up
    vm2 = FakeVM(port=port)
    try:
        assert wait_for(lambda: vm2.count() == 1, 30)
        assert wait_for(lambda: app.vm.up and app.vm.backlog_points == 0, 10)
    finally:
        vm2.stop()


def test_backpressure_429_when_vm_queue_full_and_when_sqlite_lags(env, vm):
    app = env.start()
    port = app.address[1]
    assert ingest(port, env.ingest_token, [rec()]).status == 200
    app.vm.queue_limit = -1                            # queue "over 200k": any content exceeds it
    r = ingest(port, env.ingest_token, [rec()])
    assert r.status == 429 and r.h("Retry-After") and int(r.h("Retry-After")) >= 1
    assert r.json()["error"]["code"] == "rate_limited"
    from colhelpers import check_openapi
    check_openapi("ingest", "/measurements", "post", 429, r.json())
    assert app.store.count_records() == 1                # refused batches store nothing
    app.vm.queue_limit = 200_000
    assert ingest(port, env.ingest_token, [rec()]).status == 200
    app.store.lag_s = lambda: 6.0                         # SQLite writer lagging > 5 s
    r = ingest(port, env.ingest_token, [rec()])
    assert r.status == 429 and r.h("Retry-After")
    assert app.store.count_records() == 2


def test_vm_backlog_cap_signals_backpressure(env):
    app = env.start()
    app.vm.backlog_limit = 0
    app.vm._backlog_points = 1
    assert ingest(app.address[1], env.ingest_token, [rec()]).status == 429
