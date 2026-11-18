"""Observer hook (rules engine / SSE attach here in later steps), self-telemetry series, concurrency."""
from __future__ import annotations

import threading

from colhelpers import ingest, rec, wait_for


def test_observers_get_only_accepted_records_after_they_are_durable(env, app, port):
    seen: list[list[str]] = []
    durable_at_callback: list[bool] = []

    def cb(records):
        seen.append([m.id for m in records])
        durable_at_callback.append(all(app.store.read_records(m.probe, 0, 2**62) for m in records))

    app.ingestor.subscribe(cb)
    app.ingestor.subscribe(lambda recs: 1 / 0)             # a failing observer must not break ingest
    a, b = rec(), rec()
    bad = rec(probe="probe-a2")
    r = ingest(port, env.ingest_token, [a, b, bad, a])
    assert r.status == 200 and r.json()["accepted"] == 2 and r.json()["duplicates"] == 1
    assert seen == [[a["id"], b["id"]]] and durable_at_callback == [True]
    ingest(port, env.ingest_token, [a])                    # pure duplicate -> no callback
    assert len(seen) == 1


def test_self_telemetry_series_reach_vm(env, app, port, vm):
    ingest(port, env.ingest_token, [rec(), rec(), rec(probe="probe-a2")])
    ingest(port, env.ingest_token, [rec(test="probe_self", metrics={"clock_offset_ms": 12.5, "spool_depth": 0})])
    app.telemetry.emit_once()
    assert wait_for(lambda: vm.count("exp_collector_ingest_records_total") == 3, 8), vm.names()
    got = {ln["metric"]["result"]: ln["values"][0] for ln in vm.lines
           if ln["metric"]["__name__"] == "exp_collector_ingest_records_total"}
    assert got == {"accepted": 3.0, "duplicate": 0.0, "rejected": 1.0}
    names = set(vm.names())
    assert {"exp_collector_ingest_bytes_total", "exp_collector_vm_backlog_points", "exp_collector_sse_clients",
            "exp_collector_rules_eval_ms", "exp_collector_probe_clock_offset_ms"} <= names
    off = [ln for ln in vm.lines if ln["metric"]["__name__"] == "exp_collector_probe_clock_offset_ms"][0]
    assert off["metric"]["probe"] == "probe-a1" and off["values"] == [12.5]


def test_parallel_ingest_with_overlap_stores_each_record_once(env, app, port):
    pool = [rec() for _ in range(60)]
    results: list[dict] = []
    lock = threading.Lock()

    def worker(k: int) -> None:
        for off in range(0, 60, 10):
            r = ingest(port, env.ingest_token, pool[(off + k) % 60:(off + k) % 60 + 10] or pool[:10])
            assert r.status == 200
            with lock:
                results.append(r.json())
    ts = [threading.Thread(target=worker, args=(k,)) for k in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert app.store.count_records() == 60
    assert sum(r["accepted"] for r in results) == 60        # exactly one winner per record
    assert wait_for(lambda: app.vm.queue_points == 0, 10)


def test_stats_windows(env, app, port):
    ingest(port, env.ingest_token, [rec(), rec()])
    ingest(port, env.ingest_token, [b"{bad", rec(probe="probe-a2")])
    w = app.ingestor.stats.window(60)
    assert w["accepted"] == 2 and w["rejected"] == 2 and w["bytes"] > 0
    assert app.ingestor.stats.totals["accepted"] == 2
