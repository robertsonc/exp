"""SQLite store (section 4) and pruning (hourly, batches of 10,000, incidents 90 days)."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
import time

import pytest

from exp_collector.prune import Pruner, prune_once
from exp_collector.store import SCHEMA_VERSION, RecordRow, Store, StoreError

DAY_MS = 86_400_000


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "state" / "records.db").open()
    yield s
    s.close()


def row(probe="p1", i="01AAAAAAAAAAAAAAAAAAAAAAA0", ts=1000, test="ping", outcome="ok"):
    return RecordRow(probe, i, ts, "s", test, outcome, json.dumps({"id": i}))


def ulid(n: int) -> str:
    return f"{n:026d}".replace("0", "0")  # 26 digits: only used as an opaque key here


def test_schema_is_exactly_section_4(store):
    with store.reader() as c:
        def cols(t):
            return [r[1] for r in c.execute(f"PRAGMA table_info({t})")]
        assert cols("records") == ["probe", "id", "ts_ms", "site", "test", "outcome", "body"]
        assert cols("incidents") == ["id", "probe", "site", "line", "kind", "start_ms", "end_ms", "where_json",
                                     "facts_json", "folded_into", "acked_by", "acked_at"]
        assert cols("vm_backlog") == ["seq", "payload"]
        assert cols("meta") == ["key", "value"]
        pk = [r[1] for r in c.execute("PRAGMA table_info(records)") if r[5]]
        assert pk == ["probe", "id"]
        idx = {r[1]: [x[2] for x in c.execute(f"PRAGMA index_info({r[1]})")] for r in c.execute("PRAGMA index_list(records)")
               if not r[1].startswith("sqlite_autoindex")}
        assert ["probe", "ts_ms"] in idx.values() and ["probe", "test", "ts_ms"] in idx.values()
    assert store.schema_version() == SCHEMA_VERSION == 1


def test_wal_synchronous_normal_and_private_file_mode(store):
    with store.reader() as c:
        assert c.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    mode_seen = {}

    def job(conn):
        mode_seen["sync"] = conn.execute("PRAGMA synchronous").fetchone()[0]
    store.write(job)
    assert mode_seen["sync"] == 1                       # NORMAL
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    store.insert_records([row()])
    for suffix in ("-wal", "-shm"):
        p = str(store.path) + suffix
        if os.path.exists(p):
            assert stat.S_IMODE(os.stat(p).st_mode) & 0o077 == 0


def test_all_writes_run_on_one_thread(store):
    seen = set()

    def job(conn):
        seen.add(threading.get_ident())
    ts = [threading.Thread(target=lambda: [store.write(job) for _ in range(20)]) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(seen) == 1 and threading.get_ident() not in seen


def test_failing_job_does_not_poison_others_in_the_same_transaction(store):
    def bad(conn):
        conn.execute("INSERT INTO records VALUES('x','a',1,'s','t','ok','{}')")
        raise RuntimeError("boom")

    results: list = []

    def good(i):
        results.append(store.insert_records([row(i=f"{i:026d}")]))
    threads = [threading.Thread(target=good, args=(i,)) for i in range(10)]
    [t.start() for t in threads]
    with pytest.raises(RuntimeError):
        store.write(bad)
    [t.join() for t in threads]
    assert store.count_records() == 10                  # the failing job's insert was rolled back
    with store.reader() as c:
        assert c.execute("SELECT COUNT(*) FROM records WHERE probe='x'").fetchone()[0] == 0


def test_dedupe_is_per_probe_and_id(store):
    assert store.insert_records([row("p1", "A"), row("p1", "A"), row("p2", "A")]) == [True, False, True]
    assert store.count_records() == 2


def test_time_window_reads_and_cursor(store):
    store.insert_records([row("p1", f"{i:026d}", ts=1000 + i, test="dns" if i % 2 else "ping",
                              outcome="fail" if i % 3 == 0 else "ok") for i in range(30)])
    got = store.read_records("p1", 1005, 1010)
    assert [t for t, _, _ in got] == list(range(1005, 1011))
    assert len(store.read_records("p1", 0, 2000, test="dns")) == 15
    assert len(store.read_records("p1", 0, 2000, outcome="fail")) == 10
    page1 = store.read_records("p1", 0, 2000, limit=7)
    page2 = store.read_records("p1", 0, 2000, limit=7, after=(page1[-1][0], page1[-1][1]))
    assert page1[-1][0] + 1 == page2[0][0] and len(page2) == 7
    assert store.read_records("nobody", 0, 2000) == []
    assert store.newest_ts_ms("p1") == 1029


def test_migration_is_idempotent_and_newer_schema_refused(tmp_path):
    p = tmp_path / "d.db"
    s = Store(p).open()
    s.insert_records([row()])
    s.close()
    s = Store(p).open()                                   # reopen: no re-migration, data intact
    assert s.count_records() == 1 and s.schema_version() == 1
    s.close()
    c = sqlite3.connect(p)
    c.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    c.commit()
    c.close()
    with pytest.raises(StoreError, match="newer"):
        Store(p).open()


def test_prune_records_in_batches_by_cutoff(store):
    now = time.time()
    old = int((now - 10 * 86400) * 1000)
    new = int((now - 1 * 86400) * 1000)
    store.insert_records([row("p1", f"{i:026d}", ts=old + i) for i in range(250)])
    store.insert_records([row("p2", f"{i:026d}", ts=old + i) for i in range(30)])
    store.insert_records([row("p1", f"{1000 + i:026d}", ts=new + i) for i in range(40)])
    batches: list[int] = []
    orig = store.write

    def spy(fn, timeout=60.0):
        res = orig(fn, timeout)
        if isinstance(res, int) and res:
            batches.append(res)
        return res
    store.write = spy
    res = prune_once(store, records_days=7, now=now, batch=100)
    assert res["records"] == 280
    assert store.count_records() == 40                    # only recent rows remain
    assert max(batches) <= 100 and len([b for b in batches if b == 100]) == 2   # p1: 100,100,50 ; p2: 30


def test_default_batch_size_is_10000():
    from exp_collector.store import PRUNE_BATCH
    assert PRUNE_BATCH == 10_000


def test_prune_incidents_keeps_90_days_and_open_ones(store):
    now = time.time()
    def inc(i, start_days_ago, end_days_ago):
        s = int((now - start_days_ago * 86400) * 1000)
        e = None if end_days_ago is None else int((now - end_days_ago * 86400) * 1000)
        def job(c):
            c.execute("INSERT INTO incidents(id,probe,site,line,kind,start_ms,end_ms) VALUES(?,?,?,?,?,?,?)",
                      (i, "p1", "s", "dns", "down", s, e))
        store.write(job)
    inc("old-closed", 120, 119)
    inc("recent-closed", 30, 29)
    inc("old-open", 200, None)
    res = prune_once(store, 7, now=now)
    assert res["incidents"] == 1
    with store.reader() as c:
        left = {r[0] for r in c.execute("SELECT id FROM incidents")}
    assert left == {"recent-closed", "old-open"}


def test_pruner_thread_runs_once_on_demand(store):
    store.insert_records([row("p1", "A", ts=1)])
    p = Pruner(store, 7)
    assert p.run_once() == {"records": 1, "incidents": 0} and p.last_run is not None


def test_prune_now_cli(env, tmp_path):
    import subprocess
    import sys
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps(env.cfg_doc))
    s = Store(env.state / "records.db").open()
    s.insert_records([row("p1", "A", ts=1000), row("p1", "B", ts=int(time.time() * 1000))])
    s.close()
    exe = os.path.join(os.path.dirname(__file__), "..", "bin", "exp-collector")
    r = subprocess.run([sys.executable, exe, "prune", "--now", "--config", str(cfg), "--state-dir", str(env.state)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and json.loads(r.stdout) == {"records": 1, "incidents": 0}, r.stderr
    s = Store(env.state / "records.db").open()
    assert s.count_records() == 1
    s.close()
    r = subprocess.run([sys.executable, exe, "prune", "--config", str(cfg), "--state-dir", str(env.state)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2                              # refuses to prune without --now
