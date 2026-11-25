"""Spool (02-probe.md section 6): durable, ordered, bounded; drops oldest first and counts it."""
from __future__ import annotations

import sqlite3
import threading

from exp_common.ids import new_ulid
from fakes import FakeClock

from exp_probe import spool as spool_mod
from exp_probe.spool import Spool

# Records carry a fixed timestamp, so every spool here runs on a clock pinned to that day. With the real clock the
# 7-day age bound drops them once the date is a week old (they failed on 2026-11-25T20:00Z for exactly that reason).
REC_EPOCH = 1795032000.0   # 2026-11-18T20:00:00Z


def _spool(path, **kw):
    kw.setdefault("clock", FakeClock(REC_EPOCH))
    return Spool(path, **kw)


def rec(ts="2026-11-18T20:00:00.000Z", pad=0, rid=None):
    return {"schema": "exp.measurement/1", "id": rid or new_ulid(), "ts": ts, "test": "gateway", "x": "y" * pad}


def test_roundtrip_order_and_delete(tmp_path):
    s = _spool(tmp_path / "s.db")
    rs = [rec(rid=new_ulid(1_700_000_000_000 + i)) for i in range(50)]
    assert s.add_many(rs) == 50
    got = s.fetch(500)
    assert [i for i, _ in got] == [r["id"] for r in rs]                  # insertion order
    assert s.stat()["depth"] == 50 and s.stat()["bytes"] > 0
    assert s.delete([i for i, _ in got[:10]]) == 10
    assert [i for i, _ in s.fetch(5)] == [r["id"] for r in rs[10:15]]
    assert s.stat()["depth"] == 40
    s.delete([i for i, _ in s.fetch(500)])
    assert s.stat() == {**s.stat(), "depth": 0, "bytes": 0, "oldest_ts": None}


def test_is_sqlite_wal_with_the_documented_table(tmp_path):
    p = tmp_path / "s.db"
    _spool(p).add(rec())
    db = sqlite3.connect(p)
    assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    cols = {r[1]: r[2] for r in db.execute("PRAGMA table_info(spool)")}
    assert cols == {"id": "TEXT", "ts": "TEXT", "body": "BLOB"}
    assert db.execute("SELECT count(*) FROM spool").fetchone()[0] == 1


def test_duplicate_id_is_stored_once(tmp_path):
    s = _spool(tmp_path / "s.db")
    r = rec()
    assert s.add(r) is True and s.add(r) is False        # second one is ignored (same id)
    assert s.stat()["depth"] == 1


def test_survives_restart(tmp_path):
    p = tmp_path / "s.db"
    a = _spool(p)
    ids = [rec()["id"] for _ in range(3)]
    for i in ids:
        a.add(rec(rid=i))
    a.close()
    b = _spool(p)
    assert [i for i, _ in b.fetch(10)] == ids and b.stat()["depth"] == 3


def test_size_bound_drops_oldest_first_and_counts(tmp_path):
    clock = FakeClock(1_795_000_000.0)                                    # 2026-11-18 area
    s = Spool(tmp_path / "s.db", max_mb=1, max_days=3650, clock=clock)
    ids = []
    for _ in range(40):                                                   # ~40 x 50 KiB = 2 MB > 1 MiB
        r = rec(ts="2026-11-17T00:00:00.000Z", pad=50_000)
        ids.append(r["id"])
        s.add(r)
    st = s.stat()
    assert st["bytes"] <= s.max_bytes and st["dropped_total"] > 0
    left = [i for i, _ in s.fetch(1000)]
    assert left == ids[len(ids) - len(left):]                              # only the NEWEST remain, in order
    assert st["depth"] + st["dropped_total"] == 40
    s.close()
    assert Spool(tmp_path / "s.db", max_mb=1, clock=clock).dropped_total == st["dropped_total"]   # persisted


def test_age_bound_drops_old_records(tmp_path):
    clock = FakeClock(1_795_000_000.0)                                    # 2026-11-18T..
    s = Spool(tmp_path / "s.db", max_mb=10, max_days=2, clock=clock)
    old = [rec(ts="2026-11-10T00:00:00.000Z") for _ in range(5)]
    new = [rec(ts="2026-11-17T23:00:00.000Z") for _ in range(3)]
    s.add_many(old + new)
    assert [i for i, _ in s.fetch(100)] == [r["id"] for r in new]
    assert s.stat()["dropped_total"] == 5


def test_oversized_and_malformed_records_refused_not_raised(tmp_path):
    s = _spool(tmp_path / "s.db")
    assert not s.add(rec(pad=spool_mod.MAX_LINE_BYTES + 10))
    assert not s.add({"id": "x"})                                          # no ts
    assert not s.add(b"not json")
    assert not s.add({"id": "a\nb", "ts": "2026-11-18T20:00:00.000Z"})
    assert not s.add({"id": new_ulid(), "ts": "yesterday"})
    assert s.stat()["depth"] == 0 and s.write_errors == 5


def test_corrupt_spool_is_set_aside_not_deleted(tmp_path):
    p = tmp_path / "s.db"
    p.write_bytes(b"this is not an sqlite database" * 100)
    s = _spool(p)
    assert s.add(rec()) and s.stat()["depth"] == 1
    assert list(tmp_path.glob("s.db.corrupt-*"))


def test_concurrent_writers(tmp_path):
    s = _spool(tmp_path / "s.db")

    def work():
        for _ in range(100):
            s.add(rec())
    ts = [threading.Thread(target=work) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert s.stat()["depth"] == 400 == len(s.fetch(1000))


def test_push_lag_and_read_stat(tmp_path):
    clock = FakeClock(1_795_000_100.0)
    s = Spool(tmp_path / "s.db", clock=clock)
    assert s.push_lag_s() == 0
    s.add(rec(ts="2026-11-18T00:00:00.000Z"))
    assert 0 < s.push_lag_s() < 10 * 86400
    st = spool_mod.read_stat(tmp_path / "s.db")
    assert st["depth"] == 1 and st["oldest_ts"] == "2026-11-18T00:00:00.000Z"
    assert spool_mod.read_stat(tmp_path / "missing.db") is None
