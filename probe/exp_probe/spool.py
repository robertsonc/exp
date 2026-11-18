"""The spool (02-probe.md section 6): SQLite (WAL), every measurement is written here BEFORE any send.

Table ``spool(id TEXT PRIMARY KEY, ts TEXT, body BLOB)``. Records are shipped oldest-first by
insertion order (the implicit rowid -- never VACUUM, which may renumber it; space is reused by SQLite
and bounded by the byte cap below). Bounded by ``max_mb`` (payload bytes) and ``max_days`` (by the
record's ``ts``): on overflow the OLDEST records are dropped first and counted in ``dropped_total``,
which survives restarts (``meta`` table).
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from exp_common.ids import is_ulid
from exp_common.schema import iso_to_ms

log = logging.getLogger(__name__)

MAX_LINE_BYTES = 60 * 1024          # ingest accepts 64 KiB per line; keep headroom
PER_ROW_OVERHEAD = 64               # id + ts + sqlite row header, for the byte accounting
DROP_CHUNK = 500


class SpoolError(Exception):
    pass


def _ms_to_iso(ms: int) -> str:
    t = time.gmtime(ms / 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", t) + f".{int(ms % 1000):03d}Z"


class Spool:
    def __init__(self, path: str | Path, max_mb: int = 500, max_days: int = 7,
                 clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self.max_bytes = int(max_mb) * 1024 * 1024
        self.max_days = int(max_days)
        self.clock = clock
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = self._open()
        self._depth, self._bytes = self._count()
        self.dropped_total = int(self._meta_get("dropped_total", 0))
        self.write_errors = 0

    # ------------------------------------------------------------------------------ open/close
    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.path), timeout=10, check_same_thread=False, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("CREATE TABLE IF NOT EXISTS spool (id TEXT PRIMARY KEY, ts TEXT NOT NULL, body BLOB NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        db.execute("SELECT count(*) FROM spool").fetchone()
        return db

    def _open(self) -> sqlite3.Connection:
        try:
            return self._connect()
        except sqlite3.DatabaseError as exc:
            # a corrupt spool must not stop measuring: set it aside (never delete) and start fresh
            aside = self.path.with_name(f"{self.path.name}.corrupt-{int(self.clock())}")
            log.error("spool %s is unreadable (%s); moved to %s", self.path, exc, aside.name)
            for suffix in ("", "-wal", "-shm"):
                src = Path(str(self.path) + suffix)
                if src.exists():
                    src.rename(Path(str(aside) + suffix))
            return self._connect()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _count(self) -> tuple[int, int]:
        row = self._db.execute(
            "SELECT count(*), coalesce(sum(length(body) + ?), 0) FROM spool", (PER_ROW_OVERHEAD,)).fetchone()
        return int(row[0]), int(row[1])

    def _meta_get(self, key: str, default: Any) -> Any:
        row = self._db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row[0] if row else default

    def _meta_set(self, key: str, value: Any) -> None:
        self._db.execute("INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                         (key, str(value)))

    # ------------------------------------------------------------------------------------ write
    def add(self, record: dict[str, Any] | bytes) -> bool:
        """Persist one measurement (dict with `id` and `ts`, or its JSON bytes). Returns False when the
        record is refused (oversized/malformed) -- it is logged and counted, never raised."""
        return self.add_many([record]) == 1

    def add_many(self, records: Iterable[dict[str, Any] | bytes]) -> int:
        rows: list[tuple[str, str, bytes]] = []
        for rec in records:
            try:
                doc = json.loads(rec) if isinstance(rec, (bytes, bytearray)) else rec
                body = bytes(rec) if isinstance(rec, (bytes, bytearray)) else json.dumps(
                    doc, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
                rid, ts = doc["id"], doc["ts"]
                if not is_ulid(rid) or not isinstance(ts, str) or b"\n" in body:
                    raise ValueError("id must be a ULID, ts a string, and the body one line")
                iso_to_ms(ts)
                if len(body) > MAX_LINE_BYTES:
                    raise ValueError(f"record is {len(body)} bytes (max {MAX_LINE_BYTES})")
            except (ValueError, KeyError, TypeError) as exc:
                self.write_errors += 1
                log.error("spool refused a record: %s", exc)
                continue
            rows.append((rid, ts, body))
        if not rows:
            return 0
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                added = 0
                for rid, ts, body in rows:
                    cur = self._db.execute("INSERT OR IGNORE INTO spool(id, ts, body) VALUES(?,?,?)", (rid, ts, body))
                    if cur.rowcount:
                        added += 1
                        self._depth += 1
                        self._bytes += len(body) + PER_ROW_OVERHEAD
                self._db.execute("COMMIT")
            except sqlite3.Error as exc:
                self.write_errors += 1
                self._rollback()
                self._depth, self._bytes = self._count_safe()
                log.error("spool write failed: %s", exc)
                return 0
            self.enforce_bounds()
            return added

    def _rollback(self) -> None:
        try:
            self._db.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _count_safe(self) -> tuple[int, int]:
        try:
            return self._count()
        except sqlite3.Error:
            return self._depth, self._bytes

    # ------------------------------------------------------------------------------------ read
    def fetch(self, limit: int = 500) -> list[tuple[str, bytes]]:
        """Oldest-first (by arrival) up to `limit` records: [(id, body)]."""
        with self._lock:
            rows = self._db.execute("SELECT id, body FROM spool ORDER BY rowid LIMIT ?", (int(limit),)).fetchall()
        return [(r[0], bytes(r[1])) for r in rows]

    def delete(self, ids: Iterable[str]) -> int:
        ids = list(ids)
        n = 0
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                for i in range(0, len(ids), 500):
                    chunk = ids[i:i + 500]
                    marks = ",".join("?" * len(chunk))
                    freed = self._db.execute(
                        "SELECT count(*), coalesce(sum(length(body) + ?), 0) "  # noqa: S608 - placeholders only
                        f"FROM spool WHERE id IN ({marks})", [PER_ROW_OVERHEAD, *chunk]).fetchone()
                    cur = self._db.execute(f"DELETE FROM spool WHERE id IN ({marks})", chunk)  # noqa: S608
                    n += cur.rowcount
                    self._depth -= int(freed[0])
                    self._bytes -= int(freed[1])
                self._db.execute("COMMIT")
            except sqlite3.Error as exc:
                self._rollback()
                log.error("spool delete failed: %s", exc)
                self._depth, self._bytes = self._count_safe()
                return 0
        return n

    def oldest_ts(self) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT ts FROM spool ORDER BY rowid LIMIT 1").fetchone()
        return row[0] if row else None

    def push_lag_s(self, now: float | None = None) -> float:
        """now - ts of the oldest unshipped record (0 when the spool is empty)."""
        ts = self.oldest_ts()
        if ts is None:
            return 0.0
        try:
            return max(0.0, (now if now is not None else self.clock()) - iso_to_ms(ts) / 1000.0)
        except ValueError:
            return 0.0

    def stat(self) -> dict[str, Any]:
        with self._lock:
            return {"depth": self._depth, "bytes": self._bytes, "oldest_ts": self.oldest_ts(),
                    "dropped_total": self.dropped_total, "max_bytes": self.max_bytes,
                    "max_days": self.max_days, "write_errors": self.write_errors}

    # -------------------------------------------------------------------------------- bounds
    def enforce_bounds(self) -> int:
        """Drop oldest records beyond max_days / max_mb. Returns the number dropped."""
        dropped = 0
        with self._lock:
            try:
                cutoff = _ms_to_iso(int((self.clock() - self.max_days * 86400) * 1000))
                # by age: oldest-by-arrival first; stop at the first record that is young enough
                while True:
                    old = self._db.execute(
                        "SELECT rowid FROM spool WHERE ts < ? ORDER BY rowid LIMIT ?", (cutoff, DROP_CHUNK)).fetchall()
                    if not old:
                        break
                    dropped += self._drop_rowids([r[0] for r in old])
                    if len(old) < DROP_CHUNK:
                        break
                # by size: down to 90% so we do not trim on every insert
                if self._bytes > self.max_bytes:
                    target = int(self.max_bytes * 0.9)
                    while self._bytes > target and self._depth > 0:
                        rows = self._db.execute(
                            "SELECT rowid FROM spool ORDER BY rowid LIMIT ?", (DROP_CHUNK,)).fetchall()
                        if not rows:
                            break
                        dropped += self._drop_rowids([r[0] for r in rows])
            except sqlite3.Error as exc:
                log.error("spool bound enforcement failed: %s", exc)
            if dropped:
                self.dropped_total += dropped
                self._meta_set("dropped_total", self.dropped_total)
                log.warning("spool over its bounds: dropped %d oldest records (dropped_total=%d)",
                            dropped, self.dropped_total)
        return dropped

    def _drop_rowids(self, rowids: list[int]) -> int:
        marks = ",".join("?" * len(rowids))
        freed = self._db.execute(
            "SELECT count(*), coalesce(sum(length(body) + ?), 0) "  # noqa: S608 - placeholders only
            f"FROM spool WHERE rowid IN ({marks})", [PER_ROW_OVERHEAD, *rowids]).fetchone()
        cur = self._db.execute(f"DELETE FROM spool WHERE rowid IN ({marks})", rowids)  # noqa: S608
        self._depth -= int(freed[0])
        self._bytes -= int(freed[1])
        return cur.rowcount


def read_stat(path: str | Path) -> dict[str, Any] | None:
    """Read-only stat of a spool file (for `spool stat` and `health`, which run beside the daemon)."""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        db = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=3)
    except sqlite3.Error:
        return None
    try:
        depth, size = db.execute("SELECT count(*), coalesce(sum(length(body) + ?), 0) FROM spool",
                                 (PER_ROW_OVERHEAD,)).fetchone()
        row = db.execute("SELECT ts FROM spool ORDER BY rowid LIMIT 1").fetchone()
        try:
            d = db.execute("SELECT v FROM meta WHERE k='dropped_total'").fetchone()
        except sqlite3.Error:
            d = None
        return {"depth": int(depth), "bytes": int(size), "oldest_ts": row[0] if row else None,
                "dropped_total": int(d[0]) if d else 0, "file_bytes": p.stat().st_size}
    except sqlite3.Error as exc:
        log.warning("cannot read spool %s: %s", p, exc)
        return None
    finally:
        db.close()
