"""SQLite store (03-collector.md section 4): records, incidents, vm_backlog, meta.

WAL, ``synchronous=NORMAL``. ALL writes go through ONE writer thread fed by a queue (jobs are
grouped into one transaction, each job in its own SAVEPOINT so a failing job cannot poison the
others). Reads use a small pool of read-only connections. ``lag_s()`` is how long the oldest queued
write has been waiting -- the ingest back-pressure signal (> 5 s -> 429).
"""
from __future__ import annotations

import contextlib
import logging
import os
import queue
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, NamedTuple

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
INCIDENT_KEEP_DAYS = 90
PRUNE_BATCH = 10_000
READ_POOL = 4

MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        """CREATE TABLE records (
             probe TEXT NOT NULL, id TEXT NOT NULL, ts_ms INTEGER NOT NULL, site TEXT NOT NULL,
             test TEXT NOT NULL, outcome TEXT NOT NULL, body TEXT NOT NULL,
             PRIMARY KEY (probe, id))""",
        "CREATE INDEX records_probe_ts ON records (probe, ts_ms)",
        "CREATE INDEX records_probe_test_ts ON records (probe, test, ts_ms)",
        """CREATE TABLE incidents (
             id TEXT PRIMARY KEY, probe TEXT NOT NULL, site TEXT NOT NULL, line TEXT NOT NULL,
             kind TEXT NOT NULL, start_ms INTEGER NOT NULL, end_ms INTEGER, where_json TEXT,
             facts_json TEXT, folded_into TEXT, acked_by TEXT, acked_at INTEGER)""",
        "CREATE INDEX incidents_probe_start ON incidents (probe, start_ms)",
        "CREATE INDEX incidents_start ON incidents (start_ms)",
        "CREATE TABLE vm_backlog (seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)",
    ),
}


class StoreError(Exception):
    """The database cannot be used (newer schema, closed, writer dead)."""


class RecordRow(NamedTuple):
    probe: str
    id: str
    ts_ms: int
    site: str
    test: str
    outcome: str
    body: str


class _Job:
    __slots__ = ("fn", "enqueued", "done", "result", "exc")

    def __init__(self, fn: Callable[[sqlite3.Connection], Any]) -> None:
        self.fn = fn
        self.enqueued = time.monotonic()
        self.done = threading.Event()
        self.result: Any = None
        self.exc: BaseException | None = None


class Store:
    def __init__(self, path: str | os.PathLike[str], busy_timeout_s: float = 30.0) -> None:
        self.path = Path(path)
        self.busy_timeout_s = busy_timeout_s
        self._q: queue.Queue[_Job | None] = queue.Queue()
        self._writer: threading.Thread | None = None
        self._wconn: sqlite3.Connection | None = None
        self._readers: queue.LifoQueue[sqlite3.Connection] = queue.LifoQueue()
        self._reader_all: list[sqlite3.Connection] = []
        self._reader_lock = threading.Lock()
        self._closed = False
        self._last_lag = 0.0
        self.writer_error = ""

    # --- lifecycle ----------------------------------------------------------------------------
    def open(self) -> Store:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():  # create 0600 before SQLite does (it would honour the umask)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            os.close(fd)
        conn = self._connect(readonly=False)
        try:
            self._migrate(conn)
        except BaseException:
            conn.close()
            raise
        self._wconn = conn
        self._writer = threading.Thread(target=self._writer_loop, name="sqlite-writer", daemon=True)
        self._writer.start()
        return self

    def _connect(self, readonly: bool) -> sqlite3.Connection:
        if readonly:
            conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=self.busy_timeout_s,
                                   isolation_level=None, check_same_thread=False)
            conn.execute("PRAGMA query_only=ON")
        else:
            conn = sqlite3.connect(str(self.path), timeout=self.busy_timeout_s, isolation_level=None,
                                   check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_s * 1000)}")
        return conn

    def _migrate(self, conn: sqlite3.Connection) -> None:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
            row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            current = int(row[0]) if row else 0
            if current > SCHEMA_VERSION:
                raise StoreError(f"{self.path}: database schema version {current} is newer than this "
                                 f"collector understands ({SCHEMA_VERSION}); refusing to open it")
            for ver in range(current + 1, SCHEMA_VERSION + 1):
                for stmt in MIGRATIONS[ver]:
                    conn.execute(stmt)
                conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)", (str(ver),))
                log.info("database migrated to schema version %d", ver)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._q.put(None)
        if self._writer is not None:
            self._writer.join(timeout=30)
        if self._wconn is not None:
            with contextlib.suppress(sqlite3.Error):
                self._wconn.close()
        with self._reader_lock:
            for c in self._reader_all:
                with contextlib.suppress(sqlite3.Error):
                    c.close()
            self._reader_all.clear()

    @property
    def alive(self) -> bool:
        return (not self._closed and self._writer is not None and self._writer.is_alive()
                and not self.writer_error)

    # --- writer -------------------------------------------------------------------------------
    def _writer_loop(self) -> None:
        conn = self._wconn
        if conn is None:
            return
        while True:
            job = self._q.get()
            if job is None:
                return
            batch = [job]
            stop_after = False
            while len(batch) < 64:
                try:
                    nxt = self._q.get_nowait()
                except queue.Empty:
                    break
                if nxt is None:
                    stop_after = True
                    break
                batch.append(nxt)
            self._last_lag = time.monotonic() - batch[0].enqueued
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                self.writer_error = f"cannot begin transaction: {exc}"
                log.error("sqlite writer: %s", self.writer_error)
                for j in batch:
                    j.exc = StoreError(self.writer_error)
                    j.done.set()
                if stop_after:
                    return
                continue
            for j in batch:
                try:
                    conn.execute("SAVEPOINT job")
                    j.result = j.fn(conn)
                    conn.execute("RELEASE job")
                except BaseException as exc:  # noqa: BLE001 - delivered to the submitter
                    j.exc = exc
                    with contextlib.suppress(sqlite3.Error):
                        conn.execute("ROLLBACK TO job")
                        conn.execute("RELEASE job")
            try:
                conn.execute("COMMIT")
                self.writer_error = ""
            except sqlite3.Error as exc:
                self.writer_error = f"commit failed: {exc}"
                log.error("sqlite writer: %s", self.writer_error)
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                for j in batch:
                    j.exc = StoreError(self.writer_error)
                    j.result = None
            for j in batch:
                j.done.set()
            if stop_after:
                return

    def write(self, fn: Callable[[sqlite3.Connection], Any], timeout: float = 60.0) -> Any:
        """Run ``fn(conn)`` on the writer thread inside a transaction; return its result or raise."""
        if self._closed or self._writer is None:
            raise StoreError("store is closed")
        job = _Job(fn)
        self._q.put(job)
        if not job.done.wait(timeout):
            raise StoreError(f"sqlite write timed out after {timeout:.0f} s")
        if job.exc is not None:
            raise job.exc
        return job.result

    def lag_s(self) -> float:
        """Age of the oldest queued write (0 when idle), or the last observed wait if larger and recent."""
        with self._q.mutex:
            head = self._q.queue[0] if self._q.queue else None
        age = (time.monotonic() - head.enqueued) if isinstance(head, _Job) else 0.0
        return max(age, self._last_lag if head is not None else 0.0)

    def pending(self) -> int:
        return self._q.qsize()

    # --- readers ------------------------------------------------------------------------------
    @contextlib.contextmanager
    def reader(self) -> Iterator[sqlite3.Connection]:
        try:
            conn = self._readers.get_nowait()
        except queue.Empty:
            with self._reader_lock:
                if self._closed:
                    raise StoreError("store is closed") from None
                if len(self._reader_all) < READ_POOL:
                    conn = self._connect(readonly=True)
                    self._reader_all.append(conn)
                else:
                    conn = None
            if conn is None:
                conn = self._readers.get(timeout=self.busy_timeout_s)
        try:
            yield conn
        finally:
            self._readers.put(conn)

    # --- records ------------------------------------------------------------------------------
    def insert_records(self, rows: Sequence[RecordRow], timeout: float = 60.0) -> list[bool]:
        """INSERT OR IGNORE each row (durable dedupe on (probe, id)); True where it was new."""
        def job(conn: sqlite3.Connection) -> list[bool]:
            out = []
            for r in rows:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO records(probe,id,ts_ms,site,test,outcome,body) VALUES(?,?,?,?,?,?,?)", r)
                out.append(cur.rowcount == 1)
            return out
        return self.write(job, timeout)

    def read_records(self, probe: str, from_ms: int, to_ms: int, *, test: str | None = None,
                     outcome: str | None = None, limit: int = 1000,
                     after: tuple[int, str] | None = None) -> list[tuple[int, str, str]]:
        """Records of `probe` with from_ms <= ts_ms <= to_ms ordered by (ts_ms, id); `after` is the
        exclusive (ts_ms, id) cursor. Returns [(ts_ms, id, body_json)]."""
        sql = "SELECT ts_ms, id, body FROM records WHERE probe=? AND ts_ms>=? AND ts_ms<=?"
        args: list[Any] = [probe, from_ms, to_ms]
        if test is not None:
            sql += " AND test=?"
            args.append(test)
        if outcome is not None:
            sql += " AND outcome=?"
            args.append(outcome)
        if after is not None:
            sql += " AND (ts_ms>? OR (ts_ms=? AND id>?))"
            args += [after[0], after[0], after[1]]
        sql += " ORDER BY ts_ms, id LIMIT ?"
        args.append(max(1, min(int(limit), 10_000)))
        with self.reader() as conn:
            return [(int(a), str(b), str(c)) for a, b, c in conn.execute(sql, args)]

    def count_records(self) -> int:
        with self.reader() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM records").fetchone()[0])

    def newest_ts_ms(self, probe: str) -> int | None:
        with self.reader() as conn:
            row = conn.execute("SELECT MAX(ts_ms) FROM records WHERE probe=?", (probe,)).fetchone()
        return int(row[0]) if row and row[0] is not None else None

    # --- incidents ----------------------------------------------------------------------------
    _INC_COLS = ("id", "probe", "site", "line", "kind", "start_ms", "end_ms", "where_json", "facts_json",
                 "folded_into", "acked_by", "acked_at")

    def insert_incident(self, row: Mapping[str, Any]) -> None:
        vals = [row.get(c) for c in self._INC_COLS]

        def job(conn: sqlite3.Connection) -> None:
            conn.execute("INSERT OR REPLACE INTO incidents(" + ",".join(self._INC_COLS) + ") VALUES("
                         + ",".join("?" * len(self._INC_COLS)) + ")", vals)
        self.write(job)

    def end_incidents(self, ids: Sequence[str], end_ms: int) -> None:
        """Set end_ms on the given incident rows that are still open."""
        ids = list(ids)
        if not ids:
            return

        def job(conn: sqlite3.Connection) -> None:
            conn.executemany("UPDATE incidents SET end_ms=? WHERE id=? AND end_ms IS NULL", [(end_ms, i) for i in ids])
        self.write(job)

    def ack_incident(self, incident_id: str, by: str, at_ms: int) -> bool:
        """Record who acknowledged an incident (first ack wins). False when the incident does not exist."""
        def job(conn: sqlite3.Connection) -> bool:
            cur = conn.execute("UPDATE incidents SET acked_by=?, acked_at=? WHERE id=? AND acked_by IS NULL",
                               (by[:128], at_ms, incident_id))
            if cur.rowcount:
                return True
            return conn.execute("SELECT 1 FROM incidents WHERE id=?", (incident_id,)).fetchone() is not None
        return bool(self.write(job))

    def count_open_incidents(self) -> int:
        """Incidents with no end that are causes (folded consequences are not counted separately)."""
        with self.reader() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM incidents WHERE end_ms IS NULL AND folded_into IS NULL"
                                    ).fetchone()[0])

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.reader() as conn:
            r = conn.execute("SELECT " + ",".join(self._INC_COLS) + " FROM incidents WHERE id=?",  # noqa: S608
                             (incident_id,)).fetchone()
        return dict(zip(self._INC_COLS, r, strict=True)) if r else None

    def list_incidents(self, *, probe: str | None = None, site: str | None = None, from_ms: int | None = None,
                       to_ms: int | None = None, open_only: bool = False, limit: int = 1000) -> list[dict[str, Any]]:
        """Incidents overlapping [from_ms, to_ms], newest first. Open = no end yet."""
        sql = "SELECT " + ",".join(self._INC_COLS) + " FROM incidents WHERE 1=1"  # noqa: S608 - constant columns
        args: list[Any] = []
        if probe is not None:
            sql += " AND probe=?"
            args.append(probe)
        if site is not None:
            sql += " AND site=?"
            args.append(site)
        if to_ms is not None:
            sql += " AND start_ms<=?"
            args.append(to_ms)
        if from_ms is not None:
            sql += " AND (end_ms IS NULL OR end_ms>=?)"
            args.append(from_ms)
        if open_only:
            sql += " AND end_ms IS NULL"
        sql += " ORDER BY start_ms DESC, id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 1000)))
        with self.reader() as conn:
            return [dict(zip(self._INC_COLS, r, strict=True)) for r in conn.execute(sql, args)]

    # --- meta ---------------------------------------------------------------------------------
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self.reader() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key: str, value: str) -> None:
        def job(conn: sqlite3.Connection) -> None:
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, value))
        self.write(job)

    def schema_version(self) -> int:
        return int(self.get_meta("schema_version", "0") or 0)

    # --- vm_backlog ---------------------------------------------------------------------------
    def backlog_append(self, payload: str) -> None:
        def job(conn: sqlite3.Connection) -> None:
            conn.execute("INSERT INTO vm_backlog(payload) VALUES(?)", (payload,))
        self.write(job)

    def backlog_peek(self, max_bytes: int = 1 << 20) -> list[tuple[int, str]]:
        """Oldest-first rows whose payloads total about `max_bytes` (always at least one row)."""
        out: list[tuple[int, str]] = []
        total = 0
        with self.reader() as conn:
            for seq, payload in conn.execute("SELECT seq, payload FROM vm_backlog ORDER BY seq LIMIT 1000"):
                if out and total + len(payload) > max_bytes:
                    break
                out.append((int(seq), str(payload)))
                total += len(payload)
        return out

    def backlog_delete_upto(self, seq: int) -> None:
        def job(conn: sqlite3.Connection) -> None:
            conn.execute("DELETE FROM vm_backlog WHERE seq<=?", (seq,))
        self.write(job)

    def backlog_points(self) -> int:
        """Lines (= points) across all backlog payloads (each payload is NDJSON ending in a newline)."""
        with self.reader() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(length(payload) - length(replace(payload, char(10), ''))), 0) FROM vm_backlog"
            ).fetchone()
        return int(row[0])

    # --- pruning ------------------------------------------------------------------------------
    def _probes_with_records(self) -> list[str]:
        # loose index scan over (probe, ts_ms): no full table walk
        sql = """WITH RECURSIVE p(probe) AS (
                   SELECT MIN(probe) FROM records
                   UNION ALL
                   SELECT (SELECT MIN(probe) FROM records WHERE probe > p.probe) FROM p WHERE p.probe IS NOT NULL)
                 SELECT probe FROM p WHERE probe IS NOT NULL"""
        with self.reader() as conn:
            return [str(r[0]) for r in conn.execute(sql)]

    def prune_records(self, cutoff_ms: int, batch: int = PRUNE_BATCH) -> int:
        """Delete records with ts_ms < cutoff_ms, `batch` rows per transaction. Returns rows deleted."""
        total = 0
        for probe in self._probes_with_records():
            while True:
                def job(conn: sqlite3.Connection, probe: str = probe) -> int:
                    cur = conn.execute(
                        "DELETE FROM records WHERE rowid IN "
                        "(SELECT rowid FROM records WHERE probe=? AND ts_ms<? LIMIT ?)", (probe, cutoff_ms, batch))
                    return cur.rowcount
                n = int(self.write(job))
                total += n
                if n < batch:
                    break
        return total

    def prune_incidents(self, cutoff_ms: int, batch: int = PRUNE_BATCH) -> int:
        """Delete CLOSED incidents that ended before cutoff_ms (open incidents are never pruned)."""
        total = 0
        while True:
            def job(conn: sqlite3.Connection) -> int:
                cur = conn.execute(
                    "DELETE FROM incidents WHERE rowid IN "
                    "(SELECT rowid FROM incidents WHERE end_ms IS NOT NULL AND end_ms<? LIMIT ?)",
                    (cutoff_ms, batch))
                return cur.rowcount
            n = int(self.write(job))
            total += n
            if n < batch:
                return total

    # --- sizes --------------------------------------------------------------------------------
    def db_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                total += os.stat(str(self.path) + suffix).st_size
        return total
