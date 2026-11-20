"""The syslog ring buffer: a SQLite database indexed by IP + time (SR-24, 12 section 5.2).

* Lines live for ``ring_minutes`` (<= 60) after they were *received*; the pruner deletes them.
* A line attached to a test's evidence (``attach``) outlives the ring (``attached_retention_s``, default 30 days, the
  evidence retention) and is deleted with it, or earlier by ``delete_ip`` (privacy scrub, data-subject purge).
* All SQL is parameterized; stored text is already bounded and control-free (``syslog_parse``).
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import sqlite3
import threading
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from .syslog_parse import ParsedLine

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
DEFAULT_ATTACHED_RETENTION_S = 30 * 86400
DEFAULT_MAX_ROWS = 500_000

_DDL = """
CREATE TABLE IF NOT EXISTS lines(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, recv REAL NOT NULL, src TEXT NOT NULL, fmt TEXT NOT NULL, kind TEXT NOT NULL,
  keep INTEGER NOT NULL DEFAULT 0, kept_at REAL,
  mac TEXT, lease_ip TEXT, dhcp_event TEXT, fields TEXT NOT NULL, raw TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ips(ip TEXT NOT NULL, ts REAL NOT NULL, line_id INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ips_ip_ts ON ips(ip, ts);
CREATE INDEX IF NOT EXISTS ips_line ON ips(line_id);
CREATE INDEX IF NOT EXISTS lines_recv ON lines(recv);
CREATE INDEX IF NOT EXISTS lines_keep ON lines(keep, kept_at);
"""


class RingError(Exception):
    pass


class Ring:
    def __init__(self, path: str | Path, ring_minutes: int = 60, attached_retention_s: float = DEFAULT_ATTACHED_RETENTION_S,
                 max_rows: int = DEFAULT_MAX_ROWS) -> None:
        self.path = Path(path)
        self.ring_s = max(60, min(60, int(ring_minutes)) * 60)
        self.attached_retention_s = float(attached_retention_s)
        self.max_rows = int(max_rows)
        self._lock = threading.RLock()
        self._db: sqlite3.Connection | None = None

    def open(self) -> Ring:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        old = os.umask(0o077)
        try:
            db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None, timeout=10)
        finally:
            os.umask(old)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA foreign_keys=OFF")
        db.executescript(_DDL)
        ver = db.execute("PRAGMA user_version").fetchone()[0]
        if ver == 0:
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        elif ver > SCHEMA_VERSION:
            db.close()
            raise RingError(f"{self.path}: database schema {ver} is newer than this runner ({SCHEMA_VERSION})")
        with contextlib.suppress(OSError):
            os.chmod(self.path, 0o600)
        self._db = db
        return self

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def _conn(self) -> sqlite3.Connection:
        if self._db is None:
            raise RingError("ring is not open")
        return self._db

    # ------------------------------------------------------------------------------------ writes
    def insert_many(self, rows: Iterable[tuple[ParsedLine, str, float]]) -> int:
        """Insert ``(parsed, source_ip, received_epoch)``. Returns rows stored."""
        n = 0
        with self._lock:
            db = self._conn()
            db.execute("BEGIN")
            try:
                for p, src, recv in rows:
                    f = p.fields
                    cur = db.execute(
                        "INSERT INTO lines(ts,recv,src,fmt,kind,mac,lease_ip,dhcp_event,fields,raw) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (p.ts, recv, src, p.fmt, p.kind, f.get("mac"), f.get("lease_ip"), f.get("dhcp_event"),
                         json.dumps(f, separators=(",", ":")), p.raw))
                    lid = cur.lastrowid
                    for ip in p.ips:
                        db.execute("INSERT INTO ips(ip,ts,line_id) VALUES(?,?,?)", (ip, p.ts, lid))
                    n += 1
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return n

    def attach(self, line_ids: Sequence[int], now: float) -> None:
        if not line_ids:
            return
        with self._lock:
            db = self._conn()
            db.execute("BEGIN")
            try:
                for lid in line_ids:
                    db.execute("UPDATE lines SET keep=1, kept_at=? WHERE id=?", (now, int(lid)))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def prune(self, now: float) -> int:
        """Drop expired ring lines, expired attached lines and rows over ``max_rows``; returns lines deleted."""
        with self._lock:
            db = self._conn()
            n = self._delete_ids([r[0] for r in db.execute(
                "SELECT id FROM lines WHERE (keep=0 AND recv<?) OR (keep=1 AND kept_at<?)",
                (now - self.ring_s, now - self.attached_retention_s))])
            over = int(db.execute("SELECT COUNT(*) FROM lines").fetchone()[0]) - self.max_rows
            if over > 0:
                n += self._delete_ids([r[0] for r in db.execute("SELECT id FROM lines WHERE keep=0 ORDER BY id LIMIT ?", (over,))])
            return n

    def _delete_ids(self, ids: list[int]) -> int:
        if not ids:
            return 0
        db = self._conn()
        db.execute("BEGIN")
        try:
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                q = ",".join("?" * len(chunk))
                db.execute(f"DELETE FROM ips WHERE line_id IN ({q})", chunk)       # noqa: S608 - placeholders only
                db.execute(f"DELETE FROM lines WHERE id IN ({q})", chunk)           # noqa: S608
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
        return len(ids)

    def delete_ip(self, ip: str) -> int:
        """Delete every line (ring or attached) that mentions `ip` (privacy scrub / purge)."""
        with self._lock:
            ids = [r[0] for r in self._conn().execute("SELECT DISTINCT line_id FROM ips WHERE ip=?", (ip,))]
            return self._delete_ids(ids)

    # ------------------------------------------------------------------------------------- reads
    def query(self, ip: str, t0: float, t1: float, kinds: Sequence[str] | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        """Lines mentioning `ip` with event time in [t0, t1], oldest first."""
        sql = ("SELECT DISTINCT l.id,l.ts,l.src,l.fmt,l.kind,l.fields,l.raw FROM ips i JOIN lines l ON l.id=i.line_id "
               "WHERE i.ip=? AND i.ts>=? AND i.ts<=?")
        args: list[Any] = [ip, t0, t1]
        if kinds:
            sql += " AND l.kind IN (" + ",".join("?" * len(kinds)) + ")"
            args += list(kinds)
        sql += " ORDER BY l.ts, l.id LIMIT ?"
        args.append(int(limit))
        with self._lock:
            rows = self._conn().execute(sql, args).fetchall()
        return [{"id": r[0], "ts": r[1], "src": r[2], "fmt": r[3], "kind": r[4], "fields": json.loads(r[5]), "raw": r[6]} for r in rows]

    def dhcp_events(self, ip: str, t0: float, t1: float) -> list[dict[str, Any]]:
        sql = ("SELECT id,ts,mac,dhcp_event,fields FROM lines WHERE kind='dhcp' AND lease_ip=? AND ts>=? AND ts<=? ORDER BY ts,id")
        with self._lock:
            rows = self._conn().execute(sql, (ip, t0, t1)).fetchall()
        return [{"id": r[0], "ts": r[1], "mac": r[2], "event": r[3], "fields": json.loads(r[4])} for r in rows]

    def last_dhcp_before(self, ip: str, t: float) -> dict[str, Any] | None:
        sql = "SELECT id,ts,mac,dhcp_event,fields FROM lines WHERE kind='dhcp' AND lease_ip=? AND ts<? ORDER BY ts DESC,id DESC LIMIT 1"
        with self._lock:
            r = self._conn().execute(sql, (ip, t)).fetchone()
        return None if r is None else {"id": r[0], "ts": r[1], "mac": r[2], "event": r[3], "fields": json.loads(r[4])}

    def count(self) -> int:
        with self._lock:
            return int(self._conn().execute("SELECT COUNT(*) FROM lines").fetchone()[0])

    def count_kept(self) -> int:
        with self._lock:
            return int(self._conn().execute("SELECT COUNT(*) FROM lines WHERE keep=1").fetchone()[0])
