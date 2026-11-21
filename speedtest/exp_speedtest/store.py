"""The box's small durable state (SQLite, WAL): sessions that outlive their test, and the bounded delivery spool.

* ``sessions`` -- ``view_verifier`` (sha256 of the view proof, never the proof or key), state, the result as stored
  WITHOUT ``client.ip``, and the problem comment. This is what lets a share link (``/st/r/{id}#k=...``) work days later
  and after a restart. Raw client addresses live only in memory for the life of an active session.
* ``spool`` -- results (and comments) not yet accepted by the collector. Bounded by rows and bytes; when full the box
  refuses NEW results with 503 rather than dropping old ones. Rows are deleted the moment the collector accepts them,
  so the raw ``client.ip`` in a spooled result lives only while the collector is unreachable.

All SQL is parameterized (SR-23); one connection guarded by a lock (the volumes are tiny).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SPOOL_MAX_ROWS = 5000
SPOOL_MAX_BYTES = 64 * 1024 * 1024
SPOOL_MAX_AGE_S = 7 * 86400

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, created REAL NOT NULL, verifier TEXT NOT NULL, state TEXT NOT NULL,
  zone_hint TEXT, result_json TEXT, comment TEXT, comment_n INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS sessions_created ON sessions(created);
CREATE TABLE IF NOT EXISTS spool (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, sid TEXT NOT NULL, body TEXT NOT NULL,
  size INTEGER NOT NULL, created REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_try REAL NOT NULL);
CREATE INDEX IF NOT EXISTS spool_next ON spool(next_try);
"""


class SpoolFull(Exception):
    """The delivery spool is at its row/byte bound."""


class Store:
    def __init__(self, path: str | Path | None, max_rows: int = SPOOL_MAX_ROWS, max_bytes: int = SPOOL_MAX_BYTES) -> None:
        self.max_rows, self.max_bytes = max_rows, max_bytes
        self._lock = threading.Lock()
        target = ":memory:" if path is None else str(path)
        if path is not None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(target, os.O_RDWR | os.O_CREAT, 0o600)       # the db is private even under a lax umask
            os.close(fd)
        self._db = sqlite3.connect(target, check_same_thread=False, isolation_level=None, timeout=10)
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---------------------------------------------------------------------------------------------- sessions
    def add_session(self, sid: str, created: float, verifier: str, zone_hint: str | None) -> None:
        with self._lock:
            self._db.execute("INSERT INTO sessions(id, created, verifier, state, zone_hint) VALUES (?,?,?,?,?)",
                             (sid, created, verifier, "created", zone_hint))

    def get_session(self, sid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT id, created, verifier, state, zone_hint, result_json, comment, comment_n "
                                   "FROM sessions WHERE id = ?", (sid,)).fetchone()
        if row is None:
            return None
        return {"id": row[0], "created": row[1], "verifier": row[2], "state": row[3], "zone_hint": row[4],
                "result": json.loads(row[5]) if row[5] else None, "comment": row[6], "comment_n": row[7]}

    def set_state(self, sid: str, state: str) -> None:
        with self._lock:
            self._db.execute("UPDATE sessions SET state = ? WHERE id = ? AND state != 'submitted'", (state, sid))

    def mark_submitted(self, sid: str, result_without_ip: dict[str, Any]) -> bool:
        """True when this call made the transition (the one-shot guard of the result route)."""
        with self._lock:
            cur = self._db.execute("UPDATE sessions SET state='submitted', result_json=? WHERE id=? AND state != 'submitted'",
                                   (json.dumps(result_without_ip, separators=(",", ":")), sid))
            return cur.rowcount == 1

    def unmark_submitted(self, sid: str) -> None:
        """Roll back ``mark_submitted`` (the result could not be queued: the page may retry)."""
        with self._lock:
            self._db.execute("UPDATE sessions SET state='created', result_json=NULL WHERE id=?", (sid,))

    def set_comment(self, sid: str, comment: str) -> int:
        """Store the comment (verbatim text); returns the replacement count after this one."""
        with self._lock:
            self._db.execute("UPDATE sessions SET comment=?, comment_n=comment_n+1 WHERE id=?", (comment, sid))
            row = self._db.execute("SELECT comment_n FROM sessions WHERE id=?", (sid,)).fetchone()
        return int(row[0]) if row else 0

    def prune_sessions(self, older_than: float) -> int:
        with self._lock:
            return self._db.execute("DELETE FROM sessions WHERE created < ?", (older_than,)).rowcount

    def count_sessions(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])

    # ------------------------------------------------------------------------------------------------ spool
    def spool_add(self, kind: str, sid: str, body: str, now: float, next_try: float | None = None) -> int:
        size = len(body.encode("utf-8"))
        with self._lock:
            rows, total = self._db.execute("SELECT COUNT(*), COALESCE(SUM(size),0) FROM spool").fetchone()
            if rows >= self.max_rows or total + size > self.max_bytes:
                raise SpoolFull(f"spool at {rows} rows / {total} bytes")
            cur = self._db.execute("INSERT INTO spool(kind, sid, body, size, created, next_try) VALUES (?,?,?,?,?,?)",
                                   (kind, sid, body, size, now, now if next_try is None else next_try))
            return int(cur.lastrowid)

    def spool_due(self, now: float, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT seq, kind, sid, body, attempts, created FROM spool WHERE next_try <= ? "
                                    "ORDER BY seq LIMIT ?", (now, limit)).fetchall()
        return [{"seq": r[0], "kind": r[1], "sid": r[2], "body": r[3], "attempts": r[4], "created": r[5]} for r in rows]

    def spool_get(self, seq: int) -> dict[str, Any] | None:
        with self._lock:
            r = self._db.execute("SELECT seq, kind, sid, body, attempts, created FROM spool WHERE seq=?", (seq,)).fetchone()
        return None if r is None else {"seq": r[0], "kind": r[1], "sid": r[2], "body": r[3], "attempts": r[4], "created": r[5]}

    def spool_claim(self, seq: int, until: float) -> None:
        """Lease a row so the background loop does not deliver it while a request thread is trying."""
        with self._lock:
            self._db.execute("UPDATE spool SET next_try=? WHERE seq=?", (until, seq))

    def spool_done(self, seq: int) -> None:
        with self._lock:
            self._db.execute("DELETE FROM spool WHERE seq=?", (seq,))

    def spool_retry(self, seq: int, attempts: int, next_try: float) -> None:
        with self._lock:
            self._db.execute("UPDATE spool SET attempts=?, next_try=? WHERE seq=?", (attempts, next_try, seq))

    def spool_has_result(self, sid: str) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM spool WHERE kind='result' AND sid=? LIMIT 1", (sid,)).fetchone() is not None

    def spool_expire(self, now: float, max_age_s: float = SPOOL_MAX_AGE_S) -> int:
        with self._lock:
            return self._db.execute("DELETE FROM spool WHERE created < ?", (now - max_age_s,)).rowcount

    def spool_stat(self, now: float) -> dict[str, Any]:
        with self._lock:
            n, size, oldest = self._db.execute("SELECT COUNT(*), COALESCE(SUM(size),0), MIN(created) FROM spool").fetchone()
        return {"depth": int(n), "bytes": int(size), "oldest_age_s": None if oldest is None else max(0.0, now - oldest)}
