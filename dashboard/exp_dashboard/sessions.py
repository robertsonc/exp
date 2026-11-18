"""Server-side sessions in SQLite (``<state>/sessions.db``).

Only ``sha256(session_id)`` is stored: a leaked database cannot be replayed as cookies. Each row
carries a ``binding`` (fingerprint of the credential it was issued against) so credential
rotation or user removal invalidates the session (see ``SessionStore.sweep``).
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

COOKIE_NAME = "__Host-exp_session"
KINDS = ("sso", "local", "noc")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
  id_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL, username TEXT NOT NULL,
  role TEXT NOT NULL, csrf TEXT NOT NULL, binding TEXT NOT NULL,
  created REAL NOT NULL, expires REAL NOT NULL, hard_expires REAL NOT NULL, last_seen REAL NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires);
"""


@dataclass(frozen=True)
class Session:
    id_hash: str
    kind: str          # sso | local | noc
    subject: str       # credential identity: email (sso), username (local), noc token id (noc)
    username: str      # display / X-Exp-User
    role: str
    csrf: str
    binding: str
    created: float
    expires: float
    hard_expires: float


def hash_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


class SessionStore:
    def __init__(self, path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        old = os.umask(0o077)
        try:
            self._db = sqlite3.connect(str(self.path), check_same_thread=False, timeout=10,
                                       isolation_level=None)
        finally:
            os.umask(old)
        self._db.executescript(_SCHEMA)
        try:
            os.chmod(self.path, 0o600)
        except OSError as exc:
            log.warning("cannot chmod sessions.db: %s", exc.strerror)
        self._db.execute("PRAGMA journal_mode=WAL")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- create / read ----------------------------------------------------------------------
    def create(self, *, kind: str, subject: str, username: str, role: str, binding: str,
               ttl_s: float, hard_ttl_s: float | None = None) -> tuple[str, Session]:
        """New session. Returns (plaintext session id -- never stored --, record)."""
        if kind not in KINDS:
            raise ValueError("bad session kind")
        sid = secrets.token_urlsafe(32)              # 256 bits
        now = self._clock()
        hard = now + (hard_ttl_s if hard_ttl_s is not None else ttl_s)
        s = Session(hash_id(sid), kind, subject, username, role, secrets.token_urlsafe(32), binding,
                    now, min(now + ttl_s, hard), hard)
        with self._lock:
            self._db.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (s.id_hash, s.kind, s.subject, s.username, s.role, s.csrf, s.binding, s.created,
                 s.expires, s.hard_expires, now))
        return sid, s

    def _row(self, r: tuple) -> Session:
        return Session(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9])

    def get(self, session_id: str) -> Session | None:
        if not session_id or len(session_id) > 128:
            return None
        h = hash_id(session_id)
        with self._lock:
            r = self._db.execute(
                "SELECT id_hash,kind,subject,username,role,csrf,binding,created,expires,hard_expires "
                "FROM sessions WHERE id_hash=?", (h,)).fetchone()
            if r is None:
                return None
            s = self._row(r)
            if s.expires <= self._clock():
                self._db.execute("DELETE FROM sessions WHERE id_hash=?", (h,))
                return None
            return s

    def renew(self, s: Session, ttl_s: float) -> Session:
        """Sliding renewal (NOC sessions): extends expiry to now+ttl, never past ``hard_expires``."""
        now = self._clock()
        new_exp = min(now + ttl_s, s.hard_expires)
        if new_exp - s.expires < ttl_s / 10:
            return s
        with self._lock:
            self._db.execute("UPDATE sessions SET expires=?, last_seen=? WHERE id_hash=?",
                             (new_exp, now, s.id_hash))
        return Session(s.id_hash, s.kind, s.subject, s.username, s.role, s.csrf, s.binding, s.created,
                       new_exp, s.hard_expires)

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE id_hash=?", (hash_id(session_id),))

    def delete_hash(self, id_hash: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE id_hash=?", (id_hash,))

    # -- maintenance ------------------------------------------------------------------------
    def purge_expired(self) -> int:
        with self._lock:
            cur = self._db.execute("DELETE FROM sessions WHERE expires<=?", (self._clock(),))
            return cur.rowcount

    def count_active(self) -> int:
        with self._lock:
            r = self._db.execute("SELECT COUNT(*) FROM sessions WHERE expires>?", (self._clock(),)).fetchone()
        return int(r[0])

    def sweep(self, is_valid: Callable[[Session], bool]) -> int:
        """Delete every live session for which ``is_valid`` is false. Returns the number removed."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id_hash,kind,subject,username,role,csrf,binding,created,expires,hard_expires "
                "FROM sessions WHERE expires>?", (self._clock(),)).fetchall()
            dead = [r[0] for r in rows if not is_valid(self._row(r))]
            for h in dead:
                self._db.execute("DELETE FROM sessions WHERE id_hash=?", (h,))
        if dead:
            log.info("invalidated %d session(s) after credential change", len(dead))
        return len(dead)
