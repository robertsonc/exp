"""The syslog ring buffer: a SQLite database indexed by IP + time (SR-24, 12 section 5.2).

* Lines live for ``ring_minutes`` (<= 60) after they were *received*; the pruner deletes them.
* A line attached to a test's evidence (``attach``) outlives the ring (``attached_retention_s``, default 30 days, the
  evidence retention) and is deleted with it, or earlier by ``delete_ip`` (privacy scrub, data-subject purge).
* All SQL is parameterized; stored text is already bounded and control-free (``syslog_parse``).
"""
from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from .syslog_parse import ParsedLine, envelope_host

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


_SET_VERSION_SQL = "PRAGMA user_version=1"  # == SCHEMA_VERSION (PRAGMA takes no bound parameter; a constant keeps execute() literal)
_H = "[0-9A-Fa-f]"
_MAC_SHAPES = (re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"), re.compile(r"^[0-9a-f]{2}(-[0-9a-f]{2}){5}$"),
               re.compile(r"^[0-9a-f]{4}(\.[0-9a-f]{4}){2}$"), re.compile(r"^[0-9a-f]{12}$"))
# any MAC spelling inside a line (to recognise lines that name another device)
_ANY_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:])" + _H + r"{2}(?::" + _H + r"{2}){5}(?![0-9A-Fa-f:])|(?<![0-9A-Fa-f-])" + _H + r"{2}(?:-" + _H + r"{2}){5}(?![0-9A-Fa-f-])"
    r"|(?<![0-9A-Fa-f.])" + _H + r"{4}(?:\." + _H + r"{4}){2}(?![0-9A-Fa-f.])|(?<![0-9A-Fa-f])" + _H + r"{12}(?![0-9A-Fa-f])")


# the tail of a reverse-DNS name after one of its dotted-quad-looking label runs ("3.2.1.10.in-addr.arpa", ip6.arpa nibbles)
_ARPA_TAIL = r"(?:\.[0-9A-Za-z]{1,3})*\.(?:in-addr|ip6)\.arpa\b"


def _is_mac_spelling(t: str) -> bool:
    return any(r.match(t) for r in _MAC_SHAPES)


def _mac_regex(t: str) -> re.Pattern[str]:
    """This device's MAC in one spelling. A 6-octet MAC embedded in a longer octet run is still this device's identifier (DHCPv6
    DUID-LL/LLT, option-61 client-id ``01:<mac>``, netfilter ``MAC=<dst>:<src>:<type>``, ``<mac>:deauth``): a separator spelling only
    must not be glued to another hex DIGIT on either side; the bare 12-hex spelling is a plain substring (bare DUIDs, client-ids)."""
    if not any(c in t for c in ":-."):
        return re.compile(re.escape(t), re.IGNORECASE)
    return re.compile("(?<![0-9A-Fa-f])" + re.escape(t) + "(?![0-9A-Fa-f])", re.IGNORECASE)


def _plain_ip(text: str | None) -> str | None:
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return None


def _reversed_v4(ip: str | None) -> str | None:
    p = _plain_ip(ip)
    return ".".join(reversed(p.split("."))) if p and ipaddress.ip_address(p).version == 4 else None


def _py_lower(text: object) -> object:
    """SQL ``exp_lower(x)``: Python's Unicode lower-casing (SQLite's own lower() folds ASCII only, so 'BÜRO-PC' stayed 'bÜro-pc')."""
    return text.lower() if isinstance(text, str) else text


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
        db.create_function("exp_lower", 1, _py_lower, deterministic=True)  # connection-local; never used in the schema
        db.executescript(_DDL)
        ver = db.execute("PRAGMA user_version").fetchone()[0]
        if ver == 0:
            db.execute(_SET_VERSION_SQL)
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
                arg = json.dumps(chunk)  # one bound JSON array parameter: the SQL text stays constant
                db.execute("DELETE FROM ips WHERE line_id IN (SELECT value FROM json_each(?))", (arg,))
                db.execute("DELETE FROM lines WHERE id IN (SELECT value FROM json_each(?))", (arg,))
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

    def delete_mentions(self, tokens: Sequence[str], ip: str | None = None) -> int:
        """Delete the lines (ring or attached) that name a device by MAC spelling or hostname (the privacy scrub, A6.6): lines such as
        DHCPDISCOVER carry no IP, so ``delete_ip`` never reaches them. Matching is checked, not a bare substring, except where noted:

        * a MAC token: the bare 12-hex spelling anywhere (plain substring); a colon/dash/dotted spelling wherever it is not glued to
          another hex digit, also inside a longer octet run (DUID, client-id, netfilter ``MAC=``: still this device's identifier);
        * any other token is a hostname: the whole name, case-insensitively (Unicode), not preceded/followed by ``[\\w-]``;
        * a line matched ONLY by the hostname is kept when it names another device (a MAC other than this device's, or an indexed IP
          other than ``ip``): generic names ("iPhone") are shared by many devices. An indexed IP that is the line's syslog header
          HOSTNAME (the sender), the reversed form of ``ip`` or a label of an in-addr.arpa/ip6.arpa name names no device.

        Tokens shorter than 3 characters are ignored. Bounded: one scan of the ring (<= max_rows lines) per token; the SQL LIKE
        prefilter is parameterized and escaped, candidates are verified in Python and deleted in chunks in one transaction."""
        toks = list(dict.fromkeys(t.strip().lower() for t in tokens if isinstance(t, str) and len(t.strip()) >= 3))
        if not toks:
            return 0
        mac_toks = [t for t in toks if _is_mac_spelling(t)]
        names = [t for t in toks if t not in mac_toks]
        own_macs = {re.sub(r"[^0-9a-f]", "", t) for t in mac_toks}
        mac_res = [_mac_regex(t) for t in mac_toks]
        name_res = [re.compile(r"(?<![\w-])" + re.escape(t) + r"(?![\w-])", re.IGNORECASE) for t in names]
        with self._lock:
            db = self._conn()
            cand: dict[int, str] = {}
            for t in toks:
                like = "%" + t.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                # SQLite lower() folds ASCII only: a token with other letters ("büro-pc") is matched against the Python-lowered line
                for lid, raw in db.execute("SELECT id, raw FROM lines WHERE lower(raw) LIKE ? ESCAPE '\\'" if t.isascii() else
                                           "SELECT id, raw FROM lines WHERE exp_lower(raw) LIKE ? ESCAPE '\\'", (like,)):
                    cand[lid] = raw
            ids: list[int] = []
            for lid, raw in cand.items():
                if any(r.search(raw) for r in mac_res):
                    ids.append(lid)
                elif any(r.search(raw.lower()) for r in name_res) and not self._names_other_device(db, lid, raw, own_macs, ip):
                    ids.append(lid)
            log.debug("ring scrub: %d token(s), %d candidate line(s), %d deleted", len(toks), len(cand), len(ids))  # counts only
            return self._delete_ids(sorted(ids))

    @staticmethod
    def _names_other_device(db: sqlite3.Connection, lid: int, raw: str, own_macs: set[str], ip: str | None) -> bool:
        for m in _ANY_MAC_RE.finditer(raw):
            if re.sub(r"[^0-9a-f]", "", m.group(0).lower()) not in own_macs:
                return True
        # parse_line's raw-format fallback indexes every dotted quad of the text: the header HOSTNAME (the sending router) and the
        # labels of a reverse-DNS name ("3.2.1.10.in-addr.arpa" = this device's IP reversed) are not another device
        no_device = {x for x in (_plain_ip(ip), _reversed_v4(ip), _plain_ip(envelope_host(raw))) if x}
        for (x,) in db.execute("SELECT DISTINCT ip FROM ips WHERE line_id=?", (lid,)):
            if x in no_device or re.search(r"(?<![0-9])" + re.escape(x) + _ARPA_TAIL, raw, re.IGNORECASE):
                continue
            return True
        return False

    # ------------------------------------------------------------------------------------- reads
    def query(self, ip: str, t0: float, t1: float, kinds: Sequence[str] | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        """Lines mentioning `ip` with event time in [t0, t1], oldest first; `kinds` (optional) narrows to those kinds."""
        if isinstance(kinds, str):
            kinds = (kinds,)
        kinds_arg = json.dumps([str(k) for k in kinds]) if kinds else None  # one bound JSON array: the SQL text stays constant
        sql = ("SELECT DISTINCT l.id,l.ts,l.src,l.fmt,l.kind,l.fields,l.raw FROM ips i JOIN lines l ON l.id=i.line_id "
               "WHERE i.ip=? AND i.ts>=? AND i.ts<=? AND (? IS NULL OR l.kind IN (SELECT value FROM json_each(?))) "
               "ORDER BY l.ts, l.id LIMIT ?")
        with self._lock:
            rows = self._conn().execute(sql, (ip, t0, t1, kinds_arg, kinds_arg, int(limit))).fetchall()
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
