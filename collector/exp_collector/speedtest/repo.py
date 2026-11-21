"""SQLite access of the speedtest tables. Every statement is parameterized; identifiers in SQL text (columns,
group expressions) come from fixed tables in this module, never from a request. All writes run on the store's single
writer thread, each in one transaction (one job = one atomic change)."""
from __future__ import annotations

import json
import sqlite3
import statistics
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from ..store import Store

KINDS = ("wifi", "wired", "flows", "wan", "security", "baseline", "dns", "identity")
COLS = ("seq", "id", "site", "speedtest_id", "started_ms", "ended_ms", "received_ms", "zone", "zone_source", "score",
        "local_down", "local_up", "internet_down", "internet_up", "local_loaded", "internet_loaded", "flags",
        "comment", "ap_name", "ssid", "band", "os_family", "device_key", "client_ip", "mac", "hostname", "username",
        "cause", "state", "final_ms", "complete_status", "scrubbed", "evidence_n", "metrics_done", "doc")
_SELECT = "SELECT " + ",".join(COLS) + " FROM speedtests"          # noqa: S608 - constant column list
MAX_AGG_ROWS = 500_000
GROUP_EXPR = {
    "zone": "zone", "ap": "COALESCE(ap_name,'unknown')", "ssid": "COALESCE(ssid,'unknown')",
    "band": "COALESCE(band,'unknown')", "os_family": "COALESCE(os_family,'unknown')",
    "hour": "strftime('%Y-%m-%dT%H:00:00Z', started_ms/1000, 'unixepoch')", "cause": "COALESCE(cause,'unknown')",
}
VALUE_COL = {("down_p50", "local"): "local_down", ("down_p50", "internet"): "internet_down",
             ("up_p50", "local"): "local_up", ("up_p50", "internet"): "internet_up",
             ("loaded_p50", "local"): "local_loaded", ("loaded_p50", "internet"): "internet_loaded",
             ("score_p50", "local"): "score", ("score_p50", "internet"): "score"}
# row columns settable by the evidence-derived update (fixed list: used to build the UPDATE text)
DERIVED = ("zone", "zone_source", "flags", "ap_name", "ssid", "band", "os_family", "device_key", "mac", "hostname",
           "username")


def _dicts(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Repo:
    def __init__(self, store: Store) -> None:
        self.store = store

    # ------------------------------------------------------------------------------------------------ reads
    def get(self, test_id: str) -> dict[str, Any] | None:
        with self.store.reader() as conn:
            rows = _dicts(conn.execute(_SELECT + " WHERE id=?", (test_id,)))
        return rows[0] if rows else None

    def evidence(self, test_id: str) -> list[dict[str, Any]]:
        with self.store.reader() as conn:
            rows = conn.execute("SELECT body FROM evidence WHERE test_id=? ORDER BY kind", (test_id,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def diagnoses(self, test_id: str) -> dict[str, dict[str, Any]]:
        with self.store.reader() as conn:
            rows = conn.execute("SELECT stage, body FROM diagnoses WHERE test_id=?", (test_id,)).fetchall()
        return {str(s): json.loads(b) for s, b in rows}

    def latest_diagnosis(self, test_id: str) -> dict[str, Any] | None:
        d = self.diagnoses(test_id)
        return d.get("final") or d.get("quick")

    def list(self, *, site: str | None, zone: str | None, ap: str | None, ssid: str | None, cause: str | None,
             from_ms: int | None, to_ms: int | None, min_score: int | None, max_score: int | None, q: str | None,
             identifiers: bool, limit: int, before: tuple[int, str] | None) -> list[dict[str, Any]]:
        sql, args = _SELECT + " WHERE 1=1", []
        for col, val in (("site", site), ("zone", zone), ("ap_name", ap), ("ssid", ssid)):
            if val is not None:
                sql += f" AND {col}=?"                                  # noqa: S608 - col from the literal tuple
                args.append(val)
        if cause is not None:
            sql += " AND cause=?"
            args.append(cause)
        if from_ms is not None:
            sql += " AND started_ms>=?"
            args.append(from_ms)
        if to_ms is not None:
            sql += " AND started_ms<?"
            args.append(to_ms)
        if min_score is not None:
            sql += " AND score>=?"
            args.append(min_score)
        if max_score is not None:
            sql += " AND score<=?"
            args.append(max_score)
        if q:
            like = _like(q)
            cols = ["id", "comment", "zone", "ap_name", "ssid"] + (["client_ip", "mac", "hostname", "username"]
                                                                  if identifiers else [])
            sql += " AND (" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in cols) + ")"
            args += [like] * len(cols)
        if before is not None:
            sql += " AND (started_ms<? OR (started_ms=? AND id<?))"
            args += [before[0], before[0], before[1]]
        sql += " ORDER BY started_ms DESC, id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 1000)))
        with self.store.reader() as conn:
            return _dicts(conn.execute(sql, args))

    def feed(self, site: str, after_seq: int, limit: int) -> list[dict[str, Any]]:
        with self.store.reader() as conn:
            return _dicts(conn.execute(
                _SELECT + " WHERE site=? AND state!='final' AND seq>? ORDER BY seq LIMIT ?",
                (site, after_seq, max(1, min(int(limit), 100)))))

    def pending_due(self, cutoff_ms: int, limit: int = 200) -> list[str]:
        with self.store.reader() as conn:
            return [str(r[0]) for r in conn.execute(
                "SELECT id FROM speedtests WHERE state!='final' AND ended_ms<? ORDER BY seq LIMIT ?",
                (cutoff_ms, limit))]

    def unscrubbed_final(self, limit: int = 200) -> list[str]:
        with self.store.reader() as conn:
            return [str(r[0]) for r in conn.execute(
                "SELECT id FROM speedtests WHERE state='final' AND scrubbed=0 ORDER BY seq LIMIT ?", (limit,))]

    def aggregate(self, group_by: str, metric: str, leg: str, site: str | None, from_ms: int, to_ms: int
                  ) -> list[tuple[str, float, int]]:
        expr = GROUP_EXPR[group_by]
        where, args = "started_ms>=? AND started_ms<?", [from_ms, to_ms]
        if site is not None:
            where += " AND site=?"
            args.append(site)
        with self.store.reader() as conn:
            if metric == "count":
                rows = conn.execute(f"SELECT {expr} AS k, COUNT(*) FROM speedtests WHERE {where} "  # noqa: S608
                                    f"GROUP BY k ORDER BY k", args).fetchall()
                return [(str(k), float(n), int(n)) for k, n in rows]
            col = VALUE_COL[(metric, leg)]
            rows = conn.execute(f"SELECT {expr} AS k, {col} FROM speedtests WHERE {where} AND {col} IS NOT NULL "  # noqa: S608
                                f"ORDER BY k LIMIT ?", [*args, MAX_AGG_ROWS]).fetchall()
        groups: dict[str, list[float]] = {}
        for k, v in rows:
            groups.setdefault(str(k), []).append(float(v))
        return [(k, float(statistics.median(vs)), len(vs)) for k, vs in sorted(groups.items())]

    def find_for_purge(self, by: str, value: str, device_key: str | None) -> list[str]:
        """Ids of the tests a purge matches. `device_key` is the HMAC of a MAC when the secret is known."""
        sql, args = "SELECT id FROM speedtests WHERE ", []
        if by == "test":
            sql += "id=?"
            args = [value]
        elif by == "ip":
            sql += "client_ip=?"
            args = [value]
        elif by == "device_key":
            sql += "device_key=?"
            args = [value]
        else:       # mac: the raw column, and the device key when the secret is available
            sql += "mac=?" + (" OR device_key=?" if device_key else "")
            args = [value] + ([device_key] if device_key else [])
        with self.store.reader() as conn:
            return [str(r[0]) for r in conn.execute(sql, args)]

    def count(self) -> int:
        with self.store.reader() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM speedtests").fetchone()[0])

    # ----------------------------------------------------------------------------------------------- writes
    def insert(self, row: Mapping[str, Any], quick: Mapping[str, Any]) -> bool:
        cols = [c for c in COLS if c != "seq" and c in row]
        quick_json = json.dumps(quick, separators=(",", ":"))

        def job(conn: sqlite3.Connection) -> bool:
            cur = conn.execute(
                f"INSERT OR IGNORE INTO speedtests({','.join(cols)}) VALUES({','.join('?' * len(cols))})",  # noqa: S608
                [row[c] for c in cols])
            if cur.rowcount != 1:
                return False
            conn.execute("INSERT OR REPLACE INTO diagnoses(test_id,stage,updated_ms,body) VALUES(?,?,?,?)",
                         (row["id"], "quick", row["received_ms"], quick_json))
            return True
        return bool(self.store.write(job))

    def set_comment(self, test_id: str, comment: str) -> bool:
        def job(conn: sqlite3.Connection) -> bool:
            return conn.execute("UPDATE speedtests SET comment=? WHERE id=?", (comment, test_id)).rowcount == 1
        return bool(self.store.write(job))

    def put_evidence(self, test_id: str, doc: Mapping[str, Any], *, collected_ms: int, max_total: int,
                     derive: Callable[[dict[str, Any], dict[str, dict[str, Any]]], dict[str, Any]]) -> dict[str, Any]:
        """Store one evidence document. Result ``code``: ok | final | missing | too_large | stale."""
        kind = str(doc["kind"])
        body = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
        size = len(body.encode("utf-8"))

        def job(conn: sqlite3.Connection) -> dict[str, Any]:
            rows = _dicts(conn.execute(_SELECT + " WHERE id=?", (test_id,)))
            if not rows:
                return {"code": "missing"}
            test = rows[0]
            if test["state"] == "final":
                return {"code": "final"}
            sizes = {str(k): (int(s), int(c), str(src)) for k, s, c, src in conn.execute(
                "SELECT kind, size, collected_ms, source FROM evidence WHERE test_id=?", (test_id,))}
            total_other = sum(v[0] for k, v in sizes.items() if k != kind)
            old = sizes.get(kind)
            if old is not None and collected_ms < old[1]:                       # an older document never replaces
                return {"code": "stale", "stored_bytes": old[0], "total_bytes": total_other + old[0]}
            if old is not None and collected_ms == old[1] and str(doc["source"]) == old[2]:
                same = conn.execute("SELECT body FROM evidence WHERE test_id=? AND kind=?",
                                    (test_id, kind)).fetchone()
                if same and same[0] == body:                                    # dedup: same kind/source/collected_at
                    return {"code": "ok", "stored_bytes": size, "total_bytes": total_other + size, "dedup": True}
            if total_other + size > max_total:
                return {"code": "too_large", "total_bytes": total_other + size}
            conn.execute("INSERT OR REPLACE INTO evidence(test_id,kind,source,collected_ms,status,size,body) "
                         "VALUES(?,?,?,?,?,?,?)", (test_id, kind, str(doc["source"]), collected_ms,
                                                   str(doc["status"]), size, body))
            docs = {str(k): json.loads(b) for k, b in conn.execute(
                "SELECT kind, body FROM evidence WHERE test_id=?", (test_id,))}
            upd = derive(test, docs)
            sets = [f"{c}=?" for c in DERIVED if c in upd]
            if sets:
                conn.execute(f"UPDATE speedtests SET {','.join(sets)} WHERE id=?",          # noqa: S608
                             [upd[c] for c in DERIVED if c in upd] + [test_id])
            conn.execute("UPDATE speedtests SET state='correlating', evidence_n=? WHERE id=?", (len(docs), test_id))
            return {"code": "ok", "stored_bytes": size, "total_bytes": total_other + size, "dedup": False}
        return dict(self.store.write(job))

    def finalize(self, test_id: str, *, now_ms: int, status: str,
                 diagnose: Callable[[dict[str, Any], dict[str, dict[str, Any]]], dict[str, Any]],
                 scrub: Callable[[dict[str, Any], list[dict[str, Any]]], list[dict[str, Any]]] | None
                 ) -> dict[str, Any]:
        """Mark evidence final, store the final diagnosis, optionally scrub, all in one transaction."""
        def job(conn: sqlite3.Connection) -> dict[str, Any]:
            rows = _dicts(conn.execute(_SELECT + " WHERE id=?", (test_id,)))
            if not rows:
                return {"code": "missing"}
            test = rows[0]
            if test["state"] == "final":
                return {"code": "already_final"}
            docs = {str(k): json.loads(b) for k, b in conn.execute(
                "SELECT kind, body FROM evidence WHERE test_id=?", (test_id,))}
            diag = diagnose(test, docs)
            conn.execute("INSERT OR REPLACE INTO diagnoses(test_id,stage,updated_ms,body) VALUES(?,?,?,?)",
                         (test_id, "final", now_ms, json.dumps(diag, separators=(",", ":"))))
            top = diag["cause"][0]["id"] if diag["cause"] else None
            conn.execute("UPDATE speedtests SET state='final', final_ms=?, complete_status=?, cause=?, evidence_n=?,"
                         " metrics_done=1 WHERE id=?", (now_ms, status, top, len(docs), test_id))
            scrubbed = False
            if scrub is not None:
                self._scrub_in_txn(conn, test, docs, scrub)
                scrubbed = True
            return {"code": "ok", "diagnosis": diag, "scrubbed": scrubbed, "evidence_n": len(docs),
                    "metrics_due": not test["metrics_done"]}
        return dict(self.store.write(job))

    def update_cause(self, test_id: str, cause: str | None, diag: Mapping[str, Any], stage: str, now_ms: int) -> None:
        def job(conn: sqlite3.Connection) -> None:
            conn.execute("INSERT OR REPLACE INTO diagnoses(test_id,stage,updated_ms,body) VALUES(?,?,?,?)",
                         (test_id, stage, now_ms, json.dumps(diag, separators=(",", ":"))))
            conn.execute("UPDATE speedtests SET cause=? WHERE id=?", (cause, test_id))
        self.store.write(job)

    @staticmethod
    def _scrub_in_txn(conn: sqlite3.Connection, test: dict[str, Any], docs: dict[str, dict[str, Any]],
                      scrub: Callable[[dict[str, Any], list[dict[str, Any]]], list[dict[str, Any]]]) -> None:
        new_docs = scrub(test, list(docs.values()))
        for d in new_docs:
            body = json.dumps(d, separators=(",", ":"), ensure_ascii=False)
            conn.execute("UPDATE evidence SET body=?, size=? WHERE test_id=? AND kind=?",
                         (body, len(body.encode("utf-8")), test["id"], d["kind"]))
        conn.execute("UPDATE speedtests SET client_ip=NULL, mac=NULL, hostname=NULL, username=NULL, scrubbed=1 "
                     "WHERE id=?", (test["id"],))

    def scrub_one(self, test_id: str,
                  scrub: Callable[[dict[str, Any], list[dict[str, Any]]], list[dict[str, Any]]]) -> bool:
        def job(conn: sqlite3.Connection) -> bool:
            rows = _dicts(conn.execute(_SELECT + " WHERE id=?", (test_id,)))
            if not rows or rows[0]["scrubbed"]:
                return False
            docs = {str(k): json.loads(b) for k, b in conn.execute(
                "SELECT kind, body FROM evidence WHERE test_id=?", (test_id,))}
            self._scrub_in_txn(conn, rows[0], docs, scrub)
            return True
        return bool(self.store.write(job))

    def delete_tests(self, ids: Sequence[str]) -> dict[str, int]:
        ids = list(ids)

        def job(conn: sqlite3.Connection) -> dict[str, int]:
            out = {"tests": 0, "evidence": 0, "diagnoses": 0}
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                marks = ",".join("?" * len(chunk))
                out["evidence"] += conn.execute(f"DELETE FROM evidence WHERE test_id IN ({marks})", chunk).rowcount   # noqa: S608
                out["diagnoses"] += conn.execute(f"DELETE FROM diagnoses WHERE test_id IN ({marks})", chunk).rowcount  # noqa: S608
                out["tests"] += conn.execute(f"DELETE FROM speedtests WHERE id IN ({marks})", chunk).rowcount  # noqa: S608
            return out
        return dict(self.store.write(job)) if ids else {"tests": 0, "evidence": 0, "diagnoses": 0}

    def expired_ids(self, cutoff_ms: int, limit: int = 5000) -> list[str]:
        with self.store.reader() as conn:
            return [str(r[0]) for r in conn.execute(
                "SELECT id FROM speedtests WHERE ended_ms<? ORDER BY ended_ms LIMIT ?", (cutoff_ms, limit))]

    def audit(self, ts_ms: int, actor: str, action: str, subject: str, matched: int, dry_run: bool) -> None:
        def job(conn: sqlite3.Connection) -> None:
            conn.execute("INSERT INTO speedtest_audit(ts_ms,actor,action,subject,matched,dry_run) VALUES(?,?,?,?,?,?)",
                         (ts_ms, actor[:128], action[:32], subject[:128], matched, int(dry_run)))
        self.store.write(job)

    def prune_audit(self, cutoff_ms: int) -> int:
        def job(conn: sqlite3.Connection) -> int:
            return conn.execute("DELETE FROM speedtest_audit WHERE ts_ms<?", (cutoff_ms,)).rowcount
        return int(self.store.write(job))

    def audit_rows(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.store.reader() as conn:
            return _dicts(conn.execute("SELECT * FROM speedtest_audit ORDER BY seq DESC LIMIT ?", (limit,)))

    def orphan_evidence(self, ids: Iterable[str] = ()) -> int:
        with self.store.reader() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM evidence WHERE test_id NOT IN (SELECT id FROM speedtests)"
                                    ).fetchone()[0])
