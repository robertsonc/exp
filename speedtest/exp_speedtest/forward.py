"""speedtest -> collector (01-contracts.md section 14.5): result ingest, user-safe status read, comment relay.

Every call is pinned TLS (``exp_common.tlspin``; the pin is the only trust anchor, there is never an unpinned fallback) with
the ``exps_`` token read from the credential on every attempt (a rotation needs no restart) and a timeout on every
network operation. Delivery is durable: a result is written to the on-disk spool FIRST, then tried once synchronously
(so the page can get the quick diagnosis in the same answer), and otherwise retried by the background loop with
exponential backoff. Idempotent by test id: the collector answers ``duplicate`` for a repeat, so a retry after a lost
response is harmless. Only idempotent calls are retried.

Status handling: 200/201 delivered; 400/403/413 the collector will never accept this body (dropped and counted, the quarantine
is a log line, never the body); 401 auth problem (retry every 60 s, health ``fail``); pin mismatch (nothing was sent;
health ``fail``); 429 honour Retry-After; 5xx / network / timeout back off 1 s -> 60 s with jitter; 404 on a comment means
the test has not reached the collector yet (retry, bounded).
"""
from __future__ import annotations

import dataclasses
import json
import logging
import random
import threading
import time
from collections.abc import Callable
from typing import Any

from exp_common import creds as exp_creds
from exp_common import tlspin

from .config import CollectorRef
from .store import Store

log = logging.getLogger(__name__)

SYNC_TIMEOUTS = (2.0, 3.0, 4.0)          # connect, read, total for the in-request attempt
BG_TIMEOUTS = (3.0, 10.0, 15.0)
BACKOFF_MIN_S, BACKOFF_MAX_S = 1.0, 60.0
AUTH_RETRY_S = 60.0
COMMENT_404_MAX = 30
MAX_RESPONSE = 256 * 1024
S_IDLE, S_OK, S_AUTH, S_PIN, S_DOWN = "idle", "ok", "auth_failed", "tls_pin_mismatch", "unreachable"


@dataclasses.dataclass
class Outcome:
    kind: str                     # ok | drop | auth | pin | throttle | down | notfound
    status: int = 0
    body: dict[str, Any] | None = None
    retry_after: float = 0.0
    note: str = ""


def _retry_after(headers: dict[str, str], default: float = 5.0) -> float:
    try:
        v = float(headers.get("retry-after", ""))
    except ValueError:
        return default
    return default if v != v or v < 0 else min(max(v, 1.0), 300.0)


class CollectorClient:
    def __init__(self, ref: CollectorRef, token: Callable[[], str],
                 request: Callable[..., tlspin.Response] = tlspin.request) -> None:
        self.ref = ref
        self.token = token
        self.request = request
        self._url_idx = 0

    def _urls(self) -> list[str]:
        urls = [self.ref.url, *self.ref.fallback]
        i = self._url_idx % len(urls)
        return urls[i:] + urls[:i]

    def call(self, method: str, path: str, body: dict[str, Any] | None, timeouts: tuple[float, float, float]) -> Outcome:
        try:
            tok = self.token()
        except exp_creds.CredentialError as exc:
            return Outcome("auth", note=f"collector token unavailable: {exc}"[:200])
        headers = {"Authorization": f"Bearer {tok}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        last = Outcome("down", note="no collector url")
        for n, base in enumerate(self._urls()):
            try:
                resp = self.request(method, base.rstrip("/") + "/api/v1" + path, self.ref.tls_fingerprint_sha256, body=data,
                                    headers=headers, connect_timeout=timeouts[0], read_timeout=timeouts[1],
                                    total_timeout=timeouts[2], max_response_bytes=MAX_RESPONSE)
            except tlspin.PinMismatch as exc:
                return Outcome("pin", note=str(exc)[:200])
            except Exception as exc:               # every other transport failure is "down" (retry with backoff)
                last = Outcome("down", note=f"{type(exc).__name__}"[:100])
                continue
            self._url_idx = (self._url_idx + n) % max(1, len(self._urls()))
            return self._classify(resp)
        return last

    @staticmethod
    def _classify(resp: tlspin.Response) -> Outcome:
        st = resp.status
        doc: dict[str, Any] | None = None
        if resp.body:
            try:
                parsed = json.loads(resp.body)
                doc = parsed if isinstance(parsed, dict) else None
            except ValueError:
                doc = None
        if st in (200, 201, 204):
            return Outcome("ok", st, doc)
        if st == 401:
            return Outcome("auth", st, note="collector refused the speedtest token")
        if st == 404:
            return Outcome("notfound", st)
        if st == 429:
            return Outcome("throttle", st, retry_after=_retry_after(resp.headers))
        if st in (400, 403, 413, 415, 422):
            code = ((doc or {}).get("error") or {}).get("code", "")
            return Outcome("drop", st, note=str(code)[:64])
        return Outcome("down", st, retry_after=_retry_after(resp.headers, 0.0) if st == 503 else 0.0, note=f"http {st}")

    # --------------------------------------------------------------------------------------------- calls
    def post_result(self, doc: dict[str, Any], sync: bool = False) -> Outcome:
        return self.call("POST", "/speedtests", doc, SYNC_TIMEOUTS if sync else BG_TIMEOUTS)

    def get_status(self, test_id: str) -> Outcome:
        return self.call("GET", f"/speedtests/{test_id}/status", None, SYNC_TIMEOUTS)

    def post_comment(self, test_id: str, comment: str, sync: bool = False) -> Outcome:
        return self.call("POST", f"/speedtests/{test_id}/comment", {"comment": comment}, SYNC_TIMEOUTS if sync else BG_TIMEOUTS)


class Forwarder:
    """Durable delivery of results and comments."""

    def __init__(self, client: CollectorClient, store: Store, clock: Callable[[], float] = time.time,
                 rng: Callable[[], float] = random.random) -> None:
        self.client, self.store, self.clock, self.rng = client, store, clock, rng
        self.state = S_IDLE
        self.detail = ""
        self.collector_reachable: bool | None = None
        self.last_ok: float | None = None
        self.delivered_total = 0
        self.dropped_total = 0
        self.wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---------------------------------------------------------------------------------------------- state
    def _set(self, state: str, detail: str = "") -> None:
        if (state, detail) != (self.state, self.detail):
            (log.warning if state in (S_AUTH, S_PIN, S_DOWN) else log.info)("collector link %s %s", state, detail)
        self.state, self.detail = state, detail

    def _backoff(self, attempts: int) -> float:
        return min(BACKOFF_MAX_S, BACKOFF_MIN_S * (2 ** min(attempts, 7))) * (0.5 + 0.5 * self.rng())

    def status(self) -> dict[str, Any]:
        return {"state": self.state, "detail": self.detail, "collector_reachable": self.collector_reachable,
                "last_ok": self.last_ok, "delivered_total": self.delivered_total, "dropped_total": self.dropped_total,
                **self.store.spool_stat(self.clock())}

    # ------------------------------------------------------------------------------------------ enqueue
    def enqueue_result(self, doc: dict[str, Any]) -> int:
        """Durably queue a result (raises store.SpoolFull when the spool is at its bound)."""
        return self.store.spool_add("result", doc["id"], json.dumps(doc, separators=(",", ":")), self.clock())

    def enqueue_comment(self, sid: str, comment: str) -> int:
        return self.store.spool_add("comment", sid, json.dumps({"comment": comment}), self.clock())

    # ----------------------------------------------------------------------------------------- delivery
    def attempt(self, seq: int, sync: bool = False) -> Outcome | None:
        """Try one spool row now. Returns the collector's outcome (``ok`` outcomes carry the body)."""
        row = self.store.spool_get(seq)
        if row is None:
            return None
        self.store.spool_claim(seq, self.clock() + (20.0 if sync else 60.0))
        try:
            body = json.loads(row["body"])
        except ValueError:
            self.store.spool_done(seq)
            return Outcome("drop", note="unreadable spool row")
        if row["kind"] == "result":
            out = self.client.post_result(body, sync=sync)
        else:
            out = self.client.post_comment(row["sid"], body["comment"], sync=sync)
        self._apply(row, out)
        return out

    def _apply(self, row: dict[str, Any], out: Outcome) -> None:
        seq, attempts = row["seq"], row["attempts"] + 1
        now = self.clock()
        if out.kind == "ok":
            self.store.spool_done(seq)
            self.delivered_total += 1
            self.last_ok, self.collector_reachable = now, True
            self._set(S_OK)
        elif out.kind == "drop":
            log.error("collector refused %s %s with %s (%s): dropping it", row["kind"], row["sid"], out.status, out.note)
            self.store.spool_done(seq)
            self.dropped_total += 1
            self.collector_reachable = True
        elif out.kind == "notfound" and row["kind"] == "comment":
            if attempts >= COMMENT_404_MAX:
                self.store.spool_done(seq)
                self.dropped_total += 1
            else:
                self.store.spool_retry(seq, attempts, now + 5.0)
        elif out.kind == "auth":
            self.collector_reachable = True
            self._set(S_AUTH, out.note)
            self.store.spool_retry(seq, attempts, now + AUTH_RETRY_S)
        elif out.kind == "pin":
            self._set(S_PIN, out.note)
            self.store.spool_retry(seq, attempts, now + AUTH_RETRY_S)
        elif out.kind == "throttle":
            self.store.spool_retry(seq, attempts, now + out.retry_after)
        else:
            self.collector_reachable = False
            self._set(S_DOWN, out.note)
            self.store.spool_retry(seq, attempts, now + max(out.retry_after, self._backoff(attempts)))

    def step(self) -> int:
        """Deliver every due row once; returns how many rows were attempted."""
        n = 0
        for row in self.store.spool_due(self.clock(), 20):
            out = self.attempt(row["seq"])
            n += 1
            if out is not None and out.kind in ("down", "pin", "auth", "throttle"):
                break                                    # the link is bad: do not hammer it row by row
        self.store.spool_expire(self.clock())
        return n

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="forwarder", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.wake.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.step()
            except Exception:
                log.exception("forwarder step failed")
            self.wake.wait(1.0)
            self.wake.clear()
