"""Shipper (02-probe.md section 6, 01-contracts.md section 4): spool -> collector over pinned TLS.

Oldest-first batches of <= 500 records and <= 1 MiB gzip, POSTed to ``/ingest/v1/measurements`` with
``Authorization: Bearer expi_...``. The status table of the contract drives the behaviour:

  200  delete every line of the batch (accepted + duplicate + rejected); log rejects
  400  log, split the batch, retry (a single bad line is dropped and counted)
  401  stop pushing, state ``auth_failed``, one attempt every 60 s
  413  split (a single oversized line is dropped and counted); 415 treated as a transient error
  429  wait ``Retry-After``
  503 / network / TLS errors  exponential backoff 1 s -> 60 s with full jitter

The certificate pin (exp_common.tlspin) is the only trust anchor: on a mismatch NOTHING is sent,
the state becomes ``tls_pin_mismatch`` and there is never an unpinned fallback. Fallback URLs are
tried in order once the primary has been unreachable for more than 60 s. The ingest token is read
from the credential on every attempt and never logged.
"""
from __future__ import annotations

import gzip
import http.client
import json
import logging
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from exp_common import creds as exp_creds
from exp_common import ids, tlspin

from . import __version__
from .config import Collector
from .spool import Spool

log = logging.getLogger(__name__)

MAX_RECORDS = 500
MAX_GZIP_BYTES = 1024 * 1024
MAX_RAW_BYTES = 8 * 1024 * 1024
INGEST_PATH = "/ingest/v1/measurements"
AUTH_RETRY_S = 60.0
FALLBACK_AFTER_S = 60.0
BACKOFF_MIN_S = 1.0
BACKOFF_MAX_S = 60.0
RETRY_AFTER_MAX_S = 300.0
IDLE_POLL_S = 0.5
COALESCE_S = 0.2

# shipper states (health facts / status.json)
S_IDLE, S_OK, S_AUTH, S_PIN, S_DOWN, S_THROTTLED, S_ERROR, S_NO_COLLECTOR = (
    "idle", "ok", "auth_failed", "tls_pin_mismatch", "unreachable", "throttled", "error", "no_collector")


@dataclass
class Post:
    kind: str                       # ok | split | auth | pin | down | throttle | error
    status: int = 0
    retry_after: float = 0.0
    result: dict[str, Any] | None = None
    note: str = ""


def parse_retry_after(value: str | None, default: float = 5.0) -> float:
    try:
        v = float((value or "").strip())
    except ValueError:
        return default
    if v != v or v < 0:           # NaN / negative
        return default
    return min(max(v, 1.0), RETRY_AFTER_MAX_S)


def build_batch(records: list[tuple[str, bytes]]) -> tuple[list[tuple[str, bytes]], bytes]:
    """Largest prefix of `records` whose gzip fits MAX_GZIP_BYTES; returns (prefix, gzip body)."""
    n = min(len(records), MAX_RECORDS)
    raw = 0
    for i in range(n):
        raw += len(records[i][1]) + 1
        if raw > MAX_RAW_BYTES:
            n = max(1, i)
            break
    while True:
        batch = records[:n]
        body = gzip.compress(b"\n".join(b for _, b in batch) + b"\n", compresslevel=5, mtime=0)
        if len(body) <= MAX_GZIP_BYTES or n == 1:
            return batch, body
        n = max(1, n // 2)


class Shipper:
    def __init__(self, collector: Collector | None, spool: Spool, token_provider: Callable[[], str], *,
                 clock: Callable[[], float] = time.time, rng: Callable[[], float] = random.random,
                 request: Callable[..., tlspin.Response] = tlspin.request,
                 on_state: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.collector = collector
        self.spool = spool
        self.token_provider = token_provider
        self.clock = clock
        self.rng = rng
        self.request = request
        self.on_state = on_state
        self.wake = threading.Event()
        self.state = S_NO_COLLECTOR if collector is None else S_IDLE
        self.detail = ""
        self.collector_reachable: bool | None = None
        self.shipped_total = 0
        self.rejected_total = 0
        self.poison_total = 0
        self.last_ok: float | None = None
        self.last_attempt: float | None = None
        self.fail_count = 0
        self.unreachable_since: float | None = None
        self._next_attempt = 0.0
        self._url_idx = 0
        self._fallback_since = 0.0
        self.active_url = collector.url if collector else None

    # ------------------------------------------------------------------------------ public
    def notify(self) -> None:
        """A measurement was spooled: wake the loop (it coalesces for COALESCE_S then ships)."""
        self.wake.set()

    def status(self) -> dict[str, Any]:
        return {"state": self.state, "detail": self.detail, "collector_reachable": self.collector_reachable,
                "active_url": self.active_url, "last_ok": self.last_ok, "last_attempt": self.last_attempt,
                "shipped_total": self.shipped_total, "rejected_total": self.rejected_total,
                "poison_total": self.poison_total, "consecutive_failures": self.fail_count}

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            delay = self.step()
            if delay > 0:
                if self.wake.wait(min(delay, 5.0)) and delay <= IDLE_POLL_S + 1e-9:
                    stop.wait(COALESCE_S)          # let one beat's records land together
                self.wake.clear()

    def step(self) -> float:
        """One scheduling step. Returns seconds to wait before the next step (0 = go again now)."""
        if self.collector is None:
            self._set(S_NO_COLLECTOR, "no collector configured; measuring and spooling")
            return 5.0
        now = self.clock()
        if now < self._next_attempt:
            return self._next_attempt - now
        records = self.spool.fetch(MAX_RECORDS * 2)
        if not records:
            if self.state in (S_OK, S_IDLE):
                self._set(S_IDLE if self.last_ok is None else S_OK, "")
            return IDLE_POLL_S
        self.last_attempt = now
        batch, body = build_batch(records)
        outcome = self._deliver(batch, body)
        if outcome == "ok":
            return 0.0 if self.spool.stat()["depth"] > 0 else IDLE_POLL_S
        return max(0.0, self._next_attempt - self.clock())

    # ----------------------------------------------------------------------------- internals
    def _set(self, state: str, detail: str = "") -> None:
        changed = state != self.state or detail != self.detail
        self.state, self.detail = state, detail
        if changed:
            if state in (S_AUTH, S_PIN, S_DOWN, S_ERROR):
                log.warning("shipper state %s: %s", state, detail)
            else:
                log.info("shipper state %s %s", state, detail)
            if self.on_state:
                self.on_state(self.status())

    def _deliver(self, batch: list[tuple[str, bytes]], body: bytes) -> str:
        work: list[tuple[list[tuple[str, bytes]], bytes | None]] = [(batch, body)]
        while work:
            recs, gz = work.pop(0)
            if gz is None:
                recs, gz = build_batch(recs)
            res = self._post(recs, gz)
            if res.kind == "ok":
                self._on_success(recs, res)
            elif res.kind == "split":
                if len(recs) > 1:
                    h = len(recs) // 2
                    log.warning("collector answered %d: splitting a batch of %d", res.status, len(recs))
                    work[0:0] = [(recs[:h], None), (recs[h:], None)]
                else:
                    log.error("collector refused record %s with %d (%s): dropping it", recs[0][0], res.status, res.note)
                    self.spool.delete([recs[0][0]])
                    self.poison_total += 1
            else:
                self._on_failure(res)
                return res.kind
        return "ok"

    def _collector(self) -> Collector:
        if self.collector is None:
            raise RuntimeError("no collector configured")
        return self.collector

    def _candidate_url(self) -> str:
        urls = self._collector().urls
        if self._url_idx and self.clock() - self._fallback_since >= FALLBACK_AFTER_S:
            return urls[0]               # periodically retry the primary while on a fallback
        return urls[self._url_idx]

    def _post(self, recs: list[tuple[str, bytes]], gz: bytes) -> Post:
        collector = self._collector()
        try:
            token = self.token_provider()
        except exp_creds.CredentialError as exc:
            return Post("auth", note=f"ingest token unavailable: {exc}")
        if not ids.is_token(token, "expi_"):
            return Post("auth", note="ingest token is empty or malformed")
        base = self._candidate_url()
        self.active_url = base
        try:
            resp = self.request(
                "POST", base + INGEST_PATH, collector.fingerprint, body=gz,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/x-ndjson",
                         "Content-Encoding": "gzip", "User-Agent": f"exp-probe/{__version__}"},
                connect_timeout=5.0, read_timeout=15.0, total_timeout=30.0, max_response_bytes=1024 * 1024)
        except tlspin.PinMismatch as exc:
            return Post("pin", note=f"certificate of {base} does not match the pin (got {exc.actual})")
        except (tlspin.TlsPinError, OSError, ValueError, http.client.HTTPException) as exc:
            # ssl.SSLError is an OSError; HTTPException means the connection died mid-request
            return Post("down", note=f"{type(exc).__name__}: {exc}"[:200])
        st = resp.status
        if st == 200:
            try:
                doc = json.loads(resp.body.decode("utf-8"))
                ok = (isinstance(doc, dict) and isinstance(doc["accepted"], int) and isinstance(doc["duplicates"], int)
                      and isinstance(doc["rejected"], list))
                if ok and doc["accepted"] + doc["duplicates"] + len(doc["rejected"]) != len(recs):
                    return Post("error", st, note="collector line counts do not add up; keeping the batch")
            except (ValueError, KeyError, UnicodeDecodeError):
                return Post("error", st, note="unparseable 200 response; keeping the batch")
            if not ok:
                return Post("error", st, note="malformed 200 response; keeping the batch")
            return Post("ok", st, result=doc)
        if st in (400, 413):
            return Post("split", st, note=_err_code(resp.body))
        if st == 401:
            return Post("auth", st, note="collector refused the ingest token (401)")
        if st == 429:
            return Post("throttle", st, retry_after=parse_retry_after(resp.headers.get("retry-after")))
        return Post("error", st, note=f"collector answered {st}")   # 503, 415, 5xx

    def _on_success(self, recs: list[tuple[str, bytes]], res: Post) -> None:
        doc = res.result or {}
        self.spool.delete([i for i, _ in recs])
        rej = doc.get("rejected") or []
        self.shipped_total += int(doc.get("accepted", 0)) + int(doc.get("duplicates", 0))
        self.rejected_total += len(rej)
        for r in rej[:5]:
            err = (r.get("error") or {}) if isinstance(r, dict) else {}
            log.warning("collector rejected line %s (%s): %s", r.get("line") if isinstance(r, dict) else "?",
                        r.get("id") if isinstance(r, dict) else "?", str(err.get("code"))[:64])
        if len(rej) > 5:
            log.warning("... and %d more rejected lines", len(rej) - 5)
        self.last_ok = self.clock()
        self.collector_reachable = True
        self.fail_count = 0
        self.unreachable_since = None
        self._next_attempt = 0.0
        if self._url_idx and self.active_url == (self.collector.url if self.collector else None):
            self._url_idx = 0
        self._set(S_OK, "")

    def _on_failure(self, res: Post) -> None:
        now = self.clock()
        if res.kind == "auth":
            self.collector_reachable = True if res.status else self.collector_reachable
            self._next_attempt = now + AUTH_RETRY_S
            self.fail_count += 1
            self._set(S_AUTH, res.note)
            return
        if res.kind == "throttle":
            self.collector_reachable = True
            self._next_attempt = now + res.retry_after
            self._set(S_THROTTLED, f"collector asked to wait {res.retry_after:.0f}s")
            return
        # pin mismatch / unreachable / 5xx: exponential backoff with full jitter
        self.fail_count += 1
        if res.kind in ("pin", "down"):
            self.collector_reachable = False
        elif res.status:
            self.collector_reachable = True
        if self.unreachable_since is None:
            self.unreachable_since = now
        cap = min(BACKOFF_MAX_S, BACKOFF_MIN_S * (2 ** (self.fail_count - 1)))
        self._next_attempt = now + self.rng() * cap
        self._advance_fallback(now)
        self._set(S_PIN if res.kind == "pin" else (S_DOWN if res.kind == "down" else S_ERROR), res.note)

    def _advance_fallback(self, now: float) -> None:
        """After the primary was unreachable for > 60 s, try the fallbacks in order."""
        collector = self._collector()
        fb = len(collector.fallback)
        if not fb:
            return
        if self._url_idx == 0:
            if self.unreachable_since is not None and now - self.unreachable_since > FALLBACK_AFTER_S:
                self._url_idx, self._fallback_since = 1, now
        elif self.active_url == collector.url:
            self._fallback_since = now            # the periodic primary retry failed: stay on the fallback
        else:
            self._url_idx = self._url_idx % fb + 1
            self._fallback_since = now


def _err_code(body: bytes) -> str:
    try:
        return str(json.loads(body.decode("utf-8"))["error"]["code"])[:64]
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return ""
