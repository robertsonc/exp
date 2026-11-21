"""Server-sent events for ``GET speedtests/stream`` (same keepalive / replay rules as the probe stream, 01 section 5).

Events: ``speedtest`` (a test was stored), ``evidence`` (a kind arrived), ``diagnosis`` (quick or final). Event ids
are ``<boot>.<n>`` like the probe stream; replay covers at most ``replay_s`` seconds. A client that falls behind is
disconnected (it reconnects and resumes), the producer never blocks. No raw identifier is ever in an event.
"""
from __future__ import annotations

import collections
import json
import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .. import sse

log = logging.getLogger(__name__)

KINDS = ("speedtest", "evidence", "diagnosis")
QUEUE_MAX = 1000
MAX_CLIENTS = 64
RING_MAX = 20_000
_CLOSE = object()


@dataclass(frozen=True)
class StEvent:
    seq: int
    id: str
    kind: str
    site: str
    data: str
    at: float

    def wire(self) -> bytes:
        return f"id: {self.id}\nevent: {self.kind}\ndata: {self.data}\n\n".encode()


@dataclass(eq=False)
class StClient:
    site: str | None
    q: queue.Queue[Any] = field(default_factory=lambda: queue.Queue(maxsize=QUEUE_MAX))
    backlog: list[StEvent] = field(default_factory=list)
    closed: bool = False

    def wants(self, ev: StEvent) -> bool:
        return self.site is None or ev.site == self.site


class StHub:
    def __init__(self, *, clock: Callable[[], float] = time.time, replay_s: float = 300.0,
                 queue_max: int = QUEUE_MAX, max_clients: int = MAX_CLIENTS) -> None:
        self._clock = clock
        self.replay_s = replay_s
        self.queue_max = queue_max
        self.max_clients = max_clients
        self.keepalive_s = sse.KEEPALIVE_S
        self._lock = threading.Lock()
        self._clients: set[StClient] = set()
        self._ring: collections.deque[StEvent] = collections.deque()
        self._seq = 0
        self.boot = format(int(clock()), "x")
        self._closed = False
        self.dropped_clients = 0

    def client_count(self) -> int:
        return len(self._clients)

    def publish(self, kind: str, site: str, payload: dict[str, Any]) -> None:
        if kind not in KINDS:
            return
        data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        now = self._clock()
        with self._lock:
            if self._closed:
                return
            self._seq += 1
            ev = StEvent(self._seq, f"{self.boot}.{self._seq}", kind, site, data, now)
            self._ring.append(ev)
            horizon = now - self.replay_s
            while self._ring and (self._ring[0].at < horizon or len(self._ring) > RING_MAX):
                self._ring.popleft()
            for c in list(self._clients):
                if not c.wants(ev):
                    continue
                try:
                    c.q.put_nowait(ev)
                except queue.Full:
                    self._drop_locked(c)

    def _drop_locked(self, c: StClient) -> None:
        self._clients.discard(c)
        c.closed = True
        self.dropped_clients += 1
        try:
            while True:
                c.q.get_nowait()
        except queue.Empty:
            pass
        try:
            c.q.put_nowait(_CLOSE)
        except queue.Full:  # pragma: no cover
            pass
        log.info("speedtest SSE client disconnected: too slow")

    def subscribe(self, site: str | None, last_event_id: str | None) -> StClient:
        c = StClient(site)
        c.q = queue.Queue(maxsize=self.queue_max)
        with self._lock:
            if self._closed or len(self._clients) >= self.max_clients:
                raise sse.TooManyClients("too many SSE clients")
            if last_event_id:
                boot, _, num = last_event_id.partition(".")
                if boot == self.boot and num.isdigit():
                    horizon = self._clock() - self.replay_s
                    c.backlog = [e for e in self._ring if e.seq > int(num) and e.at >= horizon and c.wants(e)]
            self._clients.add(c)
        return c

    def unsubscribe(self, c: StClient) -> None:
        with self._lock:
            self._clients.discard(c)
            c.closed = True

    def next_event(self, c: StClient, timeout: float) -> StEvent | None | str:
        if c.backlog:
            return c.backlog.pop(0)
        if c.closed and c.q.empty():
            return "closed"
        try:
            item = c.q.get(timeout=timeout)
        except queue.Empty:
            return "closed" if c.closed else None
        return "closed" if item is _CLOSE else item  # type: ignore[no-any-return]

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for c in list(self._clients):
                self._drop_locked(c)
                self.dropped_clients -= 1
            self._clients.clear()
