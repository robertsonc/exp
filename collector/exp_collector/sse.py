"""Server-sent events hub (03-collector.md section 7, 01-contracts.md section 5).

Ported from reference/exm/lib/exm/web.py (``Hub``: subscribe / unsubscribe, a bounded queue per page, the
slow reader is dropped rather than the producer blocked), extended with:

* event ids and a 5-minute ring buffer so a client can resume with ``Last-Event-ID``;
* per-client filters (``probes=a,b`` or ``site=x``);
* bounded per-client queue (1,000 events): a client that falls behind is disconnected (it reconnects and
  resumes from the ring buffer) -- the producer never blocks;
* ``retry: 3000`` and a ``: keepalive`` comment every 15 s.

Event ids are ``<boot>.<n>``: ``boot`` changes on every collector start, so an id from before a restart
is recognised as foreign and nothing is replayed (the dashboard re-reads ``states`` on reconnect anyway).
"""
from __future__ import annotations

import collections
import json
import logging
import queue
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

QUEUE_MAX = 1000
RING_SECONDS = 300.0
RING_MAX = 200_000
KEEPALIVE_S = 15.0
RETRY_MS = 3000
MAX_CLIENTS = 256
KINDS = ("beat", "state", "incident")
_CLOSE = object()


@dataclass(frozen=True)
class Event:
    seq: int
    id: str
    kind: str
    probe: str
    site: str | None
    data: str                 # JSON text of the payload
    at: float                 # wall time it was published

    def wire(self) -> bytes:
        return f"id: {self.id}\nevent: {self.kind}\ndata: {self.data}\n\n".encode()


@dataclass
class Client:
    probes: frozenset[str] | None
    site: str | None
    q: queue.Queue[Any] = field(default_factory=lambda: queue.Queue(maxsize=QUEUE_MAX))
    backlog: list[Event] = field(default_factory=list)       # replay, written first (not queue-bounded)
    closed: bool = False
    reason: str = ""
    sent: int = 0

    def wants(self, ev: Event) -> bool:
        if self.probes is not None:
            return ev.probe in self.probes
        return self.site is not None and ev.site == self.site


class TooManyClients(Exception):
    pass


class Hub:
    def __init__(self, *, site_of: Callable[[str], str | None] | None = None,
                 clock: Callable[[], float] = time.time, queue_max: int = QUEUE_MAX,
                 ring_s: float = RING_SECONDS, max_clients: int = MAX_CLIENTS) -> None:
        self._site_of = site_of or (lambda _p: None)
        self._clock = clock
        self.queue_max = queue_max
        self.ring_s = ring_s
        self.max_clients = max_clients
        self._lock = threading.Lock()
        self._clients: set[Client] = set()
        self._ring: collections.deque[Event] = collections.deque()
        self._seq = 0
        self.boot = format(int(clock()), "x")
        self.published = 0
        self.dropped_clients = 0
        self._closed = False

    # --------------------------------------------------------------------------------------- stats
    def client_count(self) -> int:
        return len(self._clients)

    def ring_len(self) -> int:
        return len(self._ring)

    # ----------------------------------------------------------------------------------- producing
    def publish(self, kind: str, payload: dict[str, Any]) -> None:
        """Announce an event. Never blocks: a client whose queue is full is disconnected."""
        if kind not in KINDS:
            return
        probe = payload.get("probe")
        if not isinstance(probe, str):
            return
        site = payload.get("site") if isinstance(payload.get("site"), str) else self._site_of(probe)
        data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        now = self._clock()
        with self._lock:
            if self._closed:
                return
            self._seq += 1
            ev = Event(self._seq, f"{self.boot}.{self._seq}", kind, probe, site, data, now)
            self._ring.append(ev)
            self.published += 1
            horizon = now - self.ring_s
            while self._ring and (self._ring[0].at < horizon or len(self._ring) > RING_MAX):
                self._ring.popleft()
            laggards: list[Client] = []
            for c in self._clients:
                if not c.wants(ev):
                    continue
                try:
                    c.q.put_nowait(ev)
                except queue.Full:
                    laggards.append(c)
            for c in laggards:
                self._drop_locked(c, "too slow: queue overflow")

    def _drop_locked(self, c: Client, reason: str) -> None:
        self._clients.discard(c)
        c.closed, c.reason = True, reason
        self.dropped_clients += 1
        try:                                   # make room for the wake-up sentinel
            while True:
                c.q.get_nowait()
        except queue.Empty:
            pass
        try:
            c.q.put_nowait(_CLOSE)
        except queue.Full:  # pragma: no cover - the queue was just emptied
            pass
        log.info("SSE client disconnected: %s", reason)

    # ----------------------------------------------------------------------------------- consuming
    def subscribe(self, probes: Iterable[str] | None, site: str | None,
                  last_event_id: str | None = None) -> Client:
        client = Client(frozenset(probes) if probes is not None else None, site)
        client.q = queue.Queue(maxsize=self.queue_max)
        with self._lock:
            if self._closed:
                raise TooManyClients("collector is shutting down")
            if len(self._clients) >= self.max_clients:
                raise TooManyClients("too many SSE clients")
            if last_event_id:
                boot, _, num = last_event_id.partition(".")
                if boot == self.boot and num.isdigit():
                    after = int(num)
                    horizon = self._clock() - self.ring_s
                    client.backlog = [e for e in self._ring if e.seq > after and e.at >= horizon and client.wants(e)]
            self._clients.add(client)
        return client

    def unsubscribe(self, c: Client) -> None:
        with self._lock:
            self._clients.discard(c)
            c.closed = True

    def next_event(self, c: Client, timeout: float) -> Event | None | str:
        """Next event for the client: an Event, ``None`` on timeout, or ``"closed"`` when disconnected."""
        if c.backlog:
            return c.backlog.pop(0)
        if c.closed and c.q.empty():
            return "closed"
        try:
            item = c.q.get(timeout=timeout)
        except queue.Empty:
            return "closed" if c.closed else None
        if item is _CLOSE:
            return "closed"
        c.sent += 1
        return item  # type: ignore[no-any-return]

    def close(self) -> None:
        """Shutdown: wake every client so its connection thread ends."""
        with self._lock:
            self._closed = True
            for c in list(self._clients):
                self._drop_locked(c, "collector shutting down")
                self.dropped_clients -= 1
            self._clients.clear()


def preamble() -> bytes:
    return f"retry: {RETRY_MS}\n\n".encode()


KEEPALIVE = b": keepalive\n\n"
