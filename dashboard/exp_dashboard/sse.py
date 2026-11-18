"""SSE multiplexing: one upstream stream per collector, fanned out to every browser client.

Upstream: pinned TLS (``exp_common.tlspin`` helpers), ``Authorization: Bearer expd_``, reconnect
with exponential backoff and ``Last-Event-ID``. Downstream: each browser connection subscribes
with a probe list or a site filter; events get hub ids ``<boot>.<seq>`` and a 5-minute ring
buffer so a reconnecting browser can resume with ``Last-Event-ID``.
"""
from __future__ import annotations

import collections
import http.client
import json
import logging
import queue
import random
import re
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

from exp_common import tlspin

from .auth import user_header
from .config import CollectorCfg

log = logging.getLogger(__name__)

REPLAY_WINDOW_S = 300
RING_MAX = 5000
CLIENT_QUEUE_MAX = 1000
MAX_EVENT_BYTES = 256 * 1024
UPSTREAM_READ_TIMEOUT_S = 45.0
BACKOFF_MIN_S, BACKOFF_MAX_S = 1.0, 30.0
KINDS = ("beat", "state", "incident")
_ID_OK = re.compile(r"^[0-9A-Za-z._:-]{1,128}$")


@dataclass(frozen=True)
class HubEvent:
    seq: int
    ts: float
    kind: str            # beat | state | incident | collector
    probe: str | None
    site: str | None
    collector_id: str
    data: str            # JSON text
    hub_id: str


class _PinnedStreamConnection(http.client.HTTPSConnection):
    """HTTPS connection whose peer leaf certificate must match a pin BEFORE any request bytes."""

    def __init__(self, host: str, port: int, pins: list[str], connect_timeout: float, read_timeout: float):
        super().__init__(host, port, timeout=read_timeout)
        self._pins, self._ct = pins, connect_timeout

    def connect(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE         # the pin replaces CA verification
        raw = socket.create_connection((self.host, self.port), timeout=self._ct)
        try:
            raw.settimeout(self._ct)
            tls = ctx.wrap_socket(raw, server_hostname=None)
            der = tls.getpeercert(binary_form=True)
            if not der or not tlspin.pins_match(der, self._pins):
                tls.close()
                raise tlspin.PinMismatch(tlspin.fingerprint_of_der(der) if der else "none", self._pins)
            tls.settimeout(self.timeout)
        except BaseException:
            raw.close()
            raise
        self.sock = tls


def parse_sse_lines(readline, on_event, stop: threading.Event) -> None:
    """Read an SSE stream. ``on_event(event_name, data, event_id)`` per dispatched event."""
    ev, data, eid = "message", [], None
    size = 0
    while not stop.is_set():
        line = readline(65537)
        if not line:
            return
        if len(line) > 65536:
            raise ValueError("SSE line too long")
        line = line.rstrip(b"\r\n").decode("utf-8", "replace")
        if line == "":
            if data:
                on_event(ev, "\n".join(data), eid)
            ev, data, size = "message", [], 0
            continue
        if line.startswith(":"):
            continue
        name, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        size += len(line)
        if size > MAX_EVENT_BYTES:
            raise ValueError("SSE event too large")
        if name == "event":
            ev = value
        elif name == "data":
            data.append(value)
        elif name == "id":
            eid = value if _ID_OK.match(value) else eid


class Subscription:
    """One browser client. ``probes`` (set) xor ``site`` (str)."""

    def __init__(self, probes: set[str] | None, site: str | None, session_hash: str) -> None:
        self.probes, self.site, self.session_hash = probes, site, session_hash
        self.q: queue.Queue[HubEvent] = queue.Queue(CLIENT_QUEUE_MAX)
        self.dropped = False

    def matches(self, e: HubEvent) -> bool:
        if e.kind == "collector":
            return True
        if self.probes is not None:
            return e.probe in self.probes
        return e.site == self.site


class Hub:
    def __init__(self, collectors: list[CollectorCfg], get_tokens, site_of, clock=time.time) -> None:
        self.collectors = {c.collector_id: c for c in collectors}
        self._get_tokens, self._site_of, self._clock = get_tokens, site_of, clock
        self.boot = format(int(clock()), "x")
        self._seq = 0
        self._ring: collections.deque[HubEvent] = collections.deque(maxlen=RING_MAX)
        self._subs: set[Subscription] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.upstream_up: dict[str, bool] = {c.collector_id: False for c in collectors}
        self._last_id: dict[str, str] = {}

    # -- lifecycle --------------------------------------------------------------------------
    def start(self) -> None:
        for c in self.collectors.values():
            t = threading.Thread(target=self._upstream_loop, args=(c,), name=f"sse-{c.collector_id}",
                                 daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._subs)

    # -- downstream -------------------------------------------------------------------------
    def subscribe(self, sub: Subscription, last_event_id: str | None) -> list[HubEvent]:
        """Register and return the replay batch (events newer than ``last_event_id``, <= 5 min)."""
        replay: list[HubEvent] = []
        with self._lock:
            if last_event_id:
                boot, _, seq = last_event_id.partition(".")
                if boot == self.boot and seq.isdigit():
                    horizon = self._clock() - REPLAY_WINDOW_S
                    replay = [e for e in self._ring
                              if e.seq > int(seq) and e.ts >= horizon and sub.matches(e)
                              and e.kind != "collector"]
            self._subs.add(sub)
        return replay

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            self._subs.discard(sub)

    def drop_session(self, session_hash: str) -> None:
        with self._lock:
            for s in self._subs:
                if s.session_hash == session_hash:
                    s.dropped = True

    def publish(self, kind: str, collector_id: str, data_obj: Any, probe: str | None = None,
                site: str | None = None) -> None:
        text = json.dumps(data_obj, separators=(",", ":"))
        with self._lock:
            self._seq += 1
            e = HubEvent(self._seq, self._clock(), kind, probe, site, collector_id, text,
                         f"{self.boot}.{self._seq}")
            if kind != "collector":
                self._ring.append(e)
            for s in list(self._subs):
                if not s.matches(e):
                    continue
                try:
                    s.q.put_nowait(e)
                except queue.Full:
                    s.dropped = True        # slow client: close; it resumes with Last-Event-ID

    # -- upstream ---------------------------------------------------------------------------
    def _on_upstream_event(self, c: CollectorCfg, name: str, data: str, eid: str | None) -> None:
        if eid:
            self._last_id[c.collector_id] = eid
        if name not in KINDS:
            return
        try:
            obj = json.loads(data)
        except (ValueError, RecursionError):
            log.warning("collector %s sent invalid SSE data", c.collector_id)
            return
        if not isinstance(obj, dict):
            return
        probe = obj.get("probe") if isinstance(obj.get("probe"), str) else None
        site = obj.get("site") if isinstance(obj.get("site"), str) else None
        if site is None:
            site = self._site_of(probe, c.collector_id) if probe else c.site
        obj["collector_id"] = c.collector_id
        self.publish(name, c.collector_id, obj, probe, site)

    def _set_up(self, c: CollectorCfg, up: bool) -> None:
        if self.upstream_up.get(c.collector_id) is not up:
            self.upstream_up[c.collector_id] = up
            self.publish("collector", c.collector_id,
                         {"collector_id": c.collector_id, "site": c.site, "ok": up})

    def _upstream_loop(self, c: CollectorCfg) -> None:
        backoff = BACKOFF_MIN_S
        while not self._stop.is_set():
            conn = None
            connected = False
            try:
                token = self._get_tokens().get(c.collector_id)
                if not token:
                    raise OSError("no credential")
                u = urllib.parse.urlsplit(c.url)
                conn = _PinnedStreamConnection(u.hostname or "", u.port or 443, [c.pin], 3.0,
                                               UPSTREAM_READ_TIMEOUT_S)
                headers = {"Authorization": f"Bearer {token}", "Accept": "text/event-stream",
                           "X-Exp-User": user_header("dashboard")}
                last = self._last_id.get(c.collector_id)
                if last:
                    headers["Last-Event-ID"] = last
                conn.request("GET", "/api/v1/stream?" + urllib.parse.urlencode({"site": c.site}),
                             headers=headers)
                resp = conn.getresponse()
                if resp.status != 200:
                    raise OSError(f"upstream status {resp.status}")
                connected = True
                self._set_up(c, True)
                backoff = BACKOFF_MIN_S
                parse_sse_lines(resp.readline, lambda n, d, i: self._on_upstream_event(c, n, d, i),
                                self._stop)
            except tlspin.PinMismatch:
                log.error("collector %s stream: TLS pin mismatch", c.collector_id)
            except (OSError, ValueError, http.client.HTTPException, tlspin.TlsPinError) as exc:
                log.info("collector %s stream ended: %s", c.collector_id, type(exc).__name__)
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except OSError:
                        pass
            self._set_up(c, False)
            if self._stop.is_set():
                return
            delay = backoff * (0.75 + random.random() * 0.5)   # noqa: S311 - jitter, not security
            if connected:
                delay = min(delay, BACKOFF_MIN_S * 1.5)
            self._stop.wait(delay)
            backoff = min(backoff * 2, BACKOFF_MAX_S)


def format_event(e: HubEvent) -> bytes:
    return f"event: {e.kind}\nid: {e.hub_id}\ndata: {e.data}\n\n".encode()
