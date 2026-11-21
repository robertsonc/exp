"""The runner -> speedtest localhost channel (``http://127.0.0.1:<port>/local/v1``, ``expl_`` bearer; 01 section 14.6).

* ``GET where/wanted``: client IPs the page asked "where" for; the runner resolves them and
* ``PUT where``: publishes the cache answers (zone, source, AP, SSID, band, ``nat_suspected``; never a MAC or username);
* ``PUT pause``: publishes EdgeConnect WAN utilization for the internet-leg auto-pause (a stale value is ignored by the
  speedtest: fail open). The EC source registers at r2 through ``PausePublisher.set_source``.

Loopback only: any other host is refused at construction. Every call has a timeout; failures are logged and counted, never raised
into the correlation loop.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import threading
import time
import urllib.parse
from collections.abc import Callable
from typing import Any

from .evidence import _fmt
from .identity import Identity

log = logging.getLogger(__name__)

TIMEOUT_S = 3.0
MAX_BODY = 256 * 1024
WANTED_POLL_S = 2.0
MAX_WANTED = 100


class ChannelError(Exception):
    pass


class SpeedtestChannel:
    def __init__(self, url: str, token: str, *, timeout: float = TIMEOUT_S) -> None:
        u = urllib.parse.urlsplit(url)
        host = u.hostname or ""
        try:
            loop = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loop = False
        if u.scheme != "http" or not loop or u.port is None:
            raise ValueError("the speedtest channel must be http://127.0.0.1:<port>/...")
        self._host, self._port, self._base = host, u.port, u.path.rstrip("/")
        self._token = token
        self._timeout = timeout
        self.last_ok: float | None = None
        self.errors = 0

    def _call(self, method: str, path: str, payload: Any | None = None) -> Any:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            conn.request(method, self._base + path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(MAX_BODY + 1)
        except (OSError, http.client.HTTPException) as exc:
            self.errors += 1
            raise ChannelError(f"{method} {path}: {type(exc).__name__}") from None
        finally:
            conn.close()
        if resp.status != 200 or len(data) > MAX_BODY:
            self.errors += 1
            raise ChannelError(f"{method} {path}: HTTP {resp.status}")
        self.last_ok = time.time()
        try:
            return json.loads(data.decode("utf-8")) if data else {}
        except (ValueError, UnicodeDecodeError):
            raise ChannelError(f"{method} {path}: bad JSON") from None

    def wanted(self) -> list[str]:
        doc = self._call("GET", "/where/wanted")
        out = []
        for it in (doc.get("items") if isinstance(doc, dict) else None) or []:
            ip = it.get("ip") if isinstance(it, dict) else None
            if isinstance(ip, str) and len(out) < MAX_WANTED:
                out.append(ip)
        return out

    def put_where(self, items: list[dict[str, Any]]) -> None:
        if items:
            self._call("PUT", "/where", {"items": items[:100]})

    def put_pause(self, wan_util_pct: float | None, measured_at: float) -> None:
        self._call("PUT", "/pause", {"wan_util_pct": wan_util_pct, "source": "ec", "measured_at": _fmt(measured_at)})


class WhereLoop:
    """Answers the page's "where" questions from identity resolution (Mist cache, DHCP, subnet)."""

    def __init__(self, channel: SpeedtestChannel, resolve: Callable[[str, float], Identity], now_fn: Callable[[], float] = time.time,
                 ttl_s: int = 60) -> None:
        self.channel, self.resolve, self.now, self.ttl_s = channel, resolve, now_fn, ttl_s
        self.answered = 0

    def poll_once(self) -> int:
        try:
            ips = self.channel.wanted()
        except ChannelError as exc:
            log.warning("speedtest channel: %s", exc)
            return 0
        items = []
        for ip in ips:
            try:
                items.append(self.resolve(ip, self.now()).where_item(self.ttl_s))
            except Exception:  # noqa: BLE001 - one bad IP must not stop the rest
                log.exception("where: resolution failed")
        try:
            self.channel.put_where(items)
        except ChannelError as exc:
            log.warning("speedtest channel: %s", exc)
            return 0
        self.answered += len(items)
        return len(items)


class PausePublisher:
    """Publishes WAN utilization from a registered source (EdgeConnect at r2). No source / no value = nothing published,
    so the speedtest's 90-second staleness rule reopens the internet leg (fail open)."""

    def __init__(self, channel: SpeedtestChannel, now_fn: Callable[[], float] = time.time) -> None:
        self.channel, self.now = channel, now_fn
        self._source: Callable[[], float | None] | None = None
        self.published = 0

    def set_source(self, fn: Callable[[], float | None] | None) -> None:
        self._source = fn

    def publish_once(self) -> bool:
        if self._source is None:
            return False
        try:
            value = self._source()
        except Exception:  # noqa: BLE001
            log.warning("wan utilization source failed")
            return False
        if value is None:
            return False
        try:
            self.channel.put_pause(float(max(0.0, min(1000.0, value))), self.now())
        except ChannelError as exc:
            log.warning("speedtest channel: %s", exc)
            return False
        self.published += 1
        return True


def start_thread(name: str, fn: Callable[[], Any], interval_s: float, stop: threading.Event) -> threading.Thread:
    def run() -> None:
        while not stop.wait(interval_s):
            try:
                fn()
            except Exception:  # noqa: BLE001
                log.exception("%s failed", name)
    t = threading.Thread(target=run, name=name, daemon=True)
    t.start()
    return t
