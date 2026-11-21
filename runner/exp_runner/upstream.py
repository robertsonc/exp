"""A small, bounded JSON-over-HTTP client for the vendor APIs the connectors read (Mist, EdgeConnect Orchestrator).

Rules (SR-21..26, 12 section 5.2):

* ``https`` always; plain ``http`` only for a loopback host (the test fakes). Certificates are verified with the platform trust
  store (``SSL_CERT_FILE`` can add a private CA); verification is never switched off.
* Every call has a connect/read timeout, a response size cap and counts against the per-test :class:`CallBudget` (each *attempt*
  counts, a retry too: the shared token has an hourly quota).
* Only idempotent reads retry (timeouts, transport errors, 5xx) with bounded exponential backoff, never past the call budget or
  the connector deadline. A ``429`` is never retried inside a test: the client remembers it (``Retry-After`` when sent, else a
  default) and fails fast until the pause is over, protecting the shared token.
* Secrets travel only in the headers dict handed in by the caller; they are never part of a log line, an exception message or a path.
"""
from __future__ import annotations

import dataclasses
import http.client
import ipaddress
import json
import logging
import math
import re
import ssl
import threading
import time
import urllib.parse
from collections import OrderedDict
from collections.abc import Callable, Mapping
from typing import Any

from .connectors import CallBudget

log = logging.getLogger(__name__)

CONNECT_TIMEOUT_S = 5.0
READ_TIMEOUT_S = 8.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
RATE_LIMIT_PAUSE_S = 30.0
RATE_LIMIT_PAUSE_MAX_S = 300.0
BACKOFF_MAX_S = 4.0


@dataclasses.dataclass
class Scope:
    """Per-call-chain budget + deadline."""

    budget: CallBudget
    deadline: float
    failed: str | None = None      # set by a caller after a failure that makes the rest of the chain pointless


class UpstreamError(Exception):
    """``kind``: http, auth, not_found, rate_limited, transport, timeout, budget, deadline or bad_response."""

    def __init__(self, kind: str, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.kind = kind
        self.status = status


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


class UpstreamClient:
    def __init__(self, name: str, base_url: str, headers: Mapping[str, str], *, timeout_s: float = READ_TIMEOUT_S, retries: int = 1,
                 backoff_s: float = 0.5, max_bytes: int = MAX_RESPONSE_BYTES, ca_file: str | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> None:
        u = urllib.parse.urlsplit(base_url)
        if not u.hostname or u.scheme not in ("http", "https") or u.username or u.password:
            raise ValueError(f"{name}: the base URL must be https://host[:port][/prefix] without credentials")
        if u.scheme == "http" and not _is_loopback(u.hostname):
            raise ValueError(f"{name}: plain http is only accepted for a loopback host")
        self.name = name
        self._scheme, self._host, self._port = u.scheme, u.hostname, u.port
        self._prefix = u.path.rstrip("/")
        self._headers = dict(headers)
        self.timeout_s = timeout_s
        self.retries = max(0, int(retries))
        self.backoff_s = backoff_s
        self.max_bytes = int(max_bytes)
        self._sleep, self._clock = sleep, clock
        self._ctx: ssl.SSLContext | None = None
        if u.scheme == "https":
            self._ctx = ssl.create_default_context(cafile=ca_file)
        self._lock = threading.Lock()
        self._blocked_until = 0.0
        self.calls = 0
        self.errors = 0
        self.last_ok: float | None = None

    # ------------------------------------------------------------------------------------------ rate limit
    def blocked_for(self) -> float:
        with self._lock:
            return max(0.0, self._blocked_until - self._clock())

    def _block(self, seconds: float) -> None:
        with self._lock:
            self._blocked_until = max(self._blocked_until, self._clock() + min(max(seconds, 1.0), RATE_LIMIT_PAUSE_MAX_S))

    # ------------------------------------------------------------------------------------------- transport
    def _once(self, method: str, target: str, body: bytes | None, extra_headers: Mapping[str, str] | None) -> tuple[int, dict[str, str], bytes]:
        headers = {"Accept": "application/json", "User-Agent": "exp-runner", **self._headers, **(extra_headers or {})}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(self._host, self._port or 443, timeout=self.timeout_s, context=self._ctx)
        else:
            conn = http.client.HTTPConnection(self._host, self._port or 80, timeout=self.timeout_s)
        try:
            conn.request(method, target, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(self.max_bytes + 1)
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hdrs, data
        finally:
            conn.close()

    def request(self, method: str, path: str, params: Mapping[str, Any] | None = None, body: Any | None = None, *,
                budget: CallBudget | None = None, deadline: float | None = None, idempotent: bool = True,
                extra_headers: Mapping[str, str] | None = None) -> Any:
        """One logical call. Returns the decoded JSON (``None`` for an empty body); raises :class:`UpstreamError`."""
        query = ""
        if params:
            query = "?" + urllib.parse.urlencode([(k, str(v)) for k, v in params.items() if v is not None])
        target = self._prefix + path + query
        raw_body = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        attempt = 0
        while True:
            wait = self.blocked_for()
            if wait > 0:
                raise UpstreamError("rate_limited", f"{self.name}: rate limited, paused for {wait:.0f}s more", 429)
            if deadline is not None and self._clock() >= deadline:
                raise UpstreamError("deadline", f"{self.name}: connector deadline reached")
            if budget is not None and not budget.take(1):
                raise UpstreamError("budget", f"{self.name}: per-test call budget exhausted")
            self.calls += 1
            try:
                status, headers, data = self._once(method, target, raw_body, extra_headers)
            except (TimeoutError, OSError, http.client.HTTPException, ssl.SSLError) as exc:
                kind = "timeout" if isinstance(exc, TimeoutError) else "transport"
                self.errors += 1
                if idempotent and attempt < self.retries:
                    self._sleep(min(self.backoff_s * (2 ** attempt), BACKOFF_MAX_S))
                    attempt += 1
                    continue
                raise UpstreamError(kind, f"{self.name}: {method} {path.split('?')[0]}: {type(exc).__name__}") from None
            if len(data) > self.max_bytes:
                self.errors += 1
                raise UpstreamError("bad_response", f"{self.name}: response too large", status)
            if status == 429:
                ra = headers.get("retry-after", "")
                self._block(float(ra) if ra.isdigit() else RATE_LIMIT_PAUSE_S)
                self.errors += 1
                raise UpstreamError("rate_limited", f"{self.name}: HTTP 429", 429)
            if status in (401, 403):
                self.errors += 1
                raise UpstreamError("auth", f"{self.name}: HTTP {status} (credential refused)", status)
            if status == 404:
                raise UpstreamError("not_found", f"{self.name}: HTTP 404 {path.split('?')[0]}", 404)
            if status >= 500 or status in (408, 425):
                self.errors += 1
                if idempotent and attempt < self.retries:
                    self._sleep(min(self.backoff_s * (2 ** attempt), BACKOFF_MAX_S))
                    attempt += 1
                    continue
                raise UpstreamError("http", f"{self.name}: HTTP {status}", status)
            if not 200 <= status < 300:
                self.errors += 1
                raise UpstreamError("http", f"{self.name}: HTTP {status}", status)
            self.last_ok = time.time()
            if not data:
                return None
            try:
                return json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self.errors += 1
                raise UpstreamError("bad_response", f"{self.name}: response is not JSON", status) from None

    def get(self, path: str, params: Mapping[str, Any] | None = None, **kw: Any) -> Any:
        return self.request("GET", path, params, **kw)


class Ttl:
    """A tiny bounded TTL cache (thread-safe)."""

    def __init__(self, ttl_s: float, clock: Callable[[], float], cap: int = 512) -> None:
        self.ttl, self.clock, self.cap = ttl_s, clock, cap
        self._d: OrderedDict[Any, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any | None:
        with self._lock:
            it = self._d.get(key)
            if it is None or self.clock() - it[0] > self.ttl:
                self._d.pop(key, None)
                return None
            return it[1]

    def put(self, key: Any, value: Any) -> None:
        with self._lock:
            self._d[key] = (self.clock(), value)
            self._d.move_to_end(key)
            while len(self._d) > self.cap:
                self._d.popitem(last=False)


# ----------------------------------------------------------------------------------------------- sanitizers
# Vendor text is hostile (SR-24): bounded, control characters removed, types coerced. Used by the evidence builders.
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def s(v: Any, n: int = 64) -> str | None:
    if v is None or isinstance(v, (bool, dict, list)):
        return None
    t = _CTRL.sub("", str(v)).strip()
    return t[:n] if t else None


def i(v: Any) -> int | None:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and math.isfinite(v):
        return int(v)
    if isinstance(v, str) and re.fullmatch(r"-?\d{1,18}", v.strip()):
        return int(v)
    return None


def f(v: Any) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)) and math.isfinite(v):
        return float(v)
    if isinstance(v, str):
        try:
            x = float(v)
        except ValueError:
            return None
        return x if math.isfinite(x) else None
    return None


def b(v: Any) -> bool | None:
    return v if isinstance(v, bool) else None


def put(d: dict[str, Any], key: str, value: Any) -> None:
    """Set ``d[key]`` unless ``value`` is None (absent optional fields stay absent)."""
    if value is not None:
        d[key] = value
