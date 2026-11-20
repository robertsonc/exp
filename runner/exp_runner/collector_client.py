"""The runner's client of the collector's ``speedtests`` API (``expr_`` token, 01 section 14.5).

TLS with the collector's pinned fingerprint (``exp_common.tlspin``); plain ``http://`` is accepted for loopback hosts only
(dev and tests, never from a config document). Every call has timeouts; every call here is idempotent (the feed is a read,
evidence replaces per kind until final, ``complete`` treats 409 as done), so transport errors, 429 and 5xx retry with
bounded backoff and ``Retry-After``.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import time
import urllib.parse
from collections.abc import Callable
from typing import Any

from exp_common import tlspin

log = logging.getLogger(__name__)

API = "/api/v1"
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
TOTAL_TIMEOUT = 30.0
MAX_RESPONSE = 4 * 1024 * 1024
MAX_RETRY_AFTER = 10.0


class CollectorError(Exception):
    def __init__(self, message: str, status: int = 0, code: str = "", retryable: bool = False) -> None:
        super().__init__(message)
        self.status, self.code, self.retryable = status, code, retryable


class AuthError(CollectorError):
    """401/403: the token is wrong or not identity-bound to this runner/site. Never retried."""


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


class CollectorClient:
    def __init__(self, url: str, pin: str | None, token: str, *, retries: int = 3, backoff_s: float = 0.5,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        u = urllib.parse.urlsplit(url)
        if u.scheme == "http":
            if not u.hostname or not _is_loopback(u.hostname):
                raise ValueError("plain http is only accepted for loopback collectors")
        elif u.scheme != "https" or not u.hostname:
            raise ValueError("collector url must be https://host[:port]")
        elif not pin:
            raise ValueError("an https collector needs a tls fingerprint pin")
        self.url = url.rstrip("/")
        self._u = u
        self.pin = pin
        self._token = token
        self.retries = max(0, int(retries))
        self.backoff_s = backoff_s
        self._sleep = sleep
        self.last_ok: float | None = None

    # ---------------------------------------------------------------------------------- transport
    def _once(self, method: str, path: str, body: bytes | None) -> tuple[int, dict[str, str], bytes]:
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json", "User-Agent": "exp-runner"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._u.scheme == "https":
            r = tlspin.request(method, self.url + path, self.pin or "", body=body, headers=headers,
                               connect_timeout=CONNECT_TIMEOUT, read_timeout=READ_TIMEOUT, total_timeout=TOTAL_TIMEOUT,
                               max_response_bytes=MAX_RESPONSE)
            return r.status, r.headers, r.body
        conn = http.client.HTTPConnection(self._u.hostname or "", self._u.port or 80, timeout=READ_TIMEOUT)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise CollectorError("response too large")
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        finally:
            conn.close()

    def _request(self, method: str, path: str, payload: Any | None = None, ok_extra: tuple[int, ...] = ()) -> tuple[int, Any]:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        attempt = 0
        while True:
            try:
                status, headers, raw = self._once(method, API + path, body)
            except (OSError, http.client.HTTPException, tlspin.TlsPinError, ValueError) as exc:
                if attempt >= self.retries:
                    raise CollectorError(f"{method} {path.split('?')[0]}: {type(exc).__name__}", retryable=True) from None
                self._sleep(min(self.backoff_s * (2 ** attempt), 8.0))
                attempt += 1
                continue
            doc: Any = None
            if raw:
                try:
                    doc = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    doc = None
            if 200 <= status < 300 or status in ok_extra:
                self.last_ok = time.time()
                return status, doc
            err = (doc or {}).get("error") if isinstance(doc, dict) else None
            code = str(err.get("code", "")) if isinstance(err, dict) else ""
            msg = f"{method} {path.split('?')[0]}: HTTP {status} {code}".strip()
            if status in (401, 403):
                raise AuthError(msg, status, code)
            if status == 429 or status >= 500:
                if attempt >= self.retries:
                    raise CollectorError(msg, status, code, retryable=True)
                delay = self.backoff_s * (2 ** attempt)
                ra = headers.get("retry-after")
                if ra and ra.isdigit():
                    delay = max(delay, min(float(ra), MAX_RETRY_AFTER))
                self._sleep(min(delay, MAX_RETRY_AFTER))
                attempt += 1
                continue
            raise CollectorError(msg, status, code)

    # --------------------------------------------------------------------------------------- API
    def feed(self, after: str | None = None, limit: int = 50, wait_s: int = 0) -> tuple[list[dict[str, Any]], str | None]:
        q = {"limit": str(int(limit)), "wait_s": str(int(wait_s))}
        if after:
            q["after"] = after
        _s, doc = self._request("GET", "/speedtests/feed?" + urllib.parse.urlencode(q))
        if not isinstance(doc, dict) or not isinstance(doc.get("items"), list):
            raise CollectorError("feed: unexpected response")
        items = [i for i in doc["items"] if isinstance(i, dict) and isinstance(i.get("id"), str)]
        nc = doc.get("next_cursor")
        return items, nc if isinstance(nc, str) else None

    def post_evidence(self, test_id: str, doc: dict[str, Any]) -> dict[str, Any]:
        """409 (evidence already final) is returned as ``{"final": True}`` - the work is done."""
        status, out = self._request("POST", f"/speedtests/{test_id}/evidence", doc, ok_extra=(409,))
        if status == 409:
            return {"final": True}
        return out if isinstance(out, dict) else {}

    def complete(self, test_id: str, kinds: list[str], status: str) -> dict[str, Any]:
        st, out = self._request("POST", f"/speedtests/{test_id}/evidence/complete", {"kinds": kinds, "status": status},
                                ok_extra=(409,))
        if st == 409:
            return {"final": True}
        return out if isinstance(out, dict) else {}

    def baseline(self, site: str, zone: str | None, ap: str | None, at: str) -> dict[str, Any] | None:
        q = {"site": site, "at": at}
        if zone and zone != "unresolved":
            q["zone"] = zone
        if ap:
            q["ap"] = ap
        status, doc = self._request("GET", "/speedtests/baseline?" + urllib.parse.urlencode(q), ok_extra=(404,))
        return doc if status == 200 and isinstance(doc, dict) else None
