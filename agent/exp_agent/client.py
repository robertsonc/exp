"""HTTPS client for the manager agent API (01-contracts.md section 6, agent.yaml).

Only MANAGER_URL is ever contacted: request paths are validated against /api/agent/v1/..., redirects
are never followed. TLS: system CA store, hostname verification, TLS >= 1.2, HTTPS_PROXY honoured
(CONNECT tunnel; TLS still terminates at the manager). Every call has connect + read timeouts.
The bearer secret is only ever placed in the Authorization header, never logged.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import logging
import os
import random
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

from exp_common import config as exp_config
from exp_common import ids as exp_ids
from exp_common.log import scrub

from .config import normalise_manager_url
from .errors import ClientError, ManagerUnreachable, Refused, Unauthorized

log = logging.getLogger(__name__)

API_PREFIX = "/api/agent/v1/"
_PATH_RE = re.compile(r"/api/agent/v1/[A-Za-z0-9._/-]{1,200}\Z")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_SMALL_BYTES = 1024 * 1024
BACKOFF_MIN_S = 30.0
BACKOFF_MAX_S = 300.0
UNAUTHORIZED_PAUSE_S = 300.0


class Backoff:
    """30 s doubling to 5 min while the manager is unreachable."""

    def __init__(self, lo: float = BACKOFF_MIN_S, hi: float = BACKOFF_MAX_S) -> None:
        self.lo, self.hi, self._cur = lo, hi, 0.0

    def next(self) -> float:
        self._cur = self.lo if self._cur <= 0 else min(self.hi, self._cur * 2)
        return self._cur

    def reset(self) -> None:
        self._cur = 0.0


def jittered(base: float, frac: float = 0.2, rng: random.Random | None = None) -> float:
    """`base` seconds +/- `frac` (default 20%)."""
    r = rng or random
    return base * (1.0 + r.uniform(-frac, frac))


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes = b""

    def json(self) -> Any:
        return exp_config.parse_json(self.body, "manager response")


def _proxy_from_env(host: str) -> tuple[str, int, dict[str, str]] | None:
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not proxy:
        return None
    no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    for entry in (e.strip().lstrip(".") for e in no_proxy.split(",")):
        if entry and (entry == "*" or host == entry or host.endswith("." + entry)):
            return None
    parts = urlsplit(proxy if "//" in proxy else "http://" + proxy)
    if not parts.hostname:
        return None
    headers: dict[str, str] = {}
    if parts.username:
        cred = f"{unquote(parts.username)}:{unquote(parts.password or '')}".encode()
        headers["Proxy-Authorization"] = "Basic " + base64.b64encode(cred).decode()
    return parts.hostname, parts.port or 3128, headers


class ManagerClient:
    def __init__(
        self,
        base_url: str,
        secret: str | None = None,
        *,
        ssl_context: ssl.SSLContext | None = None,
        allow_http: bool = False,
        connect_timeout: float = 10.0,
        read_timeout: float = 30.0,
        use_proxy: bool = True,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.base = normalise_manager_url(base_url, allow_http=allow_http)
        self._parts = urlsplit(self.base)
        self._secret = secret
        self._ctx = ssl_context or self._default_context()
        self.connect_timeout, self.read_timeout = connect_timeout, read_timeout
        self.use_proxy = use_proxy
        self._mono = monotonic

    @staticmethod
    def _default_context() -> ssl.SSLContext:
        ctx = ssl.create_default_context()  # system CA store, check_hostname + CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def set_secret(self, secret: str) -> None:
        self._secret = secret

    # ----- transport -----
    def _connect(self) -> http.client.HTTPConnection:
        host = self._parts.hostname or ""
        port = self._parts.port or (443 if self._parts.scheme == "https" else 80)
        if self._parts.scheme == "http":
            return http.client.HTTPConnection(host, port, timeout=self.connect_timeout)
        proxy = _proxy_from_env(host) if self.use_proxy else None
        if proxy:
            ph, pp, ph_headers = proxy
            conn = http.client.HTTPSConnection(ph, pp, timeout=self.connect_timeout, context=self._ctx)
            conn.set_tunnel(host, port, headers=ph_headers or None)
            return conn
        return http.client.HTTPSConnection(host, port, timeout=self.connect_timeout, context=self._ctx)

    def _open(
        self, method: str, path: str, body: bytes | None, headers: dict[str, str], auth: bool
    ) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
        if not _PATH_RE.match(path) or ".." in path or "//" in path:
            raise Refused("refusing to request a path outside the manager agent API")
        h = {"Accept": "application/json", "User-Agent": "exp-agent", **headers}
        if auth:
            if not self._secret:
                raise Unauthorized("no agent secret configured")
            h["Authorization"] = "Bearer " + self._secret
        conn = self._connect()
        try:
            conn.request(method, path, body=body, headers=h)
            if conn.sock is not None:
                conn.sock.settimeout(self.read_timeout)
            return conn, conn.getresponse()
        except (OSError, http.client.HTTPException) as exc:  # incl. ssl.SSLError, timeouts
            conn.close()
            raise ManagerUnreachable(
                f"manager unreachable: {type(exc).__name__}: {scrub(str(exc))[:200]}"
            ) from None

    @staticmethod
    def _retry_after(resp: http.client.HTTPResponse) -> float | None:
        v = resp.getheader("Retry-After")
        try:
            return min(3600.0, max(0.0, float(v))) if v else None
        except ValueError:
            return None

    def _raise_for(self, resp: http.client.HTTPResponse, conn: http.client.HTTPConnection) -> None:
        status = resp.status
        raw = b""
        try:
            raw = resp.read(MAX_SMALL_BYTES)
        except (OSError, http.client.HTTPException):
            pass
        retry = self._retry_after(resp)
        conn.close()
        if status == 401:
            raise Unauthorized("manager answered 401 (credentials revoked or rotated wrongly?)")
        code, msg = "error", ""
        try:
            err = json.loads(raw.decode("utf-8", "replace"))["error"]
            code, msg = str(err.get("code", "error"))[:64], str(err.get("message", ""))[:200]
        except (ValueError, KeyError, TypeError, AttributeError):
            pass
        if status == 429 or status >= 500:
            raise ManagerUnreachable(f"manager busy: HTTP {status} {code}", retry_after=retry)
        raise ClientError(status, code, scrub(msg))

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        auth: bool = True,
        max_bytes: int = MAX_JSON_BYTES,
    ) -> Response:
        data = None
        h = dict(headers or {})
        if body is not None:
            data = json.dumps(body, separators=(",", ":"), allow_nan=False).encode("utf-8")
            h["Content-Type"] = "application/json"
        conn, resp = self._open(method, path, data, h, auth)
        try:
            if resp.status in (200, 201, 204, 304):
                try:
                    payload = resp.read(max_bytes + 1) if resp.status != 304 else b""
                except (OSError, http.client.HTTPException) as exc:
                    raise ManagerUnreachable(f"manager unreachable: {type(exc).__name__}") from None
                if len(payload) > max_bytes:
                    raise Refused("manager response is too large")
                hdrs = {k.lower(): v for k, v in resp.getheaders()}
                return Response(resp.status, hdrs, payload)
            self._raise_for(resp, conn)
            raise ClientError(resp.status, "unexpected")  # 3xx and other statuses: never followed
        finally:
            conn.close()

    # ----- API calls -----
    def enrol(self, token: str, facts: dict[str, Any]) -> dict[str, Any]:
        if not exp_ids.is_token(token, "expe"):
            raise Refused("that does not look like an enrol token (expe_...)")
        resp = self.request("POST", API_PREFIX + "enrol", body={"token": token, "facts": facts}, auth=False)
        doc = resp.json()
        exp_config.validate(
            doc,
            {
                "type": "object",
                "required": ["agent_id", "agent_secret", "poll_interval_s", "release_pubkey_pem"],
                "properties": {
                    "agent_id": {"$ref": "common.schema.json#/$defs/h_id"},
                    "agent_secret": {"$ref": "common.schema.json#/$defs/expa_token"},
                    "release_pubkey_pem": {"type": "string", "maxLength": 4096},
                },
            },
        )
        return doc

    def get_desired(self, etag: str | None) -> tuple[int, dict[str, Any] | None, str | None]:
        """(200, doc, etag), (304, None, etag) or (404, None, None): nothing compiled for this host yet
        (CR-wp4-desired-404; not an outage, retry at the next normal poll)."""
        h = {"If-None-Match": etag} if etag else {}
        try:
            resp = self.request("GET", API_PREFIX + "desired", headers=h)
        except ClientError as exc:
            if exc.status == 404 and exc.code == "not_found":
                return 404, None, None
            raise
        if resp.status == 304:
            return 304, None, resp.headers.get("etag", etag)
        doc = resp.json()
        if not isinstance(doc, dict):
            raise Refused("desired state is not a JSON object")
        return 200, doc, resp.headers.get("etag")

    def get_manifest(self, version: str) -> tuple[bytes, bytes]:
        """(manifest bytes exactly as signed, base64 signature bytes)."""
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?", version):
            raise Refused("invalid release version")
        m = self.request("GET", f"{API_PREFIX}releases/{version}/manifest", max_bytes=MAX_SMALL_BYTES)
        s = self.request("GET", f"{API_PREFIX}releases/{version}/manifest.sig", max_bytes=4096)
        return m.body, s.body

    def download_artifact(
        self, url_path: str, dest_fd: int, expected_size: int, deadline_s: float = 1800.0
    ) -> str:
        """Stream an artifact (only a /api/agent/v1/artifacts/art_... path on the manager) to `dest_fd`;
        returns its sha256 hex. Refuses more bytes than `expected_size`."""
        if not re.fullmatch(r"/api/agent/v1/artifacts/art_[0-9A-HJKMNP-TV-Z]{26}", url_path):
            raise Refused("artifact url is not an artifact path on the manager")
        conn, resp = self._open("GET", url_path, None, {"Accept": "application/gzip"}, True)
        try:
            if resp.status != 200:
                self._raise_for(resp, conn)
                raise ClientError(resp.status, "unexpected")
            total, h = 0, hashlib.sha256()
            t_end = self._mono() + deadline_s
            while True:
                try:
                    chunk = resp.read(65536)
                except (OSError, http.client.HTTPException) as exc:
                    raise ManagerUnreachable(f"artifact download failed: {type(exc).__name__}") from None
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_size:
                    raise Refused("artifact is larger than the size in the manifest")
                h.update(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(dest_fd, view) :]
                if self._mono() > t_end:
                    raise ManagerUnreachable("artifact download exceeded its deadline")
            if total != expected_size:
                raise ManagerUnreachable("artifact download was truncated")
            return h.hexdigest()
        finally:
            conn.close()

    def post_status(self, doc: dict[str, Any]) -> None:
        self.request("POST", API_PREFIX + "status", body=doc)

    def rotate(self) -> tuple[str, int]:
        """(new secret, grace_s): the OLD secret stays valid for grace_s seconds after this call."""
        doc = self.request("POST", API_PREFIX + "rotate", body={}).json()
        secret = doc.get("agent_secret") if isinstance(doc, dict) else None
        if not exp_ids.is_token(secret, "expa"):
            raise Refused("manager returned a malformed rotated secret")
        grace = doc.get("grace_s")
        if not isinstance(grace, int) or isinstance(grace, bool) or not 0 <= grace <= 86400:
            raise Refused("manager returned a malformed rotation grace period")
        return secret, grace

    def check_auth(self) -> bool:
        """True when the current secret is accepted (a cheap authenticated call); False on 401."""
        try:
            self.request("GET", API_PREFIX + "desired", headers={"If-None-Match": '"exp-auth-probe"'})
        except Unauthorized:
            return False
        except ClientError:
            return True  # authenticated, the answer was something else (e.g. 404 nothing compiled)
        return True

    def decommissioned(self) -> None:
        self.request("POST", API_PREFIX + "decommissioned", body={})
