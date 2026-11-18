"""Test world: N fake collectors (TLS, pinned), credentials, a running dashboard, an HTTPS client."""
from __future__ import annotations

import base64
import dataclasses
import http.client
import json
import os
import socket
import ssl
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT / "dashboard", ROOT / "shared" / "python", ROOT / "test" / "fakes"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import fake_collector  # noqa: E402
import fakes_common as fc  # noqa: E402
from exp_common import ids, tlspin  # noqa: E402
from exp_dashboard.auth import hash_password  # noqa: E402
from exp_dashboard.config import load_settings  # noqa: E402
from exp_dashboard.server import DashboardApp  # noqa: E402

DASH_TOKEN = fc.fixture_token("expd", "dash-main")
ORIGIN_HOST = "127.0.0.1"


@pytest.fixture(scope="session")
def pw_hashes() -> dict[str, str]:
    """600k-iteration hashes are slow; make them once."""
    return {"alice": hash_password("alice-pass-1"), "vera": hash_password("vera-pass-1"),
            "bob": hash_password("bob-pass-1")}


class Resp:
    def __init__(self, status: int, headers: dict[str, str], cookies: list[str], body: bytes) -> None:
        self.status, self.headers, self.set_cookies, self.body = status, headers, cookies, body

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


class Client:
    """Minimal HTTPS client with a cookie jar for the session cookie. Never verifies certificates."""

    def __init__(self, port: int, host: str = ORIGIN_HOST) -> None:
        self.port, self.host = port, host
        self.cookie: str | None = None
        self.csrf: str | None = None
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    @property
    def origin(self) -> str:
        return f"https://{self.host}:{self.port}"

    def request(self, method: str, path: str, *, body: bytes | None = None, json_body: Any = None,
                form: dict[str, str] | None = None, headers: dict[str, str] | None = None,
                origin: str | None | bool = None, csrf: str | None | bool = None,
                cookie: bool = True) -> Resp:
        """origin/csrf: None = automatic (correct) for non-GET, False = omit, str = explicit."""
        h = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode()
            h.setdefault("Content-Type", "application/json")
        if form is not None:
            from urllib.parse import urlencode
            body = urlencode(form).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if method not in ("GET", "HEAD"):
            if origin is None:
                h.setdefault("Origin", self.origin)
            elif origin is not False:
                h["Origin"] = str(origin)
            if csrf is None:
                if self.csrf:
                    h.setdefault("X-Exp-CSRF", self.csrf)
            elif csrf is not False:
                h["X-Exp-CSRF"] = str(csrf)
        if cookie and self.cookie:
            h["Cookie"] = f"__Host-exp_session={self.cookie}"
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=15)
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            data = r.read()
            cookies = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
            resp = Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, cookies, data)
        finally:
            conn.close()
        for c in resp.set_cookies:
            name, _, rest = c.partition("=")
            if name == "__Host-exp_session":
                val = rest.split(";")[0]
                self.cookie = None if "Max-Age=0" in c else val
        return resp

    def get(self, path: str, **kw: Any) -> Resp:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> Resp:
        return self.request("POST", path, **kw)

    def login(self, username: str, password: str) -> Resp:
        r = self.post("/auth/login", json_body={"username": username, "password": password})
        if r.status == 200:
            self.csrf = r.json()["csrf"]
        return r

    def noc(self, token: str) -> Resp:
        r = self.post("/auth/noc", json_body={"token": token})
        if r.status == 200:
            self.csrf = r.json()["csrf"]
        return r

    def whoami(self) -> Resp:
        return self.get("/auth/session")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class World:
    def __init__(self, tmp: Path, pw_hashes: dict[str, str], n_collectors: int = 3,
                 tls_mode: str = "self_signed", session_hours: int = 12,
                 clock: Callable[[], float] | None = None, start: bool = True,
                 sso: bool = True) -> None:
        self.tmp = tmp
        self.offset = 0.0
        self.pw = {"alice": "alice-pass-1", "vera": "vera-pass-1", "bob": "bob-pass-1"}
        self.hashes = pw_hashes
        self.sso_secret = os.urandom(32)
        self.noc_token = ids.new_token("expn")
        self.fakes: dict[str, Any] = {}
        self.fingerprints: dict[str, str] = {}
        letters = "abc"[:n_collectors]
        for i, ch in enumerate(letters):
            cid, probe, site = f"col-{ch}", f"probe-{ch}1", f"hall-{ch}"
            sd = tmp / f"fake-{ch}"
            f = fake_collector.start(
                tls=True, state_dir=sd, fixtures=False, site=site, keepalive_s=0.3,
                ingest_tokens={probe: fc.token_hash(fc.fixture_token("expi", probe))},
                probe_sites={probe: site})
            self.fakes[cid] = f
            self.fingerprints[cid] = f.fingerprint
        self.creds = tmp / "creds"
        self.creds.mkdir()
        self.write_creds()
        self.tls_dir = tmp / "dash-tls"
        cert, key = tlspin.generate_self_signed_cert(self.tls_dir, cn="dash-main")
        self.cert, self.key = cert, key
        self.config_path = tmp / "config.json"
        self.session_hours, self.tls_mode, self.sso = session_hours, tls_mode, sso
        self.clock = clock or (lambda: time.time() + self.offset)
        self.app: DashboardApp | None = None
        self.state_dir = tmp / "state"
        self.run_dir = tmp / "run"
        self.write_config()
        if start:
            self.start()

    # -- credentials ------------------------------------------------------------------------
    def write_creds(self, users: list[str] | None = None, noc: list[dict] | None = None,
                    collector_tokens: dict[str, str] | None = None) -> None:
        users = ["alice", "vera"] if users is None else users
        roles = {"alice": "operator", "vera": "viewer", "bob": "viewer"}
        (self.creds / "local_users.json").write_text(json.dumps(
            [{"username": u, "role": roles[u], "hash": self.hashes[u]} for u in users]))
        if noc is None:
            noc = [{"id": "noc-1", "sha256": ids.token_hash(self.noc_token), "label": "wall screen",
                    "role": "viewer", "expires": "2099-01-01T00:00:00Z"}]
        (self.creds / "noc_tokens.json").write_text(json.dumps(noc))
        (self.creds / "collector_tokens.json").write_text(json.dumps(
            collector_tokens if collector_tokens is not None else {c: DASH_TOKEN for c in self.fakes}))
        (self.creds / "sso_secret").write_text(base64.b64encode(self.sso_secret).decode())
        for n in ("local_users.json", "noc_tokens.json", "collector_tokens.json", "sso_secret"):
            os.chmod(self.creds / n, 0o600)

    def write_config(self, collectors: list[dict] | None = None) -> None:
        cols = collectors if collectors is not None else [
            {"collector_id": cid, "site": f"hall-{cid[-1]}", "url": f.base_url,
             "tls_fingerprint_sha256": self.fingerprints[cid]} for cid, f in self.fakes.items()]
        doc = json.loads((ROOT / "test/fixtures/configs/dashboard.json").read_text())
        doc["collectors"] = cols
        doc["auth"]["session_hours"] = self.session_hours
        doc["tls"]["mode"] = self.tls_mode
        if not self.sso:
            doc["auth"].pop("sso", None)
        self.config_path.write_text(json.dumps(doc))

    def settings(self) -> Any:
        s = load_settings(self.config_path, state_dir=self.state_dir, creds_dir=self.creds,
                          run_dir=self.run_dir, tls_cert=self.cert, tls_key=self.key)
        return dataclasses.replace(s, https=("127.0.0.1", 0), http_redirect=("127.0.0.1", 0))

    def start(self, watch_interval: float = 0.2) -> DashboardApp:
        self.app = DashboardApp(self.settings(), clock=self.clock, watch_interval=watch_interval)
        self.app.start()
        # wait for the first federation refresh so the probe map is populated
        deadline = time.time() + 10
        while time.time() < deadline and self.app.fed.probe_map == {} and self.fakes:
            time.sleep(0.05)
        return self.app

    def restart(self) -> DashboardApp:
        assert self.app
        self.app.stop()
        return self.start()

    def stop(self) -> None:
        if self.app:
            self.app.stop()
            self.app = None
        for f in self.fakes.values():
            f.stop()

    # -- helpers ----------------------------------------------------------------------------
    @property
    def port(self) -> int:
        assert self.app
        return self.app.https_port

    def client(self) -> Client:
        return Client(self.port)

    def as_user(self, name: str) -> Client:
        c = self.client()
        r = c.login(name, self.pw[name])
        assert r.status == 200, r.body
        return c

    def sso_token(self, **over: Any) -> str:
        return make_jwt(self.sso_secret, **over)

    def wait_for(self, cond: Callable[[], bool], timeout: float = 10.0, step: float = 0.05) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(step)
        return cond()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(secret: bytes, *, alg: str = "HS256", sign_with: bytes | None = None, **claims: Any) -> str:
    import hashlib
    import hmac
    import uuid
    now = int(time.time())
    base: dict[str, Any] = {"iss": "exp-manager:default", "aud": "dash-main", "sub": "admin@example.com",
                            "name": "Ada Admin", "role": "admin", "iat": now, "exp": now + 120,
                            "jti": str(uuid.uuid4())}
    base.update(claims)
    base = {k: v for k, v in base.items() if v is not None}
    h = b64u(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = b64u(json.dumps(base).encode())
    sig = b"" if alg == "none" else hmac.new(sign_with or secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64u(sig)}"


@pytest.fixture()
def world(tmp_path: Path, pw_hashes: dict[str, str]):
    w = World(tmp_path, pw_hashes)
    yield w
    w.stop()


@pytest.fixture()
def make_world(tmp_path: Path, pw_hashes: dict[str, str]):
    made: list[World] = []

    def factory(**kw: Any) -> World:
        sub = tmp_path / f"w{len(made)}"
        sub.mkdir()
        w = World(sub, pw_hashes, **kw)
        made.append(w)
        return w

    yield factory
    for w in made:
        w.stop()
