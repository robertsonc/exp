"""Test plumbing: a real exp-speedtest daemon in-process against the fake collector, plus small HTTP/DNS helpers.

Fake tokens and keys are built at runtime (gitleaks stays quiet); nothing here touches the public internet.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import fake_st_collector as fstc  # noqa: E402
import fakes_common as fc  # noqa: E402
from exp_common import ids
from exp_common import speedtest as st

from exp_speedtest.config import Paths, SpeedtestConfig
from exp_speedtest.daemon import Daemon

SENTINEL_ID = "st_" + "0" * 26     # CR-m6-speedtest-view-proof: the proof is derived with this fixed id


class FakePinger:
    backend = "fake"

    def __init__(self) -> None:
        self.pinged: list[str] = []
        self.rtt: float | None = 0.5

    def ping(self, addr: str, timeout: float = 1.0) -> float | None:
        self.pinged.append(addr)
        return self.rtt

    def trace_hop(self, target: str, ttl: int, timeout: float = 1.5) -> tuple[str | None, bool]:
        return None, False


class FakeClock:
    def __init__(self) -> None:
        self.offset = 0.0

    def __call__(self) -> float:
        return time.time() + self.offset

    def advance(self, s: float) -> None:
        self.offset += s


_TLS: tuple[Path, Path, str] | None = None
_PAYLOAD: Path | None = None


def shared_tls() -> tuple[Path, Path, str]:
    """One throwaway certificate per test process (openssl is the slow part of a fixture)."""
    global _TLS
    if _TLS is None:
        import tempfile
        _TLS = fc.prepare_tls(Path(tempfile.mkdtemp(prefix="st-tls-")))
    return _TLS


_PORTS: set[int] = set()


def free_port(udp_too: bool = False) -> int:
    """A currently free loopback port, never handed out twice in this process (the kernel likes to reuse them)."""
    for _ in range(200):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        if port in _PORTS:
            continue
        _PORTS.add(port)
        if udp_too:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                u.bind(("127.0.0.1", port))
            except OSError:
                continue
            finally:
                u.close()
        return port
    raise RuntimeError("no free port")


def base_config(collector_url: str, fingerprint: str, http_port: int, dns_port: int, chan_port: int, **over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema": "exp.speedtest.config/1", "speedtest_id": "spd-core", "site": "hall-b",
        "zones": [{"id": "hall-a", "name": "Hall A"}, {"id": "hall-b", "name": "Hall B"}, {"id": "hallb-row12", "name": "Hall B, row 12"}],
        "zone_labels": {"subnets": [{"cidr": "127.0.0.0/24", "zone": "hall-a"}, {"cidr": "127.0.1.0/24", "zone": "hall-b"}]},
        "branding": {"title": "Test speed check", "colors": {"primary": "#01a982"}, "languages": ["en"], "copy": {"start_button": "Start"}},
        "consent": {"text": "We measure your connection. No name or email is collected.", "version": 3},
        "display": {"show_network_details": False},
        "targets": {"down_mbps": 25, "up_mbps": 10},
        "limits": {"tests_per_10min_per_ip": 6, "max_concurrent_per_ip": 1, "max_concurrent_tests": 20,
                   "max_concurrent_internet": 2, "bytes_local": 50_000_000, "bytes_internet": 200_000_000,
                   "leg_token_ttl_s": 60, "result_deadline_s": 180},
        "internet_leg": {"enabled": True, "provider": "cloudflare", "paused": False, "auto_pause_wan_util_pct": 80},
        "serve": {"placement": "core", "hostname": "127.0.0.1", "listen_ip": "127.0.0.1", "require_real_client_ip": True,
                  "client_subnets": ["127.0.0.0/8"], "translated_addresses": ["127.0.9.9"], "port": http_port},
        "tls": {"mode": "none"},
        "dns_leg": {"enabled": True, "zone": "t.speed.test.example", "port": dns_port},
        "path": {"gateway": "127.0.0.1", "edge": "127.0.0.2", "edge1": "127.0.0.3"},
        "privacy": {"retention_days": 30, "scrub_after_diagnosis": False},
        "collector": {"url": collector_url, "tls_fingerprint_sha256": fingerprint},
        "local_channel": {"listen": f"127.0.0.1:{chan_port}"},
    }
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(doc.get(k), dict):
            doc[k] = {**doc[k], **v}
        elif v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


@dataclass
class Sess:
    box: Box
    sid: str
    leg_token: str
    key: str
    proof: str
    doc: dict[str, Any]
    src: str

    @property
    def leg(self) -> dict[str, str]:
        return {"X-Exp-Leg-Token": self.leg_token}

    @property
    def view(self) -> dict[str, str]:
        return {"X-Exp-View-Proof": self.proof}


@dataclass
class Resp:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    def h(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class Box:
    """daemon + fake collector + creds + clients."""

    def __init__(self, tmp: Path, *, cfg_over: dict[str, Any] | None = None, clock: FakeClock | None = None,
                 collector: bool = True, pinger: Any = None, fake_kwargs: dict[str, Any] | None = None) -> None:
        self.tmp = tmp
        self.clock = clock or FakeClock()
        self.pinger = pinger or FakePinger()
        self.fake: Any = None
        cert, key, fp = shared_tls()
        self.fake_args = fake_kwargs or {}
        self.collector_enabled = collector
        self.fp = fp
        self.http_port, self.dns_port, self.chan_port = free_port(), free_port(udp_too=True), free_port()
        self.cert_key = (cert, key)
        self.collector_port = 0
        self.cfg_over = cfg_over or {}
        self.channel_token = ids.new_token("expl")
        self.daemon: Daemon | None = None
        self.paths = Paths(tmp / "state", tmp / "run", tmp / "assets", tmp / "creds")

    # ---------------------------------------------------------------------------------------------- lifecycle
    def start_fake(self) -> None:
        self.fake = fstc.start(tls=self.cert_key, **self.fake_args)
        self.collector_port = self.fake.port

    def collector_url(self) -> str:
        return f"https://127.0.0.1:{self.collector_port or 9}"

    def write_creds(self, collector_token: str | None = None) -> None:
        d = self.paths.creds_dir
        assert d is not None
        d.mkdir(parents=True, exist_ok=True)
        tok = collector_token or (self.fake.app.tokens["speedtest"]["spd-core"]["token"] if self.fake else fc.fixture_token("exps", "x"))
        (d / "collector_token").write_text(tok)
        (d / "runner_channel_token_sha256").write_text(hashlib.sha256(self.channel_token.encode()).hexdigest())

    def config(self) -> SpeedtestConfig:
        fp = ":".join(self.fp[i:i + 2] for i in range(0, len(self.fp), 2)).upper() if ":" not in self.fp else self.fp
        doc = base_config(self.collector_url(), fp, self.http_port, self.dns_port, self.chan_port, **self.cfg_over)
        return SpeedtestConfig(doc)

    def start(self) -> None:
        self._seed_payload()
        if self.collector_enabled and self.fake is None:
            self.start_fake()
        self.write_creds()
        self.paths.assets_dir.mkdir(parents=True, exist_ok=True)
        self.daemon = Daemon(self.config(), self.paths, pinger=self.pinger, clock=self.clock)
        self.daemon.start()

    def _seed_payload(self) -> None:
        """Reuse one 32 MiB payload file across tests (generating random bytes is the slow part of a fixture). The seed is
        removed when the test process exits, and each box HARD-LINKS it (a copy only across filesystems): the daemon only
        reads a full-size payload and replaces, never rewrites, a wrong one (static.Payload._ensure), so the link is safe.
        Copying it into every test's tmp_path kept ~7.5 GB per full speedtest run in pytest's retained tmp dirs."""
        import atexit
        import os
        import shutil
        import tempfile

        from exp_speedtest.static import PAYLOAD_SIZE
        global _PAYLOAD
        if _PAYLOAD is None or not _PAYLOAD.is_file():
            seed_dir = Path(tempfile.mkdtemp(prefix="st-payload-"))
            atexit.register(shutil.rmtree, seed_dir, ignore_errors=True)
            _PAYLOAD = seed_dir / "payload.bin"
            _PAYLOAD.write_bytes(os.urandom(PAYLOAD_SIZE))
        self.paths.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.link(_PAYLOAD, self.paths.payload)
        except OSError:                       # another filesystem (or the link exists): fall back to a copy
            shutil.copyfile(_PAYLOAD, self.paths.payload)

    def stop(self) -> None:
        if self.daemon:
            self.daemon.stop()
            self.daemon = None
        if self.fake:
            self.fake.stop()
            self.fake = None

    @property
    def core(self) -> Any:
        assert self.daemon is not None
        return self.daemon.core

    # ------------------------------------------------------------------------------------------------- http
    def request(self, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None, src: str = "127.0.0.1",
                port: int | None = None, raw_body: bytes | None = None, timeout: float = 15.0) -> Resp:
        conn = http.client.HTTPConnection("127.0.0.1", port or self.http_port, source_address=(src, 0), timeout=timeout)
        try:
            hdrs = dict(headers or {})
            data = raw_body
            if body is not None:
                data = json.dumps(body).encode()
                hdrs.setdefault("Content-Type", "application/json")
            conn.request(method, path, body=data, headers=hdrs)
            r = conn.getresponse()
            out = r.read()
            return Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, out)
        finally:
            conn.close()

    def get(self, path: str, **kw: Any) -> Resp:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: Any = None, **kw: Any) -> Resp:
        return self.request("POST", path, body, **kw)

    def channel(self, method: str, path: str, body: Any = None, token: str | None = None, src: str = "127.0.0.1") -> Resp:
        h = {"Authorization": f"Bearer {token or self.channel_token}"}
        return self.request(method, path, body, headers=h, src=src, port=self.chan_port)

    def new_session(self, src: str = "127.0.0.1", zone_hint: str | None = None, ua: str | None = None, check: bool = True) -> Sess:
        key = st.new_view_key()
        proof = st.view_proof(key, SENTINEL_ID)
        body: dict[str, Any] = {"consent": {"text_version": 3}, "view_verifier": st.view_verifier(proof)}
        if zone_hint:
            body["zone_hint"] = zone_hint
        r = self.post("/st/api/v1/sessions", body, src=src, headers={"User-Agent": ua} if ua else None)
        if check:
            assert r.status == 201, r.body
        doc = r.json()
        return Sess(self, doc.get("session_id", ""), doc.get("leg_token", ""), key, proof, doc, src)

    def raw(self, data: bytes, port: int | None = None, read: bool = True, timeout: float = 5.0) -> bytes:
        s = socket.create_connection(("127.0.0.1", port or self.http_port), timeout=timeout)
        try:
            s.sendall(data)
            if not read:
                return b""
            out = b""
            try:
                while True:
                    c = s.recv(65536)
                    if not c:
                        break
                    out += c
            except (TimeoutError, ConnectionResetError):
                pass
            return out
        finally:
            s.close()


def submission(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema": "exp.speedtest.submission/1",
        "legs": {"local": {"down_mbps": 200.0, "up_mbps": 80.0, "idle_ms": 6.0, "jitter_ms": 1.0, "loaded_down_ms": 40.0,
                           "loaded_up_ms": 52.0, "rpm": 1150, "cv": 0.1, "failures": 0},
                 "internet": {"down_mbps": 180.0, "up_mbps": 60.0, "idle_ms": 19.0, "jitter_ms": 2.4, "loaded_down_ms": 95.0,
                              "loaded_up_ms": 118.0, "rpm": 520, "cv": 0.2, "failures": 0, "bytes": 150_000_000, "colo": "FRA"},
                 "dns": {"cold_ms": 38.0, "warm_ms": 2.1, "resolver_ip": "10.0.0.53", "source": "browser"}},
        "client": {"connection_hint": "wifi"}, "started_offset_ms": 4100, "duration_ms": 16400}
    for k, v in over.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


def wait_for(cond: Any, timeout: float = 5.0, step: float = 0.02) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(step)
    return False


def tls_ctx() -> ssl.SSLContext:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


__all__ = ["Box", "FakeClock", "FakePinger", "Sess", "free_port", "submission", "wait_for", "SENTINEL_ID", "threading"]
