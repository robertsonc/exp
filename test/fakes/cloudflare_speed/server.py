"""Fake of Cloudflare's public speed-test endpoints, generated from the M6 live recording.

Source of truth: ``test/fixtures/cloudflare/recording-*.json`` (the newest by file name; see that directory's
README). Endpoints served (what ``@cloudflare/speedtest`` 1.16.0 and the exp page use):

* ``GET  /__down?bytes=N[&during=idle|downloadload|uploadload]``  ``N`` bytes of ``0`` (0x30).
* ``POST /__up?bytes=N``                                           empty 200, ``cf-meta-upload-bytes`` = bytes read.
* ``GET  /cdn-cgi/trace``                                          ``key=value`` lines incl. ``colo=`` and ``loc=``.
* ``OPTIONS`` on any of them                                       204 preflight.

Response headers replay the recording: same names, same order, same case (including the two ``Server-Timing``
lines and the lowercase ``access-control-expose-headers``). Static values (CORS, Timing-Allow-Origin, Cache-Control,
Vary, Content-Type, Connection ...) are copied verbatim; values that are per-request in reality (Date, Content-Length,
CF-RAY, cf-meta-request-time, cf-meta-upload-bytes, Server-Timing figures, the colo / geo headers) are generated.
The recording holds the recording sandbox's egress IP, city and coordinates: the fake never replays those, it emits
documentation values (203.0.113.0/24, "Testville") under the same header names. The NEL ``Report-To`` / ``Nel`` headers
are replayed with their reporting URL's per-request token replaced by a constant.

Knobs for harness tests (all changeable while running, ``fake.app.set(...)`` or ``POST /_fake/set``):

* ``latency_ms``        added before every response (idle latency); ``loaded_latency_ms`` is added instead when the request
                        carries ``during=`` (latency under load, i.e. bufferbloat).
* ``down_bps`` / ``up_bps``  rate limit in bits per second for ``__down`` bodies / ``__up`` bodies (0 = unlimited).
* ``fail``              ``none`` | ``reset`` (close the connection without answering) | ``http500`` | ``stall`` (accept, never answer)
                        | ``slow_headers`` (answer after ``fail_delay_s``).
* ``fail_after_bytes``  cut a ``__down`` body with a connection reset after this many bytes (0 = off).
* ``colo`` / ``loc``    the serving location in ``/cdn-cgi/trace`` and the ``colo`` / ``cf-meta-colo`` headers.
* ``server_edge_ms`` / ``server_worker_ms``   the ``cfSpeedEdge`` / ``cfSpeedWorker`` durations in ``Server-Timing``.

HTTP by default; ``start(tls=(cert_chain, key))`` serves HTTPS (use ``fake_ca`` for a runtime throwaway CA). ``/_fake/``
(loopback only): ``GET stats``, ``POST set``, ``POST kill`` (= ``fail=reset`` for good), ``POST heal``.
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import re
import sys
import threading
import time
from email.utils import formatdate
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import fakes_common as fc  # noqa: E402

log = logging.getLogger("exp.fakes.cloudflare_speed")

RECORDING_DIR = fc.FIXTURES_DIR / "cloudflare"
MAX_BYTES = 256 * 1024 * 1024      # 400 above this (the real limit is not documented in the recording)
MAX_UP_BODY = 256 * 1024 * 1024
CHUNK = 16 * 1024
FAIL_MODES = ("none", "reset", "http500", "stall", "slow_headers")
_REPORT_TOKEN = re.compile(r"(\?s=)[^\"]+")
GEO = {   # documentation values under the recorded header names (never the recording sandbox's real egress)
    "asn": "64496", "city": "Testville", "country": "ZZ", "latitude": "0.00000", "longitude": "0.00000",
    "postalCode": "00000", "timezone": "UTC",
}


def newest_recording() -> Path:
    files = sorted(RECORDING_DIR.glob("recording-*.json"))
    if not files:
        raise FileNotFoundError(f"no recording under {RECORDING_DIR}")
    return files[-1]


def load_recording(path: Path | None = None) -> dict[str, Any]:
    with open(path or newest_recording(), encoding="utf-8") as fh:
        return json.load(fh)


def _exchange(rec: dict[str, Any], method: str, url_part: str, label_part: str = "") -> dict[str, Any]:
    for ex in rec["exchanges"]:
        req = ex["request"]
        if req["method"] == method and url_part in req["url"] and label_part in ex["label"]:
            return ex
    raise LookupError(f"recording has no {method} {url_part} ({label_part})")


class Templates:
    """Header templates (ordered ``[name, value]`` lists) cut out of the recording."""

    def __init__(self, rec: dict[str, Any]) -> None:
        self.recording = rec
        self.down = _exchange(rec, "GET", "__down?bytes=0", "latency probe (idle)")["response"]["headers"]
        self.up = _exchange(rec, "POST", "__up")["response"]["headers"]
        self.trace = _exchange(rec, "GET", "cdn-cgi/trace")["response"]["headers"]
        self.preflight = _exchange(rec, "OPTIONS", "__up", "no custom headers")["response"]["headers"]
        self.trace_head_hex = _exchange(rec, "GET", "cdn-cgi/trace")["response"]["body"]["head_hex"]
        self.trace_length = _exchange(rec, "GET", "cdn-cgi/trace")["response"]["body"]["length"]


class SpeedApp:
    """Behaviour knobs + counters; the handler asks it how to answer."""

    def __init__(self, templates: Templates, *, colo: str = "FRA", loc: str = "DE", seed: int = 1,
                 now_fn: Any = time.time) -> None:
        self.t = templates
        self.now = now_fn
        self.rng = random.Random(seed)  # noqa: S311 - fake header noise, not security
        self.lock = threading.Lock()
        self.cfg: dict[str, Any] = {
            "latency_ms": 0.0, "loaded_latency_ms": 0.0, "down_bps": 0, "up_bps": 0, "fail": "none",
            "fail_delay_s": 1.0, "fail_after_bytes": 0, "colo": colo, "loc": loc, "server_edge_ms": 4,
            "server_worker_ms": 5,
        }
        self.stats: dict[str, Any] = {"requests": 0, "down": 0, "up": 0, "trace": 0, "preflight": 0,
                                      "bytes_down": 0, "bytes_up": 0, "failed": 0, "by_path": {}}

    def set(self, **kw: Any) -> None:
        for k, v in kw.items():
            if k not in self.cfg:
                raise KeyError(f"unknown knob {k!r}")
            if k == "fail" and v not in FAIL_MODES:
                raise ValueError(f"fail must be one of {FAIL_MODES}")
            if k in ("colo", "loc"):
                if not isinstance(v, str) or not re.fullmatch(r"[A-Z]{2,3}", v):
                    raise ValueError(f"{k} must be 2-3 upper-case letters")
            elif k == "fail":
                pass
            else:
                v = float(v) if isinstance(self.cfg[k], float) else int(v)
                if v < 0:
                    raise ValueError(f"{k} must be >= 0")
            with self.lock:
                self.cfg[k] = v

    def kill(self) -> None:
        self.set(fail="reset")

    def heal(self) -> None:
        self.set(fail="none", fail_after_bytes=0)

    def get(self, k: str) -> Any:
        with self.lock:
            return self.cfg[k]

    def count(self, kind: str, path: str) -> None:
        with self.lock:
            self.stats["requests"] += 1
            self.stats[kind] += 1
            self.stats["by_path"][path] = self.stats["by_path"].get(path, 0) + 1

    def add_bytes(self, key: str, n: int) -> None:
        with self.lock:
            self.stats[key] += n

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {"cfg": dict(self.cfg), "stats": json.loads(json.dumps(self.stats))}

    # ---- header synthesis --------------------------------------------------------------------------------
    def _cfl4(self) -> str:
        rtt = int((self.get("latency_ms") + 10) * 1000)
        return (f'cfL4;desc="?proto=TCP&rtt={rtt}&min_rtt={rtt}&rtt_var={rtt // 4}&sent=5&recv=7&lost=0&retrans=0'
                f'&sent_bytes=3931&recv_bytes=1800&delivery_rate=390000&cwnd=53&unsent_bytes=0&cid=0000000000000000&ts=40&x=0"')

    def headers(self, template: list[list[str]], *, content_length: int | None, upload_bytes: int = 0) -> list[tuple[str, str]]:
        """The recorded header list, in order, with the per-request values regenerated."""
        out: list[tuple[str, str]] = []
        colo = self.get("colo")
        ts_lines = [f"cfSpeedEdge;dur={self.get('server_edge_ms')}, cfSpeedWorker;dur={self.get('server_worker_ms')}", self._cfl4()]
        ts_idx = 0
        for name, value in template:
            low = name.lower()
            if low == "date":
                value = formatdate(self.now(), usegmt=True)
            elif low == "content-length":
                value = str(content_length if content_length is not None else 0)
            elif low == "cf-meta-ip":
                value = f"203.0.113.{self.rng.randint(1, 254)}"
            elif low == "cf-meta-request-time":
                value = str(int(self.now() * 1000))
            elif low == "cf-meta-upload-bytes":
                value = str(upload_bytes)
            elif low in ("colo", "cf-meta-colo"):
                value = colo
            elif name in GEO:
                value = GEO[name]
            elif low == "cf-ray":
                value = f"{self.rng.getrandbits(64):016x}-{colo}"
            elif low == "server-timing":
                value = ts_lines[min(ts_idx, 1)]
                ts_idx += 1
            elif low == "report-to":
                value = _REPORT_TOKEN.sub(r"\1FAKEFAKEFAKE", value)
            out.append((name, value))
        return out

    def trace_body(self) -> bytes:
        ip = f"203.0.113.{self.rng.randint(1, 254)}"
        lines = [
            "fl=000f000", "h=speed.cloudflare.com", f"ip={ip}", f"ts={self.now():.3f}", "visit_scheme=https",
            "uag=exp-fake", f"colo={self.get('colo')}", "sliver=none", "http=http/1.1", f"loc={self.get('loc')}",
            "tls=TLSv1.3", "sni=plaintext", "warp=off", "gateway=off", "rbi=off", "kex=X25519",
        ]
        return ("\n".join(lines) + "\n").encode()


class Handler(fc.BaseHandler):
    """Raw-header handler: ``send_response_only`` so ``Server``/``Date`` come from the recording template."""

    def dispatch(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        app: SpeedApp = self.app
        if path.startswith("/_fake/"):
            return self._control(method, path)
        kind = {"/__down": "down", "/__up": "up", "/cdn-cgi/trace": "trace"}.get(path)
        if kind is None:
            self.send_err(404, "not_found", "no such endpoint")
            return
        if method == "OPTIONS":
            app.count("preflight", path)
            self._respond(app.headers(app.t.preflight, content_length=None), 204, b"", include_length=False)
            return
        app.count(kind, path)
        if self._maybe_fail(app):
            return
        delay = app.get("loaded_latency_ms") if "during" in query else app.get("latency_ms")
        if delay and self._sleep(delay / 1000.0):
            return
        if kind == "trace":
            if method not in ("GET", "HEAD"):
                self.send_err(405, "method_not_allowed", "GET only")
                return
            body = app.trace_body()
            self._respond(app.headers(app.t.trace, content_length=len(body)), 200, body)
        elif kind == "down":
            self._down(method, query)
        else:
            self._up(method, query)

    # ---- helpers ---------------------------------------------------------------------------------------------
    def _sleep(self, seconds: float) -> bool:
        """Sleep (abortable by stop). True when the server is stopping."""
        return self.fake.stopping.wait(seconds)

    def _maybe_fail(self, app: SpeedApp) -> bool:
        mode = app.get("fail")
        if mode == "none":
            return False
        with app.lock:
            app.stats["failed"] += 1
        if mode == "reset":
            self.close_connection = True
            self._body_consumed = True
            try:
                self.connection.shutdown(2)
            except OSError:
                pass
            return True
        if mode == "http500":
            self.send_response_only(500)
            self.send_header("Content-Length", "0")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            return True
        if mode == "stall":
            self.close_connection = True
            self._body_consumed = True
            self.fake.stopping.wait(60)
            return True
        if mode == "slow_headers":
            return self._sleep(app.get("fail_delay_s"))
        return False

    def _respond(self, headers: list[tuple[str, str]], status: int, body: bytes, include_length: bool = True) -> None:
        self.send_response_only(status)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    @staticmethod
    def _bytes_param(query: dict[str, list[str]]) -> int | None:
        raw = (query.get("bytes") or ["0"])[0]
        if not re.fullmatch(r"[0-9]{1,12}", raw):
            return None
        n = int(raw)
        return n if n <= MAX_BYTES else None

    def _down(self, method: str, query: dict[str, list[str]]) -> None:
        app: SpeedApp = self.app
        n = self._bytes_param(query)
        if n is None:
            self.send_err(400, "bad_bytes", "bytes must be an integer <= 268435456")
            return
        self.send_response_only(200)
        for k, v in app.headers(app.t.down, content_length=n):
            self.send_header(k, v)
        self.end_headers()
        if method == "HEAD":
            return
        rate = app.get("down_bps")
        cut = app.get("fail_after_bytes")
        sent = 0
        start = time.monotonic()
        chunk = b"0" * CHUNK
        while sent < n:
            part = min(CHUNK, n - sent)
            if cut and sent + part > cut:
                part = max(0, cut - sent)
            if part:
                self.wfile.write(chunk[:part])
                sent += part
                app.add_bytes("bytes_down", part)
            if cut and sent >= cut:
                self.close_connection = True
                try:
                    self.connection.shutdown(2)
                except OSError:
                    pass
                return
            if rate:
                due = start + (sent * 8) / rate
                wait = due - time.monotonic()
                if wait > 0 and self.fake.stopping.wait(wait):
                    return
            elif self.fake.stopping.is_set():
                return

    def _up(self, method: str, query: dict[str, list[str]]) -> None:
        app: SpeedApp = self.app
        if method != "POST":
            self.send_err(405, "method_not_allowed", "POST only")
            return
        length = self.content_length()
        if length is None or length < 0 or length > MAX_UP_BODY:
            self.send_err(411 if length is None else 413, "bad_length", "Content-Length required and bounded")
            return
        rate = app.get("up_bps")
        got = 0
        start = time.monotonic()
        while got < length:
            chunk = self.rfile.read(min(CHUNK, length - got))
            if not chunk:
                break
            got += len(chunk)
            if rate:
                wait = start + (got * 8) / rate - time.monotonic()
                if wait > 0 and self.fake.stopping.wait(wait):
                    return
        self._body_consumed = True
        app.add_bytes("bytes_up", got)
        self._respond(app.headers(app.t.up, content_length=0, upload_bytes=got), 200, b"")

    def _control(self, method: str, path: str) -> None:
        if not self.client_is_loopback():
            self.send_err(403, "forbidden", "loopback only")
            return
        app: SpeedApp = self.app
        sub = path[len("/_fake/"):]
        if method == "GET" and sub == "stats":
            self.send_json(200, app.snapshot())
        elif method == "POST" and sub in ("set", "kill", "heal"):
            if sub == "kill":
                app.kill()
            elif sub == "heal":
                app.heal()
            else:
                doc, ok = self.read_json(4096)
                if not ok:
                    return
                try:
                    app.set(**doc)
                except (KeyError, TypeError, ValueError) as exc:
                    self.send_err(400, "invalid_request", str(exc)[:200])
                    return
            self.send_json(200, app.snapshot())
        else:
            self.send_err(404, "not_found", "no such control")


class FakeSpeed(fc.FakeServer):
    pass


def start(*, host: str = "127.0.0.1", port: int = 0, tls: tuple[Path, Path] | None = None,
          recording: Path | None = None, colo: str = "FRA", loc: str = "DE", seed: int = 1,
          now_fn: Any = time.time, **knobs: Any) -> FakeSpeed:
    app = SpeedApp(Templates(load_recording(recording)), colo=colo, loc=loc, seed=seed, now_fn=now_fn)
    if knobs:
        app.set(**knobs)
    srv = FakeSpeed(Handler, app, host=host, port=port, tls=tls, name="fake-cloudflare-speed")
    srv.start()
    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", default="127.0.0.1:8480")
    ap.add_argument("--cert", help="PEM certificate chain (with --key) to serve HTTPS")
    ap.add_argument("--key")
    ap.add_argument("--colo", default="FRA")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, stream=sys.stderr)
    host, _, port = args.listen.rpartition(":")
    tls = (Path(args.cert), Path(args.key)) if args.cert and args.key else None
    app = SpeedApp(Templates(load_recording()), colo=args.colo)
    srv = FakeSpeed(Handler, app, host=host or "127.0.0.1", port=int(port), tls=tls, name="fake-cloudflare-speed")
    fc.run_forever(srv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
