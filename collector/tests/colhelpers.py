"""Test plumbing: fake VictoriaMetrics, HTTPS client, record factory, OpenAPI response checks."""
from __future__ import annotations

import gzip
import http.client
import json
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT / "collector"), str(ROOT / "shared" / "python")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from exp_common import ids, schema, tlspin  # noqa: E402

from exp_collector.app import CollectorApp  # noqa: E402
from exp_collector.config import CollectorConfig, CredStore, Paths  # noqa: E402

SCHEMAS = ROOT / "shared" / "schemas"
OPENAPI = ROOT / "shared" / "openapi"


# ----------------------------------------------------------------------------------- fake VM
class FakeVM:
    """Tiny VictoriaMetrics stand-in: records /api/v1/import bodies; can be 'down' (503) or stopped."""

    def __init__(self, port: int = 0) -> None:
        self.lines: list[dict[str, Any]] = []
        self.requests = 0
        self.mode = "up"          # up | 503 | 400
        self.lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a: Any) -> None:
                pass

            def _reply(self, status: int, body: bytes = b"") -> None:
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path == "/health":
                    self._reply(503 if outer.mode == "503" else 200, b"OK")
                elif self.path.startswith("/api/v1/series/count"):
                    self._reply(200, json.dumps({"status": "success", "data": [len(outer.lines)]}).encode())
                elif self.path == "/metrics":
                    self._reply(200, b'vm_data_size_bytes{type="storage/small"} 1048576\n')
                else:
                    self._reply(404)

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                with outer.lock:
                    outer.requests += 1
                    mode = outer.mode
                if self.path != "/api/v1/import":
                    return self._reply(404)
                if mode == "503":
                    return self._reply(503, b"down")
                if mode == "400":
                    return self._reply(400, b"bad")
                parsed = [json.loads(ln) for ln in body.decode().split("\n") if ln]
                with outer.lock:
                    outer.lines.extend(parsed)
                self._reply(204)

        class S(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.httpd = S(("127.0.0.1", port), H)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def names(self) -> list[str]:
        with self.lock:
            return [ln["metric"]["__name__"] for ln in self.lines]

    def count(self, name: str | None = None) -> int:
        with self.lock:
            return sum(1 for ln in self.lines if name is None or ln["metric"]["__name__"] == name)


# -------------------------------------------------------------------------------- HTTPS client
@dataclass
class Resp:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    def h(self, name: str) -> str | None:
        return {k.lower(): v for k, v in self.headers.items()}.get(name.lower())


def client_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def https(port: int, method: str, path: str, *, body: bytes | None = None, headers: dict[str, str] | None = None,
          timeout: float = 20.0) -> Resp:
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout, context=client_ctx())
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        return Resp(r.status, {k: v for k, v in r.getheaders()}, r.read())
    finally:
        conn.close()


def raw_tls(port: int, timeout: float = 15.0) -> ssl.SSLSocket:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    return client_ctx().wrap_socket(s, server_hostname="localhost")


def ingest(port: int, token: str, lines: list[Any] | bytes, *, gz: bool = False, ctype: str = "application/x-ndjson",
           extra: dict[str, str] | None = None) -> Resp:
    if isinstance(lines, bytes):
        body = lines
    else:
        body = b"\n".join(x if isinstance(x, bytes) else json.dumps(x).encode() for x in lines) + b"\n"
    h = {"Authorization": f"Bearer {token}", "Content-Type": ctype, "User-Agent": "exp-probe/0.1.0"}
    if gz:
        body = gzip.compress(body)
        h["Content-Encoding"] = "gzip"
    h.update(extra or {})
    return https(port, "POST", "/ingest/v1/measurements", body=body, headers=h)


# --------------------------------------------------------------------------------- records
def rec(probe: str = "probe-a1", site: str = "hall-b", test: str = "ping", outcome: str = "ok", ts: str | None = None,
        **kw: Any) -> dict[str, Any]:
    kw.setdefault("metrics", {"rtt_ms": 12.5})
    kw.setdefault("labels", {"port": "c01"})
    m = schema.measure(probe, test, outcome, site=site, ts=ts or schema.utcnow(), **kw)
    return m.to_dict()


def iso(epoch: float) -> str:
    import datetime
    return (datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def new_id() -> str:
    return ids.new_ulid()


def wait_for(cond: Any, timeout: float = 10.0, interval: float = 0.05) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(interval)
    return bool(cond())


# ------------------------------------------------------------------------- OpenAPI/JSON Schema
def _rewrite_refs(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: (v.replace("../schemas/", "") if k == "$ref" and isinstance(v, str) else _rewrite_refs(v))
                for k, v in node.items()}
    if isinstance(node, list):
        return [_rewrite_refs(x) for x in node]
    return node


def _registry() -> Registry:
    reg = Registry()
    for f in sorted(SCHEMAS.glob("*.schema.json")):
        reg = reg.with_resource(f.name, Resource.from_contents(json.loads(f.read_text("utf-8"))))
    for f in ("ingest", "collector"):
        doc = _rewrite_refs(yaml.safe_load((OPENAPI / f"{f}.yaml").read_text("utf-8")))
        reg = reg.with_resource(f"{f}.yaml", Resource.from_contents(doc, default_specification=DRAFT202012))
    return reg


REGISTRY = _registry()
_DOCS = {f: _rewrite_refs(yaml.safe_load((OPENAPI / f"{f}.yaml").read_text("utf-8"))) for f in ("ingest", "collector")}


def _esc(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")


def check_openapi(api: str, path: str, method: str, status: int, doc: Any) -> None:
    op = _DOCS[api]["paths"][path][method.lower()]
    resp = op["responses"].get(str(status))
    assert resp is not None, f"{method} {path}: status {status} is not documented in {api}.yaml"
    if "$ref" in resp:
        name = resp["$ref"].rsplit("/", 1)[1]
        resp = _DOCS[api]["components"]["responses"][name]
        base = f"{api}.yaml#/components/responses/{_esc(name)}"
    else:
        base = f"{api}.yaml#/paths/{_esc(path)}/{method.lower()}/responses/{status}"
    media = "application/json"
    assert media in resp.get("content", {}), f"{method} {path} {status}: no JSON body documented"
    v = Draft202012Validator({"$ref": f"{base}/content/{_esc(media)}/schema"}, registry=REGISTRY)
    errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
    assert not errs, f"{method} {path} {status}: " + "; ".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:5])


def check_schema_file(name: str, doc: Any) -> None:
    sch = json.loads((SCHEMAS / name).read_text("utf-8"))
    errs = sorted(Draft202012Validator(sch, registry=REGISTRY).iter_errors(doc), key=lambda e: list(e.path))
    assert not errs, f"{name}: " + "; ".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:5])


# ---------------------------------------------------------------------------- environment
CONFIG_FIXTURE = ROOT / "test" / "fixtures" / "configs" / "collector.json"


class Env:
    """A temp collector environment: dirs, tokens, config. `start()` builds a running app."""

    def __init__(self, tmp: Path, vm_url: str) -> None:
        self.tmp = tmp
        self.state = tmp / "state"
        self.run = tmp / "run"
        self.creds = tmp / "creds"
        for d in (self.state, self.run, self.creds):
            d.mkdir(parents=True, exist_ok=True)
        self.cert, self.key = tlspin.generate_self_signed_cert(self.state / "tls", cn="col-hallb")
        self.vm_url = vm_url
        self.ingest_token = ids.new_token("expi")
        self.ingest_token2 = ids.new_token("expi")
        self.dash_token = ids.new_token("expd")
        self.cfg_doc = json.loads(CONFIG_FIXTURE.read_text())
        self.cfg_doc["probes"] = [{"probe_id": "probe-a1", "site": "hall-b", "label": "Hall B east"},
                                  {"probe_id": "probe-a2", "site": "hall-b", "label": "Hall B west"},
                                  {"probe_id": "probe-c1", "site": "hall-c", "label": "Hall C"}]
        self.write_creds({"probe-a1": ids.token_hash(self.ingest_token),
                          "probe-a2": ids.token_hash(self.ingest_token2)},
                         {"dash-main": ids.token_hash(self.dash_token)}, [])
        self.apps: list[CollectorApp] = []

    def write_creds(self, ingest: dict[str, str], dash: dict[str, str], hooks: list[Any]) -> None:
        (self.creds / "ingest_tokens.json").write_text(json.dumps(ingest))
        (self.creds / "dashboard_tokens.json").write_text(json.dumps(dash))
        (self.creds / "webhooks.json").write_text(json.dumps(hooks))

    def config(self) -> CollectorConfig:
        return CollectorConfig.from_dict(self.cfg_doc)

    def paths(self) -> Paths:
        return Paths.resolve(self.state, self.run, self.creds)

    def start(self, **kw: Any) -> CollectorApp:
        kw.setdefault("monitor_interval_s", 0.3)
        creds = CredStore(self.creds, poll_s=kw.pop("poll_s", 0.2))
        app = CollectorApp(self.config(), self.paths(), creds=creds, vm_url=self.vm_url,
                           listen=kw.pop("listen", ("127.0.0.1", 0)), **kw)
        app.start()
        self.apps.append(app)
        return app

    def stop_all(self) -> None:
        for a in self.apps:
            a.stop()
        self.apps.clear()


