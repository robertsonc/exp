"""Test plumbing for the fakes (dev tooling: uses jsonschema + PyYAML, never imported by product code)."""
from __future__ import annotations

import http.client
import json
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

FAKES = Path(__file__).resolve().parents[1]
ROOT = FAKES.parents[1]
for p in (str(FAKES), str(ROOT / "shared" / "python")):
    if p not in sys.path:
        sys.path.insert(0, p)

SCHEMAS = ROOT / "shared" / "schemas"
OPENAPI = ROOT / "shared" / "openapi"


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
    for f in ("ingest", "collector", "agent", "admin"):
        doc = _rewrite_refs(yaml.safe_load((OPENAPI / f"{f}.yaml").read_text("utf-8")))
        reg = reg.with_resource(f"{f}.yaml", Resource.from_contents(doc, default_specification=DRAFT202012))
    return reg


REGISTRY = _registry()
_DOCS = {f: _rewrite_refs(yaml.safe_load((OPENAPI / f"{f}.yaml").read_text("utf-8")))
         for f in ("ingest", "collector", "agent", "admin")}


def _esc(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")


def check_openapi(api: str, path: str, method: str, status: int, doc: Any, media: str = "application/json") -> None:
    """Validate `doc` against the documented response schema of (path, method, status) in `api`.yaml."""
    op = _DOCS[api]["paths"][path][method.lower()]
    resp = op["responses"].get(str(status))
    assert resp is not None, f"{method} {path}: status {status} is not documented in {api}.yaml"
    if "$ref" in resp:   # shared response component
        name = resp["$ref"].rsplit("/", 1)[1]
        resp = _DOCS[api]["components"]["responses"][name]
        ref_base = f"{api}.yaml#/components/responses/{_esc(name)}"
    else:
        ref_base = f"{api}.yaml#/paths/{_esc(path)}/{method.lower()}/responses/{status}"
    if "content" not in resp:
        assert doc in (None, b"", ""), f"{method} {path} {status} must have no body"
        return
    assert media in resp["content"], f"{method} {path} {status}: {media} not documented"
    v = Draft202012Validator({"$ref": f"{ref_base}/content/{_esc(media)}/schema"}, registry=REGISTRY)
    errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
    assert not errs, f"{method} {path} {status}: " + "; ".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:5])


def check_response_headers(api: str, path: str, method: str, status: int, headers: dict[str, str]) -> None:
    op = _DOCS[api]["paths"][path][method.lower()]
    resp = op["responses"][str(status)]
    for name, spec in (resp.get("headers") or {}).items():
        if "$ref" in spec:
            spec = _DOCS[api]["components"]["headers"][spec["$ref"].rsplit("/", 1)[1]]
        const = (spec.get("schema") or {}).get("const")
        if const is not None:
            got = {k.lower(): v for k, v in headers.items()}.get(name.lower())
            assert got == const, f"{method} {path} {status}: header {name} = {got!r}, documented {const!r}"


def check_schema_file(name: str, doc: Any) -> None:
    schema = json.loads((SCHEMAS / name).read_text("utf-8"))
    v = Draft202012Validator(schema, registry=REGISTRY)
    errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
    assert not errs, f"{name}: " + "; ".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:5])


@dataclass
class R:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    def h(self, name: str) -> str | None:
        return {k.lower(): v for k, v in self.headers.items()}.get(name.lower())


def request(port: int, method: str, path: str, body: bytes | dict | list | None = None,
            headers: dict[str, str] | None = None, host: str = "127.0.0.1", tls: bool = False,
            timeout: float = 15.0) -> R:
    hdrs = dict(headers or {})
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return R(resp.status, dict(resp.getheaders()), data)
    finally:
        conn.close()


@pytest.fixture()
def req():
    return request


def check_component(api: str, name: str, doc: Any) -> None:
    """Validate `doc` against components.schemas.<name> of an OpenAPI file."""
    v = Draft202012Validator({"$ref": f"{api}.yaml#/components/schemas/{name}"}, registry=REGISTRY)
    errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
    assert not errs, f"{api}.{name}: " + "; ".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:5])
