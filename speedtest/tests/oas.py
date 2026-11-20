"""Validate real responses against shared/openapi/speedtest.yaml (dev tooling: jsonschema + PyYAML, never product code)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "shared" / "schemas"
OPENAPI = ROOT / "shared" / "openapi"


def _rewrite(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: (v.replace("../schemas/", "") if k == "$ref" and isinstance(v, str) else _rewrite(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [_rewrite(x) for x in node]
    return node


DOC = _rewrite(yaml.safe_load((OPENAPI / "speedtest.yaml").read_text("utf-8")))


def _registry() -> Registry:
    reg = Registry()
    for f in sorted(SCHEMAS.glob("*.schema.json")):
        reg = reg.with_resource(f.name, Resource.from_contents(json.loads(f.read_text("utf-8"))))
    return reg.with_resource("speedtest.yaml", Resource.from_contents(DOC, default_specification=DRAFT202012))


REGISTRY = _registry()


def _esc(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")


def check(path: str, method: str, status: int, doc: Any, media: str = "application/json") -> None:
    op = DOC["paths"][path][method.lower()]
    resp = op["responses"].get(str(status))
    assert resp is not None, f"{method} {path}: status {status} is not documented in speedtest.yaml"
    if "$ref" in resp:
        name = resp["$ref"].rsplit("/", 1)[1]
        resp = DOC["components"]["responses"][name]
        base = f"speedtest.yaml#/components/responses/{_esc(name)}"
    else:
        base = f"speedtest.yaml#/paths/{_esc(path)}/{method.lower()}/responses/{status}"
    if "content" not in resp:
        return
    assert media in resp["content"], f"{method} {path} {status}: {media} not documented"
    v = Draft202012Validator({"$ref": f"{base}/content/{_esc(media)}/schema"}, registry=REGISTRY)
    errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
    assert not errs, f"{method} {path} {status}: " + "; ".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:5])


def check_schema(name: str, doc: Any) -> None:
    """Validate against a shared/schemas file (the result document the collector receives)."""
    schema = json.loads((SCHEMAS / name).read_text("utf-8"))
    errs = sorted(Draft202012Validator(schema, registry=REGISTRY).iter_errors(doc), key=lambda e: list(e.path))
    assert not errs, f"{name}: " + "; ".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:5])
