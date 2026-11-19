"""Contract tests for shared/openapi/*.yaml (WP-0).

Checks: OpenAPI 3.1 validity (external refs resolved relative to each file), the endpoint tables of
01-contracts.md sections 4-6 and 13, the agreed schema file names, the agreed JSON-Schema keyword
subset in inline schemas, and per-operation hygiene (operationId, 4xx error response, role marker).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from openapi_spec_validator import validate

HERE = Path(__file__).resolve().parent
SCHEMAS = HERE.parent / "schemas"
FILES = ["ingest", "collector", "agent", "admin"]

AGREED_SCHEMA_FILES = {
    "common", "measurement", "desired", "status", "health", "state", "beats", "incident", "manifest",
    "probe.config", "collector.config", "dashboard.config", "runner.config",
}
AGREED_NAMES = {f"{n}.schema.json" for n in AGREED_SCHEMA_FILES}

# Bases documented in each file's `servers` (paths in the files are relative to these).
BASES = {
    "ingest": "/ingest/v1",
    "collector": "/api/v1",
    "agent": "/api/agent/v1",
    "admin": "/api/admin/v1",
}

# (method, path relative to the base) per 01-contracts.md. Root-level routes (`/healthz`,
# `/install.sh`) are declared with an operation-level `servers` override of the bare host.
_TABLE = {
    "ingest": """
        POST /measurements
    """,
    "collector": """
        GET /health
        GET /probes
        GET /state
        GET /states
        GET /beats
        GET /records
        GET /incidents
        POST /incidents/{id}/ack
        GET /summary
        GET /query_range
        GET /stream
        GET /drills/{run_id}
        POST /drills/{run_id}/abort
        GET /drills/control
        GET /healthz
    """,
    "agent": """
        POST /enrol
        GET /desired
        GET /releases/{version}/manifest
        GET /releases/{version}/manifest.sig
        GET /artifacts/{artifact_id}
        POST /status
        POST /rotate
        POST /decommissioned
        GET /install.sh
        GET /healthz
    """,
    "admin": """
        GET /me
        GET /sites
        POST /sites
        GET /sites/{site}
        PATCH /sites/{site}
        DELETE /sites/{site}
        GET /hosts
        POST /hosts
        GET /hosts/{id}
        PATCH /hosts/{id}
        DELETE /hosts/{id}
        POST /hosts/{id}/enrol-token
        POST /hosts/{id}/decommission
        GET /hosts/{id}/components
        POST /hosts/{id}/components
        PATCH /components/{component_id}
        DELETE /components/{component_id}
        POST /components/{component_id}/restart
        PUT /components/{component_id}/ports
        GET /releases
        POST /releases/import
        POST /releases/upload
        PATCH /sites/{site}/release
        POST /components/{component_id}/rotate
        POST /hosts/{id}/rotate-agent
        GET /dashboards/{dashboard_id}/users
        POST /dashboards/{dashboard_id}/users
        DELETE /dashboards/{dashboard_id}/users/{usr}
        GET /dashboards/{dashboard_id}/noc-tokens
        POST /dashboards/{dashboard_id}/noc-tokens
        DELETE /dashboards/{dashboard_id}/noc-tokens/{noc}
        POST /dashboards/{dashboard_id}/sso
        GET /sites/{site}/alerts
        PUT /sites/{site}/alerts
        POST /sites/{site}/alerts/test
        GET /integrations/{kind}
        PUT /integrations/{kind}
        POST /integrations/{kind}/test
        GET /drills
        POST /drills
        POST /drills/{id}/approve
        POST /drills/{id}/start
        POST /drills/abort-all
        GET /drills/{id}/runs/{run}
        GET /overview
        GET /hosts/{id}/status
        GET /fleet/summary
        GET /fleet/sites
        GET /fleet/hosts
        GET /fleet/hosts/{id}/metrics
        GET /fleet/hosts/{id}/interfaces/{iface}/metrics
        GET /fleet/components/{component_id}/probes
        GET /fleet/components/{component_id}/metrics
        GET /fleet/top
        GET /issues
        POST /issues/{id}/snooze
        DELETE /issues/{id}/snooze
        GET /settings/fleet-thresholds
        PUT /settings/fleet-thresholds
        GET /settings/platform-webhook
        PUT /settings/platform-webhook
        POST /settings/platform-webhook/test
        GET /audit
        GET /settings
        PATCH /settings
    """,
}
EXPECTED = {
    k: [(line.split()[0].lower(), line.split()[1]) for line in v.strip().splitlines()]
    for k, v in _TABLE.items()
}

# JSON Schema keyword subset a stdlib validator implements (plus OpenAPI `x-*` extensions).
ALLOWED_KEYWORDS = {
    "$schema", "$id", "$ref", "$defs", "title", "description", "type", "properties", "required",
    "additionalProperties", "patternProperties", "propertyNames", "items", "prefixItems", "minItems",
    "maxItems", "uniqueItems", "enum", "const", "pattern", "minLength", "maxLength", "minimum", "maximum",
    "exclusiveMinimum", "exclusiveMaximum", "minProperties", "maxProperties", "anyOf", "oneOf", "allOf",
    "not", "default", "examples",
}
METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}
ROLES = {"viewer", "operator", "admin", "owner"}
PUBLIC_OK_NO_ROLE = {"collector", "agent", "ingest"}


def _load(name: str) -> dict:
    return yaml.safe_load((HERE / f"{name}.yaml").read_text(encoding="utf-8"))


@pytest.fixture(params=FILES)
def api(request):
    return request.param, _load(request.param)


def _operations(doc):
    for path, item in doc["paths"].items():
        for method, o in item.items():
            if method in METHODS:
                yield path, method, o


def _walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def test_schemas_present_or_skip_note():
    missing = [n for n in AGREED_NAMES if not (SCHEMAS / n).is_file()]
    if missing:
        pytest.skip(f"schema files not yet present: {sorted(missing)}")


@pytest.mark.parametrize("name", FILES)
def test_validates_as_openapi_31(name):
    from openapi_spec_validator import validate as _validate

    path = HERE / f"{name}.yaml"
    doc = _load(name)
    assert doc["openapi"] == "3.1.0"
    assert doc["jsonSchemaDialect"] == "https://json-schema.org/draft/2020-12/schema"
    missing = [n for n in AGREED_NAMES if not (SCHEMAS / n).is_file()]
    if missing:
        pytest.skip(f"external schemas not yet present ({sorted(missing)}); cannot resolve $ref")
    _validate(doc, base_uri=path.as_uri())


def test_external_refs_actually_resolve():
    """Prove the validator does resolve cross-file refs: a bad file name must fail."""
    missing = [n for n in AGREED_NAMES if not (SCHEMAS / n).is_file()]
    if missing:
        pytest.skip("external schemas not yet present")
    doc = _load("ingest")
    doc["components"]["schemas"]["IngestResult"] = {"$ref": "../schemas/does-not-exist.schema.json"}
    with pytest.raises(Exception):  # noqa: B017 - any resolver error proves refs are followed
        validate(doc, base_uri=(HERE / "ingest.yaml").as_uri())


@pytest.mark.parametrize("name", FILES)
def test_every_contract_endpoint_exists(name):
    doc = _load(name)
    have = {(m, p) for p, m, _ in _operations(doc)}
    missing = [e for e in EXPECTED[name] if e not in have]
    assert not missing, f"{name}.yaml lacks contract endpoints: {missing}"


@pytest.mark.parametrize("name", FILES)
def test_no_undocumented_endpoints(name):
    doc = _load(name)
    have = {(m, p) for p, m, _ in _operations(doc)}
    extra = have - set(EXPECTED[name])
    assert not extra, f"{name}.yaml has endpoints not in the contract tables: {sorted(extra)}"


@pytest.mark.parametrize("name", FILES)
def test_servers_use_documented_base(name):
    doc = _load(name)
    urls = [s["url"] for s in doc["servers"]]
    assert len(urls) == 1 and urls[0].endswith(BASES[name]), urls
    for p, _m, o in _operations(doc):
        for s in o.get("servers", []):
            # only the root-level routes may override the base
            assert p in ("/healthz", "/install.sh"), p
            assert not s["url"].endswith("/v1")


def test_external_refs_use_agreed_filenames(api):
    name, doc = api
    seen = set()
    for node in _walk(doc):
        ref = node.get("$ref") if isinstance(node, dict) else None
        if isinstance(ref, str) and not ref.startswith("#"):
            fname, _, frag = ref.partition("#")
            assert fname.startswith("../schemas/"), ref
            base = fname[len("../schemas/"):]
            assert base in AGREED_NAMES, f"{name}: {ref} is not one of the 13 agreed schema files"
            assert frag == "" or frag.startswith("/"), ref
            seen.add(base)
    assert seen, f"{name}.yaml references no shared schema"


def test_internal_refs_resolve(api):
    name, doc = api
    for node in _walk(doc):
        ref = node.get("$ref") if isinstance(node, dict) else None
        if isinstance(ref, str) and ref.startswith("#/"):
            cur = doc
            for part in ref[2:].split("/"):
                assert part in cur, f"{name}: dangling {ref}"
                cur = cur[part]


def test_every_operation_has_id_summary_and_4xx(api):
    name, doc = api
    ids = []
    for p, m, o in _operations(doc):
        where = f"{name} {m.upper()} {p}"
        assert o.get("operationId"), where
        assert o.get("summary"), where
        ids.append(o["operationId"])
        codes = [str(c) for c in o["responses"]]
        assert any(c.startswith("4") for c in codes), f"{where}: no 4xx response"
        assert any(c.startswith("2") or c == "304" for c in codes), where
        for c, r in o["responses"].items():
            if str(c).startswith(("4", "5")) and "$ref" not in r:
                content = r.get("content", {})
                if "application/json" in content:
                    assert "error_envelope" in json.dumps(content["application/json"]["schema"]), where
    assert len(ids) == len(set(ids)), f"{name}: duplicate operationId"


def test_security_declared_on_every_operation(api):
    name, doc = api
    schemes = set(doc["components"]["securitySchemes"])
    assert {"ingestToken", "dashboardToken", "agentSecret", "accessJwt"} <= schemes
    assert doc["components"]["securitySchemes"]["accessJwt"] == {
        "type": "apiKey", "in": "header", "name": "Cf-Access-Jwt-Assertion",
        "description": doc["components"]["securitySchemes"]["accessJwt"]["description"],
    }
    for sname in ("ingestToken", "dashboardToken", "agentSecret"):
        s = doc["components"]["securitySchemes"][sname]
        assert s["type"] == "http" and s["scheme"] == "bearer"
    for p, m, o in _operations(doc):
        sec = o.get("security", doc.get("security"))
        assert sec is not None, f"{name} {m} {p}"
        for req in sec:
            assert set(req) <= schemes


def test_public_routes_are_explicitly_unauthenticated():
    public = (("collector", "/healthz"), ("agent", "/install.sh"), ("agent", "/enrol"), ("agent", "/healthz"))
    for name, path in public:
        o = _load(name)["paths"][path]
        o = o.get("get") or o.get("post")
        assert o["security"] == [], f"{name} {path} must be explicitly public"


def test_admin_every_operation_has_min_role_and_jwt():
    doc = _load("admin")
    assert doc["security"] == [{"accessJwt": []}]
    for p, m, o in _operations(doc):
        assert o.get("x-exp-min-role") in ROLES, f"{m} {p}"
        assert "security" not in o, f"admin {m} {p} must not weaken global Access JWT security"
        assert "401" in o["responses"] and "403" in o["responses"], f"{m} {p}"
        if m in ("post", "put", "patch", "delete"):
            # mutations are audited (the one exception: none; even tests/rotations are audited)
            assert o.get("x-exp-audited") is True, f"{m} {p}"


def test_admin_role_matrix_matches_spec():
    doc = _load("admin")
    role = {(m, p): o["x-exp-min-role"] for p, m, o in _operations(doc)}
    # 05-manager.md section 4
    assert role[("get", "/audit")] == "admin"
    assert role[("put", "/integrations/{kind}")] == "owner"
    assert role[("patch", "/settings")] == "owner"
    assert role[("post", "/drills")] == "admin"
    assert role[("post", "/drills/{id}/approve")] == "admin"
    assert role[("post", "/drills/{id}/start")] == "operator"
    assert role[("post", "/drills/abort-all")] == "operator"
    assert role[("post", "/dashboards/{dashboard_id}/sso")] == "viewer"
    assert role[("post", "/hosts/{id}/decommission")] == "admin"
    assert role[("post", "/components/{component_id}/rotate")] == "admin"
    assert role[("post", "/releases/import")] == "admin"
    assert role[("get", "/dashboards/{dashboard_id}/users")] == "admin"
    for (m, p), r in role.items():
        admin_only = ("/audit", "/dashboards/{dashboard_id}/users", "/dashboards/{dashboard_id}/noc-tokens")
        if m == "get" and p not in admin_only:
            assert r == "viewer", (m, p)


def test_fleet_endpoints_document_etag_and_cache():
    doc = _load("admin")
    n = 0
    for p, _m, o in _operations(doc):
        if p.startswith("/fleet/"):
            n += 1
            r200 = o["responses"]["200"]
            assert set(r200["headers"]) == {"ETag", "Cache-Control"}, p
            assert r200["headers"]["Cache-Control"]["schema"]["const"] == "private, max-age=15"
            assert "304" in o["responses"], p
            assert any(prm.get("name") == "If-None-Match" for prm in o["parameters"]), p
    assert n == 8


def test_agent_desired_documents_etag_and_304():
    o = _load("agent")["paths"]["/desired"]["get"]
    assert "304" in o["responses"] and "ETag" in o["responses"]["200"]["headers"]
    assert any(p["name"] == "If-None-Match" and p["in"] == "header" for p in o["parameters"])
    codes = set(_load("agent")["paths"]["/enrol"]["post"]["responses"])
    assert {"201", "401", "410", "429"} <= codes


def test_ingest_limits_and_status_table():
    doc = _load("ingest")
    o = doc["paths"]["/measurements"]["post"]
    assert {"200", "400", "401", "413", "415", "429", "503"} <= set(o["responses"])
    lim = o["requestBody"]["content"]["application/x-ndjson"]["x-exp-limits"]
    assert lim == {"max_lines": 1000, "max_wire_bytes": 4 * 1024 * 1024,
                   "max_decompressed_bytes": 16 * 1024 * 1024, "max_line_bytes": 64 * 1024}
    rejected = doc["components"]["schemas"]["RejectedLine"]
    codes = set(rejected["properties"]["error"]["properties"]["code"]["enum"])
    assert {"identity_mismatch", "ts_future", "ts_too_old"} <= codes
    assert "Retry-After" in o["responses"]["429"]["headers"]


def test_collector_sse_events_documented():
    o = _load("collector")["paths"]["/stream"]["get"]
    assert set(o["x-exp-sse-events"]) == {"beat", "state", "incident"}
    assert "text/event-stream" in o["responses"]["200"]["content"]
    assert o["x-exp-sse-comments"] == {"keepalive_interval_s": 15, "retry_ms": 3000, "replay_window_s": 300}


def test_list_params_bounded():
    for name in FILES:
        doc = _load(name)
        lim = doc["components"].get("parameters", {}).get("Limit")
        if lim is not None:
            assert lim["schema"]["maximum"] == 1000 and lim["schema"]["default"] == 100


def _schema_nodes(doc):
    """Yield (location, schema) for every Schema Object kept inline in the document."""
    def walk_schema(sch, loc):
        if not isinstance(sch, dict):
            return
        yield loc, sch
        for key in ("properties", "patternProperties", "$defs"):
            for k, v in (sch.get(key) or {}).items():
                yield from walk_schema(v, f"{loc}/{key}/{k}")
        for key in ("items", "additionalProperties", "propertyNames", "not"):
            if isinstance(sch.get(key), dict):
                yield from walk_schema(sch[key], f"{loc}/{key}")
        for key in ("anyOf", "oneOf", "allOf", "prefixItems"):
            for i, v in enumerate(sch.get(key) or []):
                yield from walk_schema(v, f"{loc}/{key}/{i}")

    for k, v in doc.get("components", {}).get("schemas", {}).items():
        yield from walk_schema(v, f"components/schemas/{k}")
    for node in _walk(doc.get("paths", {})):
        if "schema" in node and isinstance(node["schema"], dict):
            yield from walk_schema(node["schema"], "paths(schema)")
    for k, v in doc.get("components", {}).get("parameters", {}).items():
        yield from walk_schema(v.get("schema", {}), f"components/parameters/{k}")
    for k, v in doc.get("components", {}).get("headers", {}).items():
        yield from walk_schema(v.get("schema", {}), f"components/headers/{k}")


def test_inline_schemas_use_only_agreed_keyword_subset(api):
    name, doc = api
    bad = []
    for loc, sch in _schema_nodes(doc):
        for key in sch:
            if key not in ALLOWED_KEYWORDS and not key.startswith("x-"):
                bad.append((loc, key))
        if "type" in sch:
            t = sch["type"]
            ts = t if isinstance(t, list) else [t]
            assert set(ts) <= {"string", "number", "integer", "boolean", "object", "array", "null"}, loc
    assert not bad, f"{name}: keywords outside the agreed subset: {bad[:10]}"


def test_no_secrets_or_real_hosts_in_examples():
    for name in FILES:
        text = (HERE / f"{name}.yaml").read_text(encoding="utf-8")
        assert not re.search(r"exp[aeidn]_[A-Za-z0-9_-]{43}", text), f"{name}: token-shaped value present"
        assert "BEGIN PRIVATE KEY" not in text
