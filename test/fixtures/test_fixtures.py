"""Fixture and schema conformance tests (WP-0). Dev tooling only: uses jsonschema, never imported by product code."""
from __future__ import annotations

import gzip
import json
import os
import re
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCHEMAS = os.path.join(ROOT, "shared", "schemas")
EXM = os.path.join(HERE, "exm", "outage-2026-10-27.ndjson.gz")

ALLOWED = {"$schema", "$id", "$ref", "$defs", "title", "description", "type", "properties", "required", "additionalProperties",
           "patternProperties", "propertyNames", "items", "prefixItems", "minItems", "maxItems", "uniqueItems", "enum", "const",
           "pattern", "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minProperties",
           "maxProperties", "anyOf", "oneOf", "allOf", "not", "default", "examples"}
SCHEMA_FILES = sorted(f for f in os.listdir(SCHEMAS) if f.endswith(".schema.json"))
DOC_SCHEMAS = {"measurement": "exp.measurement/1", "desired": "exp.desired/1", "status": "exp.status/1", "health": "exp.health/1",
               "state": "exp.state/1", "beats": "exp.beats/1", "manifest": "exp.manifest/1", "probe.config": "exp.probe.config/1",
               "collector.config": "exp.collector.config/1", "dashboard.config": "exp.dashboard.config/1", "runner.config": "exp.runner.config/1"}


def load(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def registry() -> Registry:
    reg = Registry()
    for name in SCHEMA_FILES:
        reg = reg.with_resource(name, Resource.from_contents(load(os.path.join(SCHEMAS, name))))
    return reg


REG = registry()


def validator(schema_file: str) -> Draft202012Validator:
    return Draft202012Validator(load(os.path.join(SCHEMAS, schema_file)), registry=REG)


def walk_keywords(node, found: list, where: str = "") -> None:
    """Collect (keyword, location) for every schema object under node, schema-aware (property names are not keywords)."""
    if not isinstance(node, dict):
        found.append(("<non-object schema: %r>" % (node,), where))
        return
    for kw, val in node.items():
        found.append((kw, where))
        if kw in ("properties", "patternProperties", "$defs"):
            for k, sub in val.items():
                walk_keywords(sub, found, where + "/" + kw + "/" + k)
        elif kw in ("items", "additionalProperties", "propertyNames", "not"):
            if kw == "additionalProperties" and isinstance(val, bool):
                continue
            walk_keywords(val, found, where + "/" + kw)
        elif kw in ("anyOf", "oneOf", "allOf", "prefixItems"):
            for i, sub in enumerate(val):
                walk_keywords(sub, found, "%s/%s/%d" % (where, kw, i))


# (a) -------------------------------------------------------------------------
def test_expected_schema_files_exist():
    want = {"common.schema.json", "incident.schema.json"} | {k + ".schema.json" for k in DOC_SCHEMAS}
    assert want <= set(SCHEMA_FILES)


@pytest.mark.parametrize("name", SCHEMA_FILES)
def test_schema_is_valid_2020_12(name):
    Draft202012Validator.check_schema(load(os.path.join(SCHEMAS, name)))


@pytest.mark.parametrize("name", SCHEMA_FILES)
def test_schema_uses_only_the_allowed_keyword_subset(name):
    found: list = []
    walk_keywords(load(os.path.join(SCHEMAS, name)), found)
    bad = sorted({(k, w) for k, w in found if k not in ALLOWED})
    assert not bad, bad


@pytest.mark.parametrize("name", SCHEMA_FILES)
def test_schema_id_and_const_pins(name):
    s = load(os.path.join(SCHEMAS, name))
    assert s["$id"] == name
    assert s["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    stem = name[:-len(".schema.json")]
    if stem in DOC_SCHEMAS:
        assert s["properties"]["schema"] == {"const": DOC_SCHEMAS[stem]}
        assert "schema" in s["required"]
    if stem == "incident":
        assert "schema" not in s["properties"]


def test_all_refs_resolve_and_are_local_or_relative_file():
    for name in SCHEMA_FILES:
        text = open(os.path.join(SCHEMAS, name), encoding="utf-8").read()
        for ref in re.findall(r'"\$ref":\s*"([^"]+)"', text):
            # local, cross-file fragment, or (desired -> per-type config only) a whole-file ref
            assert re.match(r"^(#/\$defs/[A-Za-z0-9_]+|[a-z.]+\.schema\.json(#/\$defs/[A-Za-z0-9_]+)?)$", ref), (name, ref)
            file, _, frag = ref.partition("#")
            assert file in SCHEMA_FILES or file == "", (name, ref)
            target = load(os.path.join(SCHEMAS, file or name))
            if frag:
                assert frag.split("/")[-1] in target["$defs"], (name, ref)


# (b)(c) ----------------------------------------------------------------------
INDEX = load(os.path.join(HERE, "INDEX.json"))


def test_index_shape():
    assert INDEX
    for path, ent in INDEX.items():
        assert set(ent) == {"schema", "expected"}, path
        assert ent["expected"] in ("valid", "invalid"), path
        assert ent["schema"] in SCHEMA_FILES, path


def test_every_index_entry_exists_and_every_fixture_is_indexed():
    on_disk = set()
    for dp, _, fs in os.walk(HERE):
        for f in fs:
            if f.endswith(".json") and f != "INDEX.json":
                on_disk.add(os.path.relpath(os.path.join(dp, f), HERE))
    assert on_disk == set(INDEX), (sorted(on_disk - set(INDEX)), sorted(set(INDEX) - on_disk))


@pytest.mark.parametrize("path", sorted(INDEX))
def test_fixture_validates_as_declared(path):
    ent = INDEX[path]
    errors = sorted(validator(ent["schema"]).iter_errors(load(os.path.join(HERE, path))), key=lambda e: list(e.path))
    if ent["expected"] == "valid":
        assert not errors, [e.message[:200] for e in errors[:3]]
    else:
        assert errors, "forbidden document was accepted"


def test_coverage_of_required_fixture_kinds():
    tests = {load(os.path.join(HERE, p))["test"] for p, e in INDEX.items() if p.startswith("measurements/")}
    catalog = {"gateway", "dhcp_hb", "dns_hb", "trace", "ping", "dhcp", "dns", "app", "throughput", "path", "wifi_hb", "wifi_join",
               "target_access", "probe_self", "ext_mist", "ext_ec", "drill"}
    assert catalog <= tests
    for t in ("gateway", "dhcp_hb", "dns_hb", "trace", "ping", "wifi_hb"):
        outs = {load(os.path.join(HERE, p))["outcome"] for p, e in INDEX.items()
                if p.startswith("measurements/") and load(os.path.join(HERE, p))["test"] == t}
        assert outs >= {"ok", "degraded", "fail", "error"}, t
    assert sum(1 for p, e in INDEX.items() if p.startswith("invalid/measurements/")) >= 12
    assert sum(1 for p, e in INDEX.items() if p.startswith("invalid/configs/")) >= 6


def test_each_invalid_measurement_breaks_exactly_one_thing():
    """Every invalid measurement is the valid gateway.ok base with a single mutation: it must fail, and the base must pass."""
    base = load(os.path.join(HERE, "measurements", "gateway.ok.json"))
    v = validator("measurement.schema.json")
    assert not list(v.iter_errors(base))
    for p in INDEX:
        if not p.startswith("invalid/measurements/"):
            continue
        d = load(os.path.join(HERE, p))
        changed = {k for k in set(d) | set(base) if d.get(k) != base.get(k)}
        assert len(changed) == 1, (p, changed)


# (d) -------------------------------------------------------------------------
def test_converted_outage_fixture_validates_with_unique_ids():
    v = validator("measurement.schema.json")
    seen = set()
    n = 0
    prev_ts = ""
    with gzip.open(EXM, "rt", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            rec = json.loads(line)
            errs = list(v.iter_errors(rec))
            assert not errs, (lineno, errs[0].message[:200])
            key = (rec["probe"], rec["id"])
            assert key not in seen, key
            seen.add(key)
            assert rec["ts"] >= prev_ts, "output must be ordered by ts"
            prev_ts = rec["ts"]
            assert len(json.dumps(rec.get("detail", {}), separators=(",", ":"))) <= 8192, lineno
            n += 1
    assert n > 10000


# (e) -------------------------------------------------------------------------
def test_convert_exm_is_deterministic(tmp_path):
    a, b = tmp_path / "a.ndjson.gz", tmp_path / "b.ndjson.gz"
    for out in (a, b):
        subprocess.run([sys.executable, os.path.join(HERE, "convert_exm.py"), "--out", str(out)], check=True, timeout=300)
    assert a.read_bytes() == b.read_bytes()
    assert a.read_bytes() == open(EXM, "rb").read(), "committed fixture is stale: rerun convert_exm.py"


def test_gen_fixtures_is_deterministic_and_matches_committed(tmp_path):
    subprocess.run([sys.executable, os.path.join(HERE, "gen_fixtures.py"), str(tmp_path)], check=True, timeout=120)
    for p in INDEX:
        assert (tmp_path / p).read_bytes() == open(os.path.join(HERE, p), "rb").read(), p
    assert (tmp_path / "INDEX.json").read_bytes() == open(os.path.join(HERE, "INDEX.json"), "rb").read()
