"""Differential test: our stdlib subset validator must agree (accept/reject) with `jsonschema`
(dev dependency only; never imported by product code)."""
import json
from pathlib import Path

import pytest

from exp_common import config

jsonschema = pytest.importorskip("jsonschema")
referencing = pytest.importorskip("referencing")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[3] / "test" / "fixtures"


def _registry():
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
    reg = Registry()
    for f in sorted(config.schemas_dir().glob("*.schema.json")):
        reg = reg.with_resource(f.name, Resource.from_contents(json.loads(f.read_text()), DRAFT202012))
    return reg


def _ref_valid(schema, doc, registry=None):
    cls = jsonschema.Draft202012Validator
    return cls(schema, registry=registry).is_valid(doc) if registry else cls(schema).is_valid(doc)


def test_fixture_index_accept_reject_matches_jsonschema_and_expectation():
    index_path = FIXTURES / "INDEX.json"
    if not index_path.exists():
        pytest.skip("test/fixtures/INDEX.json not present yet")
    index = json.loads(index_path.read_text())
    if not (config.schemas_dir()).is_dir():
        pytest.skip("schemas dir missing")
    reg = _registry()
    checked = 0
    for rel, meta in sorted(index.items()):
        path = FIXTURES / rel
        if not path.exists():
            continue
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue                     # deliberately unparseable fixtures are loader tests
        schema_name = meta["schema"]
        schema = json.loads((config.schemas_dir() / schema_name).read_text())
        ours = not config.iter_errors(doc, schema_name)
        ref = _ref_valid(schema, doc, reg)
        assert ours == ref, f"{rel}: stdlib validator={ours} jsonschema={ref}"
        assert ours == (meta["expected"] == "valid"), f"{rel}: expected {meta['expected']}, got valid={ours}"
        checked += 1
    assert checked > 0


# ----------------------------------------------------------------- hypothesis: ad-hoc schemas

_json = st.recursive(
    st.none() | st.booleans() | st.integers(-5, 5) | st.floats(-5, 5, allow_nan=False, allow_infinity=False)
    | st.text("ab1_-\n ", max_size=6),
    lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text("abc", min_size=1, max_size=2), c, max_size=4),
    max_leaves=12)

_names = st.sampled_from(["a", "b", "ab", "c"])
_type = st.sampled_from(["string", "number", "integer", "boolean", "null", "array", "object"])
_leaf = st.one_of(
    st.fixed_dictionaries({"type": _type | st.lists(_type, min_size=1, max_size=3, unique=True)}),
    st.fixed_dictionaries({}, optional={"minimum": st.integers(-3, 3), "maximum": st.integers(-3, 3),
                                        "exclusiveMinimum": st.integers(-3, 3),
                                        "exclusiveMaximum": st.integers(-3, 3)}),
    st.fixed_dictionaries({}, optional={"minLength": st.integers(0, 4), "maxLength": st.integers(0, 4),
                                        "pattern": st.sampled_from(["^a", "b$", "[0-9]", "^[a-z]+$"])}),
    st.fixed_dictionaries({}, optional={"minItems": st.integers(0, 3), "maxItems": st.integers(0, 3),
                                        "uniqueItems": st.booleans()}),
    st.fixed_dictionaries({}, optional={"minProperties": st.integers(0, 3), "maxProperties": st.integers(0, 3),
                                        "required": st.lists(_names, max_size=3, unique=True)}),
    st.fixed_dictionaries({}, optional={"enum": st.lists(_json, min_size=1, max_size=3)}),
    st.fixed_dictionaries({}, optional={"const": _json}),
    st.sampled_from([True, False]))


def _extend(c):
    return st.one_of(
        c,
        st.fixed_dictionaries({}, optional={
            "properties": st.dictionaries(_names, c, max_size=3),
            "patternProperties": st.dictionaries(st.sampled_from(["^a", "b", "^$"]), c, max_size=2),
            "additionalProperties": c,
            "propertyNames": c,
            "required": st.lists(_names, max_size=2, unique=True)}),
        st.fixed_dictionaries({}, optional={"items": c, "prefixItems": st.lists(c, min_size=1, max_size=3),
                                            "minItems": st.integers(0, 3)}),
        st.fixed_dictionaries({"anyOf": st.lists(c, min_size=1, max_size=3)}),
        st.fixed_dictionaries({"oneOf": st.lists(c, min_size=1, max_size=3)}),
        st.fixed_dictionaries({"allOf": st.lists(c, min_size=1, max_size=3)}),
        st.fixed_dictionaries({"not": c}),
    )


_schema = st.recursive(_leaf, _extend, max_leaves=8)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(schema=_schema, doc=_json)
def test_random_schemas_and_docs_agree_with_jsonschema(schema, doc):
    ours = not config.iter_errors(doc, schema)
    ref = _ref_valid(schema, doc)
    assert ours == ref, f"schema={json.dumps(schema)} doc={json.dumps(doc)} ours={ours} ref={ref}"


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(doc=_json)
def test_docs_agree_on_local_refs(doc):
    schema = {"$defs": {"n": {"anyOf": [{"type": "null"}, {"type": "array", "items": {"$ref": "#/$defs/n"}}]}},
              "$ref": "#/$defs/n"}
    assert (not config.iter_errors(doc, schema)) == _ref_valid(schema, doc)
