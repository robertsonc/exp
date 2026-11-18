import json
import os

import pytest

from exp_common import config
from exp_common.config import ConfigError, SchemaError, iter_errors, validate


def ok(doc, schema):
    assert iter_errors(doc, schema) == [], iter_errors(doc, schema)


def bad(doc, schema, path=None, text=None):
    errs = iter_errors(doc, schema)
    assert errs, f"expected rejection of {doc!r}"
    if path is not None:
        assert any(e.path == path for e in errs), errs
    if text is not None:
        assert any(text in e.message for e in errs), errs


# ---- types
@pytest.mark.parametrize("t,good,badv", [
    ("string", "x", 1), ("integer", 3, 3.5), ("integer", 3.0, True), ("number", 1.5, "1"),
    ("number", 2, True), ("boolean", False, 0), ("null", None, 0), ("array", [], {}), ("object", {}, []),
])
def test_type(t, good, badv):
    ok(good, {"type": t})
    bad(badv, {"type": t})


def test_type_union():
    s = {"type": ["string", "null"]}
    ok(None, s)
    ok("a", s)
    bad(1, s)


# ---- scalars
def test_enum_const_json_equality():
    ok(1, {"enum": [1, 2]})
    ok(1.0, {"const": 1})
    bad(True, {"const": 1})
    bad(1, {"const": True})
    bad("c", {"enum": ["a", "b"]})
    ok([1, {"a": [2]}], {"const": [1, {"a": [2.0]}]})
    bad([True], {"const": [1]})


def test_string_keywords():
    s = {"type": "string", "minLength": 2, "maxLength": 3, "pattern": "^a"}
    ok("ab", s)
    bad("a", s)
    bad("abcd", s)
    bad("ba", s)
    ok("€€", {"maxLength": 2})              # code points, not bytes
    ok("x", {"pattern": "x"})
    ok("axb", {"pattern": "x"})             # unanchored search


def test_number_keywords():
    s = {"minimum": 1, "maximum": 3, "exclusiveMinimum": 0, "exclusiveMaximum": 4}
    ok(1, s)
    ok(3, s)
    bad(0.5, s)
    bad(3.5, s)
    bad(4, {"exclusiveMaximum": 4})
    bad(0, {"exclusiveMinimum": 0})
    ok("str", {"minimum": 5})               # applies to numbers only
    ok(True, {"minimum": 5})                # booleans are not numbers


# ---- arrays
def test_array_keywords():
    bad([1], {"minItems": 2})
    bad([1, 2, 3], {"maxItems": 2})
    bad([1, 2, 1], {"uniqueItems": True}, path="/2")
    bad([1, 1.0], {"uniqueItems": True})
    ok([1, True], {"uniqueItems": True})
    ok([{"a": 1, "b": 2}, {"a": 1}], {"uniqueItems": True})
    bad([{"a": 1, "b": 2}, {"b": 2, "a": 1}], {"uniqueItems": True})
    ok([1, 1], {"uniqueItems": False})
    bad([1, "x"], {"items": {"type": "integer"}}, path="/1")


def test_prefix_items():
    s = {"prefixItems": [{"type": "string"}, {"type": "integer"}], "items": {"type": "boolean"}}
    ok(["a", 1, True], s)
    ok(["a"], s)
    bad(["a", 1, 2], s, path="/2")
    bad([1, 1], s, path="/0")
    ok(["a", 1, "anything"], {"prefixItems": [{"type": "string"}, {"type": "integer"}]})
    bad(["a", 1, 5], {"prefixItems": [{}], "items": False})


# ---- objects
def test_required_and_additional():
    s = {"type": "object", "required": ["a"], "properties": {"a": {"type": "integer"}},
         "additionalProperties": False}
    ok({"a": 1}, s)
    bad({}, s, text="missing required")
    bad({"a": 1, "b": 2}, s, path="/b")
    bad({"a": "x"}, s, path="/a")


def test_additional_properties_schema_and_pattern_properties():
    s = {"properties": {"a": {}}, "patternProperties": {"^x_": {"type": "integer"}},
         "additionalProperties": {"type": "string"}}
    ok({"a": [1], "x_1": 5, "z": "s"}, s)
    bad({"x_1": "no"}, s, path="/x_1")
    bad({"z": 1}, s, path="/z")
    # a key matching both properties and patternProperties must satisfy both
    s2 = {"properties": {"x_a": {"type": "string"}}, "patternProperties": {"^x_": {"minLength": 3}}}
    bad({"x_a": "ab"}, s2)


def test_property_names_and_counts():
    s = {"propertyNames": {"pattern": "^[a-z]+$", "maxLength": 3}, "minProperties": 1, "maxProperties": 2}
    ok({"ab": 1}, s)
    bad({"A": 1}, s)
    bad({"abcd": 1}, s)
    bad({}, s)
    bad({"a": 1, "b": 2, "c": 3}, s)
    bad({"a": 1}, {"propertyNames": False})


def test_pointer_escaping_in_paths():
    s = {"properties": {"a/b": {"properties": {"c~d": {"type": "integer"}}}}}
    bad({"a/b": {"c~d": "x"}}, s, path="/a~1b/c~0d")


# ---- combinators
def test_combinators():
    ok(5, {"anyOf": [{"type": "string"}, {"type": "integer"}]})
    bad(None, {"anyOf": [{"type": "string"}, {"type": "integer"}]})
    ok(5, {"oneOf": [{"type": "string"}, {"type": "integer"}]})
    bad(5, {"oneOf": [{"type": "integer"}, {"minimum": 1}]}, text="exactly one")
    bad(5, {"oneOf": [{"type": "string"}, {"type": "null"}]})
    ok(5, {"allOf": [{"type": "integer"}, {"minimum": 1}]})
    bad(0, {"allOf": [{"type": "integer"}, {"minimum": 1}]})
    ok("a", {"not": {"type": "integer"}})
    bad(1, {"not": {"type": "integer"}})


def test_boolean_schemas():
    ok(1, True)
    bad(1, False)
    ok({"a": 1}, {"properties": {"a": True}})
    bad({"a": 1}, {"properties": {"a": False}})


# ---- refs
def test_local_refs_and_recursion():
    s = {"$defs": {"n": {"type": "object", "properties": {"kids": {"type": "array", "items": {"$ref": "#/$defs/n"}}},
                         "additionalProperties": False}},
         "$ref": "#/$defs/n"}
    ok({"kids": [{"kids": [{}]}]}, s)
    bad({"kids": [{"kids": [{"x": 1}]}]}, s, path="/kids/0/kids/0/x")
    bad({"kids": 5}, {"$ref": "#/$defs/n", "$defs": s["$defs"]})


def test_ref_sibling_keywords_apply():
    s = {"$defs": {"i": {"type": "integer"}}, "properties": {"a": {"$ref": "#/$defs/i", "minimum": 5}}}
    ok({"a": 6}, s)
    bad({"a": 1}, s)
    bad({"a": "x"}, s)


def test_ref_cycle_protection():
    s = {"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}}, "$ref": "#/$defs/a"}
    with pytest.raises(SchemaError, match="cycle"):
        iter_errors(1, s)
    with pytest.raises(SchemaError, match="cycle"):
        iter_errors(1, {"$ref": "#"})


def test_dangling_and_malformed_refs():
    with pytest.raises(SchemaError):
        iter_errors(1, {"$ref": "#/$defs/missing"})
    for ref in ("", "#x", "http://evil.example/s.json", "../x.json#/a", "/etc/passwd#/a", "a/b.json#/x"):
        with pytest.raises(SchemaError):
            iter_errors(1, {"$ref": ref})


def test_cross_file_refs_relative_to_schemas_dir(tmp_path, monkeypatch):
    (tmp_path / "common.schema.json").write_text(json.dumps({"$defs": {"slug": {"type": "string", "pattern": "^[a-z]+$"}}}))
    (tmp_path / "doc.schema.json").write_text(json.dumps(
        {"$id": "doc.schema.json", "type": "object", "properties": {"s": {"$ref": "common.schema.json#/$defs/slug"}}}))
    monkeypatch.setenv("EXP_SCHEMAS_DIR", str(tmp_path))
    ok({"s": "abc"}, "doc")
    ok({"s": "abc"}, "doc.schema.json")
    bad({"s": "A"}, "doc", path="/s")
    validate({"s": "abc"}, "doc")
    with pytest.raises(ConfigError) as ei:
        validate({"s": "A"}, "doc")
    assert ei.value.errors[0].path == "/s" and "/s" in str(ei.value)
    # inline dict schema may reference files in schemas_dir too
    ok("abc", {"$ref": "common.schema.json#/$defs/slug"})


def test_schema_name_resolution(tmp_path, monkeypatch):
    (tmp_path / "probe.config.schema.json").write_text('{"type":"object"}')
    monkeypatch.setenv("EXP_SCHEMAS_DIR", str(tmp_path))
    for name in ("probe.config", "probe.config.schema.json", "exp.probe.config/1"):
        ok({}, name)
        bad([], name)
    with pytest.raises(SchemaError):
        iter_errors({}, "../../etc/passwd")      # path-ish names are only for explicit paths
    with pytest.raises(SchemaError):
        iter_errors({}, "Bad Name!")
    with pytest.raises(SchemaError, match="not found"):
        iter_errors({}, "nope")


def test_ref_file_path_traversal_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("EXP_SCHEMAS_DIR", str(tmp_path))
    (tmp_path.parent / "secret.json").write_text("{}")
    with pytest.raises(SchemaError):
        iter_errors(1, {"$ref": "../secret.json"})
    with pytest.raises(SchemaError):
        iter_errors(1, {"$ref": "..%2Fsecret.json"})


# ---- schema errors: unknown/forbidden keywords are never silently ignored
@pytest.mark.parametrize("kw", ["format", "if", "then", "else", "dependentRequired", "dependentSchemas",
                                "unevaluatedProperties", "unevaluatedItems", "$dynamicRef", "$anchor",
                                "contains", "multipleOf", "contentMediaType", "$comment", "bogus"])
def test_forbidden_keywords_raise(kw):
    with pytest.raises(SchemaError, match="unsupported schema keyword"):
        iter_errors(1, {kw: 1})
    with pytest.raises(SchemaError):
        iter_errors({"a": 1}, {"properties": {"a": {kw: 1}}})            # nested position
    with pytest.raises(SchemaError):
        iter_errors(1, {"$defs": {"x": {kw: 1}}})                         # unused defs still checked


def test_property_named_like_a_keyword_is_fine():
    ok({"format": 1, "if": 2}, {"properties": {"format": {"type": "integer"}, "if": {}}})
    ok(1, {"default": {"format": 1}, "examples": [{"if": 1}], "const": 1})


@pytest.mark.parametrize("schema", [
    {"type": "strin"}, {"type": []}, {"type": 3}, {"required": "a"}, {"required": [1]},
    {"minLength": -1}, {"minLength": 1.5}, {"minLength": True}, {"minimum": "1"}, {"pattern": "("},
    {"pattern": 5}, {"properties": []}, {"enum": []}, {"enum": 1}, {"anyOf": []}, {"anyOf": {}},
    {"uniqueItems": 1}, {"items": 5}, {"additionalProperties": "no"}, {"patternProperties": {"(": {}}},
    {"$ref": 5}, {"title": 5}, 5, "str", None,
])
def test_malformed_schemas_raise(schema):
    with pytest.raises(SchemaError):
        iter_errors(1, schema)


def test_real_schema_files_use_only_the_subset():
    d = config.schemas_dir()
    files = sorted(d.glob("*.schema.json"))
    if not files:
        pytest.skip(f"no schema files in {d} yet")
    for f in files:
        config.check_schema(json.loads(f.read_text()), where=f.name)


# ---- load_json / load_config
def test_load_json_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        config.load_json(tmp_path / "nope.json")
    p = tmp_path / "a.json"
    p.write_text("{bad")
    with pytest.raises(ConfigError, match=r"not valid JSON.*line 1"):
        config.load_json(p)
    p.write_bytes(b"\xff\xfe")
    with pytest.raises(ConfigError, match="UTF-8"):
        config.load_json(p)
    p.write_text('{"a":1,"a":2}')
    with pytest.raises(ConfigError, match="duplicate key"):
        config.load_json(p)
    for const in ("NaN", "Infinity", "-Infinity"):
        p.write_text(f'{{"a": {const}}}')
        with pytest.raises(ConfigError, match="non-finite"):
            config.load_json(p)
    p.write_text("[" * 100000)
    with pytest.raises(ConfigError):
        config.load_json(p, max_bytes=10_000_000)
    with pytest.raises(ConfigError, match="not a regular file"):
        config.load_json(tmp_path)


def test_load_json_size_bound(tmp_path):
    p = tmp_path / "big.json"
    p.write_text('{"a":"' + "x" * 5000 + '"}')
    with pytest.raises(ConfigError, match="limit"):
        config.load_json(p, max_bytes=1000)
    assert config.load_json(p, max_bytes=10_000)["a"].startswith("x")


def test_load_json_refuses_fifo_without_blocking(tmp_path):
    f = tmp_path / "fifo.json"
    os.mkfifo(f)
    with pytest.raises(ConfigError):
        config.load_json(f)


def test_load_config_refuses_invalid_and_says_why(tmp_path):
    schema = {"type": "object", "required": ["site"], "properties": {"site": {"type": "string", "pattern": "^[a-z]+$"}}}
    p = tmp_path / "c.json"
    p.write_text('{"site": "Hall B"}')
    with pytest.raises(ConfigError) as ei:
        config.load_config(p, schema)
    assert "invalid config" in str(ei.value) and "/site" in str(ei.value)
    p.write_text("{}")
    with pytest.raises(ConfigError, match="missing required"):
        config.load_config(p, schema)
    p.write_text('{"site": "ok"}')
    assert config.load_config(p, schema) == {"site": "ok"}


def test_load_config_or_exit_exits_78_and_reports(tmp_path, capsys):
    p = tmp_path / "c.json"
    p.write_text("[]")
    with pytest.raises(SystemExit) as ei:
        config.load_config_or_exit(p, {"type": "object"}, component="exp-probe")
    assert ei.value.code == 78
    err = capsys.readouterr().err
    assert "exp-probe: refusing to start" in err and "expected type object" in err
    capsys.readouterr()
    with pytest.raises(SystemExit):
        config.load_config_or_exit(tmp_path / "missing.json", {"type": "object"})
    assert "not found" in capsys.readouterr().err


def test_issue_cap_and_deep_document():
    errs = iter_errors(list(range(1000)), {"items": {"type": "string"}})
    assert len(errs) == config.MAX_ISSUES
    deep = cur = []
    for _ in range(5000):
        nxt = []
        cur.append(nxt)
        cur = nxt
    s = {"$defs": {"r": {"type": "array", "items": {"$ref": "#/$defs/r"}}}, "$ref": "#/$defs/r"}
    assert iter_errors(deep, s)          # reported as an error, not a crash
