"""Config loading and a stdlib JSON Schema validator (draft 2020-12, restricted keyword subset).

Contract: components MUST refuse to start on an invalid config and say why (`load_config`,
`load_config_or_exit`).

Supported schema keywords (anything else in a schema raises `SchemaError` -- never silently
ignored, so a schema author cannot believe a constraint is enforced when it is not):
  $schema $id $ref $defs title description type properties required additionalProperties
  patternProperties propertyNames items prefixItems minItems maxItems uniqueItems enum const
  pattern minLength maxLength minimum maximum exclusiveMinimum exclusiveMaximum minProperties
  maxProperties anyOf oneOf allOf not default examples
`$ref` is local ("#/$defs/x", any JSON pointer) or cross-file relative to the schemas dir
("common.schema.json#/$defs/ts"); cross-file names are plain file names (no path separators).

API:
  schemas_dir()                  -> Path   (see exp_common.schemas_dir)
  load_json(path, max_bytes)     -> parsed JSON; ConfigError with a clear reason
  iter_errors(doc, schema)       -> list[Issue]   (all problems, [] = valid)
  validate(doc, schema)          -> None; raises ConfigError (a ValueError) listing every Issue
  load_config(path, schema)      -> dict; raises ConfigError on unreadable/invalid
  load_config_or_exit(...)       -> like load_config, but prints reasons to stderr and exits 78
`schema` may be a dict, a schema file name ("probe.config.schema.json"), a short name
("probe.config"), or a document `schema` const ("exp.probe.config/1").
"""
from __future__ import annotations

import json
import logging
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, NoReturn, Optional, Union

log = logging.getLogger(__name__)

DEFAULT_MAX_BYTES = 1024 * 1024
MAX_ISSUES = 100
MAX_REF_DEPTH = 64
EX_CONFIG = 78

KEYWORDS = frozenset("""$schema $id $ref $defs title description type properties required
additionalProperties patternProperties propertyNames items prefixItems minItems maxItems uniqueItems
enum const pattern minLength maxLength minimum maximum exclusiveMinimum exclusiveMaximum
minProperties maxProperties anyOf oneOf allOf not default examples""".split())

_TYPES = frozenset({"null", "boolean", "object", "array", "number", "integer", "string"})
_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json\Z")
_SHORT_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,100}\Z")
_SCHEMA_CONST_RE = re.compile(r"exp\.([a-z0-9.]+)/[0-9]+\Z")


class ConfigError(ValueError):
    """Config unreadable or invalid. `.errors` holds the list of `Issue`s (may be empty)."""

    def __init__(self, message: str, errors: Optional[list["Issue"]] = None) -> None:
        self.errors = list(errors or [])
        self.summary = message
        detail = "".join(f"\n  - {i}" for i in self.errors)
        super().__init__(message + detail)


class SchemaError(Exception):
    """The *schema* is unusable (unknown keyword, malformed keyword value, bad $ref...)."""


class Issue:
    """One validation problem: JSON-pointer path of the offending value + human message."""

    __slots__ = ("path", "message")

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message

    def __str__(self) -> str:
        return f"{self.path or '/'}: {self.message}"

    def __repr__(self) -> str:
        return f"Issue({self.path!r}, {self.message!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Issue) and (self.path, self.message) == (other.path, other.message)

    def __hash__(self) -> int:
        return hash((self.path, self.message))


# ----------------------------------------------------------------------------- schema locations

def schemas_dir() -> Path:
    """Schema directory: $EXP_SCHEMAS_DIR, else packaged exp_common/schemas, else shared/schemas."""
    from . import schemas_dir as _sd
    return _sd()


def _esc(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _jp(path: str, token: Any) -> str:
    return f"{path}/{_esc(str(token))}"


_cache: dict[tuple[str, int, int], Any] = {}


def _load_schema_file(path: Path) -> Any:
    try:
        st = path.stat()
    except OSError as exc:
        raise SchemaError(f"schema file not found: {path}") from exc
    key = (str(path), st.st_mtime_ns, st.st_size)
    hit = _cache.get(key)
    if hit is not None:
        return hit
    try:
        doc = load_json(path, max_bytes=4 * DEFAULT_MAX_BYTES)
    except ConfigError as exc:
        raise SchemaError(f"cannot load schema {path}: {exc.summary}") from exc
    check_schema(doc, where=str(path))
    if len(_cache) > 64:
        _cache.clear()
    _cache[key] = doc
    return doc


def resolve_schema_file(schema: Union[str, Path]) -> Path:
    """Map a schema name / file name / document schema const to a path under schemas_dir()."""
    if isinstance(schema, Path):
        return schema
    m = _SCHEMA_CONST_RE.match(schema)
    if m:
        schema = m.group(1) + ".schema.json"
    elif _FILE_RE.match(schema):
        pass
    elif _SHORT_RE.match(schema):
        schema = schema + ".schema.json"
    elif os.sep in schema or "/" in schema:
        return Path(schema)       # explicit path chosen by the caller (never from a document)
    else:
        raise SchemaError(f"invalid schema name {schema!r}")
    return schemas_dir() / schema


# ------------------------------------------------------------------------------- schema checking

def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def check_schema(schema: Any, where: str = "schema") -> None:
    """Eagerly verify a schema uses only the supported subset with well-formed keyword values.
    Raises SchemaError. Walks every subschema position (not data such as enum/const/default)."""

    def sub(s: Any, at: str) -> None:
        if isinstance(s, bool):
            return
        if not isinstance(s, dict):
            raise SchemaError(f"{where}{at}: a schema must be an object or boolean")
        for kw, val in s.items():
            here = f"{at}/{_esc(kw)}"
            if kw not in KEYWORDS:
                raise SchemaError(f"{where}{here}: unsupported schema keyword {kw!r}")
            if kw in ("$schema", "$id", "title", "description"):
                if not isinstance(val, str):
                    raise SchemaError(f"{where}{here}: must be a string")
            elif kw == "$ref":
                if not isinstance(val, str):
                    raise SchemaError(f"{where}{here}: must be a string")
                _split_ref(val)
            elif kw == "type":
                ts = val if isinstance(val, list) else [val]
                if not ts or any(t not in _TYPES for t in ts if isinstance(t, str)) \
                        or not all(isinstance(t, str) for t in ts):
                    raise SchemaError(f"{where}{here}: invalid type {val!r}")
            elif kw in ("$defs", "properties", "patternProperties"):
                if not isinstance(val, dict):
                    raise SchemaError(f"{where}{here}: must be an object")
                for k, v in val.items():
                    if kw == "patternProperties":
                        _compile(k, f"{where}{here}")
                    sub(v, f"{here}/{_esc(k)}")
            elif kw in ("additionalProperties", "propertyNames", "items", "not"):
                sub(val, here)
            elif kw in ("prefixItems", "anyOf", "oneOf", "allOf"):
                if not isinstance(val, list) or not val:
                    raise SchemaError(f"{where}{here}: must be a non-empty array")
                for i, v in enumerate(val):
                    sub(v, f"{here}/{i}")
            elif kw == "required":
                if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                    raise SchemaError(f"{where}{here}: must be an array of strings")
            elif kw in ("minItems", "maxItems", "minLength", "maxLength", "minProperties",
                        "maxProperties"):
                if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                    raise SchemaError(f"{where}{here}: must be a non-negative integer")
            elif kw in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
                if not _is_num(val):
                    raise SchemaError(f"{where}{here}: must be a number")
            elif kw == "uniqueItems":
                if not isinstance(val, bool):
                    raise SchemaError(f"{where}{here}: must be a boolean")
            elif kw == "pattern":
                if not isinstance(val, str):
                    raise SchemaError(f"{where}{here}: must be a string")
                _compile(val, f"{where}{here}")
            elif kw == "enum":
                if not isinstance(val, list) or not val:
                    raise SchemaError(f"{where}{here}: must be a non-empty array")
            # const / default / examples: any JSON

    sub(schema, "")


_re_cache: dict[str, "re.Pattern[str]"] = {}


def _compile(pattern: str, where: str) -> "re.Pattern[str]":
    rx = _re_cache.get(pattern)
    if rx is None:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise SchemaError(f"{where}: invalid regular expression {pattern!r}: {exc}") from exc
        if len(_re_cache) > 512:
            _re_cache.clear()
        _re_cache[pattern] = rx
    return rx


def _split_ref(ref: str) -> tuple[str, str]:
    """-> (file or "", pointer-with-leading-slash or "")."""
    file_part, _, frag = ref.partition("#")
    if file_part and not _FILE_RE.match(file_part):
        raise SchemaError(f"$ref {ref!r}: file part must be a plain schema file name")
    if frag and not frag.startswith("/"):
        raise SchemaError(f"$ref {ref!r}: fragment must be a JSON pointer starting with '/'")
    if not file_part and not frag:
        raise SchemaError(f"$ref {ref!r} is empty")
    return file_part, frag


def _pointer(doc: Any, pointer: str, ref: str) -> Any:
    cur = doc
    if pointer == "":
        return cur
    for raw in pointer[1:].split("/"):
        tok = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and tok in cur:
            cur = cur[tok]
        elif isinstance(cur, list) and tok.isdigit() and int(tok) < len(cur):
            cur = cur[int(tok)]
        else:
            raise SchemaError(f"$ref {ref!r} does not resolve (missing {tok!r})")
    return cur


# --------------------------------------------------------------------------------- JSON semantics

def _type_ok(v: Any, t: str) -> bool:
    if t == "null":
        return v is None
    if t == "boolean":
        return isinstance(v, bool)
    if t == "string":
        return isinstance(v, str)
    if t == "array":
        return isinstance(v, list)
    if t == "object":
        return isinstance(v, dict)
    if t == "number":
        return _is_num(v)
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool) or (isinstance(v, float) and v.is_integer())
    return False


def json_equal(a: Any, b: Any) -> bool:
    """JSON equality: booleans are not numbers, 1 == 1.0, deep for arrays/objects."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_num(a) and _is_num(b):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if type(a) is not type(b):
        return False
    return a == b


def _canon(v: Any) -> str:
    def norm(x: Any) -> Any:
        if isinstance(x, bool) or x is None or isinstance(x, str):
            return x
        if _is_num(x):
            return int(x) if isinstance(x, float) and x.is_integer() else x
        if isinstance(x, list):
            return [norm(i) for i in x]
        return {k: norm(i) for k, i in x.items()}
    return json.dumps(norm(v), sort_keys=True, separators=(",", ":"), allow_nan=True)


# -------------------------------------------------------------------------------------- validator

class _Ctx:
    def __init__(self, base_dir: Optional[Path]) -> None:
        self.base_dir = base_dir
        self.active: set[tuple[str, str, int]] = set()
        self.docs: dict[str, Any] = {}

    def load(self, name: str) -> Any:
        if name not in self.docs:
            d = self.base_dir if self.base_dir is not None else schemas_dir()
            self.docs[name] = _load_schema_file(d / name)
        return self.docs[name]


def _check(inst: Any, schema: Any, path: str, root: Any, root_name: str, ctx: _Ctx,
           depth: int = 0) -> list[Issue]:
    if schema is True:
        return []
    if schema is False:
        return [Issue(path, "no value is allowed here")]
    if depth > MAX_REF_DEPTH * 4:
        raise SchemaError("schema nesting too deep")
    out: list[Issue] = []

    def rec(i: Any, s: Any, p: str, r: Any = None, rn: Optional[str] = None) -> list[Issue]:
        return _check(i, s, p, root if r is None else r, root_name if rn is None else rn, ctx, depth + 1)

    ref = schema.get("$ref")
    if ref is not None:
        fname, frag = _split_ref(ref)
        if fname:
            r_doc, r_name = ctx.load(fname), fname
        else:
            r_doc, r_name = root, root_name
        key = (r_name, frag, id(inst))
        if key in ctx.active:
            raise SchemaError(f"$ref cycle at {ref!r} without consuming the instance")
        target = _pointer(r_doc, frag, ref)
        ctx.active.add(key)
        try:
            out += rec(inst, target, path, r_doc, r_name)
        finally:
            ctx.active.discard(key)

    t = schema.get("type")
    if t is not None:
        ts = t if isinstance(t, list) else [t]
        if not any(_type_ok(inst, x) for x in ts):
            return out + [Issue(path, f"expected type {' or '.join(ts)}, got {_tname(inst)}")]

    if "const" in schema and not json_equal(inst, schema["const"]):
        out.append(Issue(path, f"must equal {json.dumps(schema['const'])}"))
    if "enum" in schema and not any(json_equal(inst, e) for e in schema["enum"]):
        out.append(Issue(path, "must be one of " + ", ".join(json.dumps(e) for e in schema["enum"][:20])))

    if isinstance(inst, str):
        if "minLength" in schema and len(inst) < schema["minLength"]:
            out.append(Issue(path, f"string shorter than {schema['minLength']} characters"))
        if "maxLength" in schema and len(inst) > schema["maxLength"]:
            out.append(Issue(path, f"string longer than {schema['maxLength']} characters"))
        if "pattern" in schema and not _compile(schema["pattern"], "pattern").search(inst):
            out.append(Issue(path, f"does not match pattern {schema['pattern']}"))

    if _is_num(inst):
        if "minimum" in schema and inst < schema["minimum"]:
            out.append(Issue(path, f"must be >= {schema['minimum']}"))
        if "maximum" in schema and inst > schema["maximum"]:
            out.append(Issue(path, f"must be <= {schema['maximum']}"))
        if "exclusiveMinimum" in schema and inst <= schema["exclusiveMinimum"]:
            out.append(Issue(path, f"must be > {schema['exclusiveMinimum']}"))
        if "exclusiveMaximum" in schema and inst >= schema["exclusiveMaximum"]:
            out.append(Issue(path, f"must be < {schema['exclusiveMaximum']}"))

    if isinstance(inst, list):
        if "minItems" in schema and len(inst) < schema["minItems"]:
            out.append(Issue(path, f"array has fewer than {schema['minItems']} items"))
        if "maxItems" in schema and len(inst) > schema["maxItems"]:
            out.append(Issue(path, f"array has more than {schema['maxItems']} items"))
        if schema.get("uniqueItems") is True:
            seen: set[str] = set()
            for i, item in enumerate(inst):
                c = _canon(item)
                if c in seen:
                    out.append(Issue(_jp(path, i), "duplicate item (items must be unique)"))
                    break
                seen.add(c)
        prefix = schema.get("prefixItems", [])
        for i, sub in enumerate(prefix):
            if i < len(inst):
                out += rec(inst[i], sub, _jp(path, i))
        if "items" in schema:
            for i in range(len(prefix), len(inst)):
                out += rec(inst[i], schema["items"], _jp(path, i))

    if isinstance(inst, dict):
        if "minProperties" in schema and len(inst) < schema["minProperties"]:
            out.append(Issue(path, f"object has fewer than {schema['minProperties']} properties"))
        if "maxProperties" in schema and len(inst) > schema["maxProperties"]:
            out.append(Issue(path, f"object has more than {schema['maxProperties']} properties"))
        for name in schema.get("required", []):
            if name not in inst:
                out.append(Issue(path, f"missing required property {name!r}"))
        props = schema.get("properties", {})
        pats = schema.get("patternProperties", {})
        for k, v in inst.items():
            matched = False
            if k in props:
                matched = True
                out += rec(v, props[k], _jp(path, k))
            for pat, sub in pats.items():
                if _compile(pat, "patternProperties").search(k):
                    matched = True
                    out += rec(v, sub, _jp(path, k))
            if not matched and "additionalProperties" in schema:
                ap = schema["additionalProperties"]
                if ap is False:
                    out.append(Issue(_jp(path, k), "additional property not allowed"))
                else:
                    out += rec(v, ap, _jp(path, k))
        if "propertyNames" in schema:
            for k in inst:
                for iss in rec(k, schema["propertyNames"], _jp(path, k)):
                    out.append(Issue(iss.path, "property name " + repr(k) + ": " + iss.message))

    for sub in schema.get("allOf", []):
        out += rec(inst, sub, path)
    if "anyOf" in schema:
        branches = [rec(inst, s, path) for s in schema["anyOf"]]
        if all(branches):
            best = min(branches, key=len)
            out.append(Issue(path, f"matches none of the {len(branches)} alternatives (closest: "
                             + "; ".join(str(i) for i in best[:3]) + ")"))
    if "oneOf" in schema:
        n = sum(1 for s in schema["oneOf"] if not rec(inst, s, path))
        if n != 1:
            out.append(Issue(path, f"must match exactly one alternative, matched {n}"))
    if "not" in schema and not rec(inst, schema["not"], path):
        out.append(Issue(path, "must not match the 'not' schema"))
    return out


def _tname(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    return {str: "string", list: "array", dict: "object"}.get(type(v), type(v).__name__)


def _prepare(schema: Union[dict, bool, str, Path]) -> tuple[Any, str, _Ctx]:
    if isinstance(schema, (str, Path)):
        path = resolve_schema_file(schema)
        root = _load_schema_file(path)
        return root, path.name, _Ctx(path.parent)
    check_schema(schema, where="schema")
    return schema, "<inline>", _Ctx(None)


def iter_errors(doc: Any, schema: Union[dict, bool, str, Path]) -> list[Issue]:
    """All validation problems (capped at MAX_ISSUES). [] means valid. Raises SchemaError if the
    schema itself is unusable."""
    root, name, ctx = _prepare(schema)
    try:
        issues = _check(doc, root, "", root, name, ctx)
    except RecursionError:
        return [Issue("", "document is nested too deeply")]
    return issues[:MAX_ISSUES]


def is_valid(doc: Any, schema: Union[dict, bool, str, Path]) -> bool:
    return not iter_errors(doc, schema)


def validate(doc: Any, schema: Union[dict, bool, str, Path]) -> None:
    """Raise ConfigError (with `.errors`, JSON-pointer paths) unless `doc` conforms."""
    errs = iter_errors(doc, schema)
    if errs:
        label = schema if isinstance(schema, (str, Path)) else "schema"
        raise ConfigError(f"document does not conform to {label}", errs)


# ------------------------------------------------------------------------------------- file loading

def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _bad_constant(name: str) -> NoReturn:
    raise ValueError(f"non-finite number {name} is not valid JSON")


def parse_json(text: Union[str, bytes], what: str = "document") -> Any:
    """Strict JSON parse: no duplicate keys, no NaN/Infinity. ConfigError on failure."""
    try:
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_bad_constant)
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{what} is not valid UTF-8 ({exc.reason} at byte {exc.start})") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{what} is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})") from exc
    except RecursionError as exc:
        raise ConfigError(f"{what} is nested too deeply") from exc
    except ValueError as exc:
        raise ConfigError(f"{what} is not valid JSON: {exc}") from exc


def load_json(path: Union[str, Path], max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Read and parse a JSON file of at most `max_bytes`. Clear ConfigError on every failure."""
    p = str(path)
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError as exc:
        raise ConfigError(f"{p}: file not found") from exc
    except PermissionError as exc:
        raise ConfigError(f"{p}: permission denied") from exc
    except OSError as exc:
        raise ConfigError(f"{p}: cannot open ({exc.strerror})") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"{p}: not a regular file")
        if st.st_size > max_bytes:
            raise ConfigError(f"{p}: file is {st.st_size} bytes, larger than the {max_bytes}-byte limit")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(max_bytes + 1)
    except OSError as exc:
        raise ConfigError(f"{p}: read failed ({exc.strerror})") from exc
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise ConfigError(f"{p}: file is larger than the {max_bytes}-byte limit")
    return parse_json(data, what=p)


def load_config(path: Union[str, Path], expected_schema: Union[dict, str, Path],
                max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """Load + validate a component config. Raises ConfigError naming the file and every problem;
    callers must not continue on error."""
    doc = load_json(path, max_bytes=max_bytes)
    errs = iter_errors(doc, expected_schema)
    if errs:
        raise ConfigError(f"{path}: invalid config", errs)
    if not isinstance(doc, dict):  # schemas for configs are objects; defensive
        raise ConfigError(f"{path}: config must be a JSON object")
    return doc


def load_config_or_exit(path: Union[str, Path], expected_schema: Union[dict, str, Path],
                        component: str = "exp") -> dict[str, Any]:
    """`load_config`, but on failure log the reasons, print them to stderr, and exit 78
    (EX_CONFIG) so systemd marks the unit failed with a readable cause."""
    try:
        return load_config(path, expected_schema)
    except (ConfigError, SchemaError) as exc:
        log.error("%s refusing to start: %s", component, exc)
        print(f"{component}: refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(EX_CONFIG) from exc


__all__ = [
    "ConfigError", "SchemaError", "Issue", "KEYWORDS", "schemas_dir", "resolve_schema_file",
    "check_schema", "iter_errors", "is_valid", "validate", "load_json", "parse_json",
    "load_config", "load_config_or_exit", "json_equal", "DEFAULT_MAX_BYTES", "EX_CONFIG",
]
