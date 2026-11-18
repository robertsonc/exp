"""Property/fuzz tests of the ingest parser (SR-3, SR-4): whatever bytes arrive, the pipeline either
refuses the whole request with a contract error or returns consistent per-line results, never crashes,
and only records that satisfy the schema AND the identity binding reach SQLite."""
from __future__ import annotations

import gzip
import json

import pytest
from colhelpers import Env, FakeVM, iso, rec
from exp_common import schema
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from exp_collector.ingest import IngestError, gunzip_bounded

json_leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True, allow_infinity=True),
                      st.text(max_size=40))
json_any = st.recursive(json_leaf, lambda c: st.one_of(st.lists(c, max_size=4),
                                                       st.dictionaries(st.text(max_size=12), c, max_size=4)), max_leaves=12)

SET = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])


@pytest.fixture(scope="module")
def fuzz_app(tmp_path_factory):
    vm = FakeVM()
    env = Env(tmp_path_factory.mktemp("fuzz"), vm.url)
    app = env.start()
    yield app, env
    env.stop_all()
    vm.stop()


def check_consistent(app, body: bytes, res: dict) -> None:
    lines = body.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    assert res["accepted"] + res["duplicates"] + len(res["rejected"]) == len(lines)
    nums = [r["line"] for r in res["rejected"]]
    assert len(nums) == len(set(nums)) and all(1 <= n <= len(lines) for n in nums)
    for r in res["rejected"]:
        assert r["error"]["code"] in {"invalid_json", "line_too_long", "invalid_measurement", "identity_mismatch",
                                      "ts_future", "ts_too_old"}


def stored_ok(app) -> None:
    """Every stored record re-validates and is bound to a configured probe/site."""
    rows = app.store.read_records("probe-a1", 0, 2**62, limit=10_000)
    for _, _, body in rows:
        m = schema.Measurement.from_dict(json.loads(body), require_id=True)
        assert m.probe == "probe-a1" and m.site == "hall-b"
    assert app.store.read_records("probe-a2", 0, 2**62) == []


@SET
@given(st.binary(max_size=3000))
def test_random_bytes_never_crash(fuzz_app, blob):
    app, _ = fuzz_app
    try:
        res = app.ingestor.process("probe-a1", blob)
    except IngestError as e:
        assert e.status in (400, 413) and e.code
        return
    check_consistent(app, blob, res)


@SET
@given(st.lists(json_any, min_size=1, max_size=8))
def test_random_json_lines(fuzz_app, docs):
    app, _ = fuzz_app
    body = b"\n".join(json.dumps(d, allow_nan=True).encode() for d in docs) + b"\n"
    res = app.ingestor.process("probe-a1", body)
    check_consistent(app, body, res)
    assert res["accepted"] == 0                          # arbitrary JSON is never a valid measurement


FIELDS = ["schema", "id", "ts", "probe", "site", "test", "target", "outcome", "duration_ms", "metrics", "labels",
          "detail", "error", "agent_ver"]


@SET
@given(st.sampled_from(FIELDS), json_any, st.booleans())
def test_mutated_valid_record(fuzz_app, field, value, delete):
    app, _ = fuzz_app
    r = rec(detail={"a": 1})
    if delete:
        r.pop(field, None)
    else:
        r[field] = value
    body = json.dumps(r, allow_nan=True).encode() + b"\n"
    res = app.ingestor.process("probe-a1", body)
    check_consistent(app, body, res)
    stored_ok(app)


@SET
@given(st.dictionaries(st.text(alphabet="abcdefghijklmnopqrstuvwxyz_ABC0123", min_size=1, max_size=70), json_any, max_size=12),
       st.dictionaries(st.text(min_size=1, max_size=70), st.one_of(st.text(max_size=140), json_any), max_size=25))
def test_hostile_metrics_and_labels(fuzz_app, metrics, labels):
    app, _ = fuzz_app
    r = rec()
    r["metrics"], r["labels"] = metrics, labels
    body = json.dumps(r, allow_nan=True).encode() + b"\n"
    res = app.ingestor.process("probe-a1", body)
    check_consistent(app, body, res)
    if res["accepted"]:                                    # accepted => no reserved label ever reached the record
        saved = json.loads(app.store.read_records("probe-a1", 0, 2**62, limit=10_000)[-1][2])
        assert not (set(saved.get("labels", {})) & schema.RESERVED_LABELS)
    stored_ok(app)


@SET
@given(st.sampled_from(["probe-a2", "probe-c1", "PROBE", "", "probe-a1 ", "probe-a1\n", "x" * 100]),
       st.sampled_from(["hall-b", "hall-c", "", "HALL", "hall-b\n", "x" * 100]))
def test_identity_binding_cannot_be_spoofed(fuzz_app, probe, site):
    app, _ = fuzz_app
    r = rec()
    r["probe"], r["site"] = probe, site
    body = json.dumps(r).encode() + b"\n"
    res = app.ingestor.process("probe-a1", body)
    assert res["accepted"] == 0 and res["rejected"]
    stored_ok(app)


@SET
@given(st.binary(max_size=2000), st.integers(min_value=1, max_value=4000))
def test_gunzip_bounded_is_always_bounded(blob, limit):
    try:
        out = gunzip_bounded(blob, limit)
    except IngestError as e:
        assert e.status in (400, 413)
    else:
        assert len(out) <= limit


@SET
@given(st.binary(max_size=3000), st.integers(min_value=1, max_value=500))
def test_gunzip_roundtrip_respects_limit(data, limit):
    comp = gzip.compress(data)
    if len(data) <= limit:
        assert gunzip_bounded(comp, limit) == data
    else:
        with pytest.raises(IngestError) as e:
            gunzip_bounded(comp, limit)
        assert e.value.status == 413


@SET
@given(st.text(max_size=70_000))
def test_big_strings_in_fields_never_exceed_stored_bounds(fuzz_app, text):
    app, _ = fuzz_app
    r = rec(target="t")
    r["error"] = text
    r["target"] = text[:300]
    body = json.dumps(r).encode() + b"\n"
    try:
        res = app.ingestor.process("probe-a1", body)
    except IngestError:
        return
    if res["accepted"]:
        saved = json.loads(app.store.read_records("probe-a1", 0, 2**62, limit=10_000)[-1][2])
        assert len(saved.get("error") or "") <= 512 and len(saved.get("target") or "") <= 256
    assert iso(1)  # keep helper import used
