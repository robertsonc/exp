"""WP-0 delta to the measurement reference: `id` (ULID) and bounded `detail`."""
import pytest
from exp_common.ids import is_ulid
from exp_common.schema import DETAIL_MAX_ARRAY, Measurement, measure, validate_detail


def test_measure_generates_ulid_id_and_it_is_required_at_ingest():
    m = measure("p", "dns", "ok")
    assert is_ulid(m.id)
    assert m.validate(require_id=True) is m
    assert m.to_dict()["id"] == m.id


def test_ids_are_unique_and_time_ordered():
    ids = [measure("p", "dns", "ok").id for _ in range(200)]
    assert len(set(ids)) == 200 and ids == sorted(ids)


def test_missing_id_refused_at_ingest_but_not_locally():
    m = Measurement(probe="p", test="dns", outcome="ok")
    m.validate()
    with pytest.raises(ValueError, match="id is required"):
        m.validate(require_id=True)
    with pytest.raises(ValueError, match="id is required"):
        Measurement.from_dict({"probe": "p", "test": "dns", "outcome": "ok"}, require_id=True)


@pytest.mark.parametrize("bad", ["x", "01ARZ3NDEKTSV4RRFFQ69G5FA", "01ARZ3NDEKTSV4RRFFQ69G5FAVX",
                                 "01ARZ3NDEKTSV4RRFFQ69G5FAU", "01arz3ndektsv4rrffq69g5fav", 5])
def test_malformed_id_rejected(bad):
    with pytest.raises(ValueError):
        Measurement(probe="p", test="dns", outcome="ok", id=bad).validate()


def test_explicit_id_kept_and_roundtrip_with_detail():
    m = measure("p", "app", "ok", id="01ARZ3NDEKTSV4RRFFQ69G5FAV", detail={"hops": [1, 2], "a": {"b": "c"}})
    assert m.id == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    again = Measurement.from_dict(m.to_dict(), require_id=True)
    assert again.to_dict() == m.to_dict() and again.detail == {"hops": [1, 2], "a": {"b": "c"}}


def test_detail_never_becomes_a_series_label_or_metric():
    m = measure("p", "app", "ok", metrics={"x": 1}, detail={"url": "https://x/y?z=1"})
    for s in m.series():
        assert "url" not in s["labels"] and "detail" not in s["labels"]


def test_detail_absent_is_omitted_from_dict():
    assert "detail" not in measure("p", "dns", "ok").to_dict()


def test_detail_accepts_boundaries():
    validate_detail({"a": {"b": {"c": {"d": 1}}}})               # 4 nested containers, detail itself = depth 1
    validate_detail({"k": "x" * 1024})
    validate_detail({"k": list(range(DETAIL_MAX_ARRAY))})
    validate_detail({"A_1": None, "b": True, "c": 1.5})
    validate_detail({"k" * 64: 1})


@pytest.mark.parametrize("detail,why", [
    ({"a": {"b": {"c": {"d": {"e": 1}}}}}, "depth 5"),
    ({"a": [[[[1]]]]}, "depth via arrays"),
    ({"k": "x" * 1025}, "string too long"),
    ({"k": "a\nb"}, "control char"),
    ({"k": "a\x00b"}, "NUL"),
    ({"k": list(range(257))}, "array too long"),
    ({"1bad": 1}, "key starts with digit"),
    ({"bad-key": 1}, "key with dash"),
    ({"k" * 65: 1}, "key too long"),
    ({"": 1}, "empty key"),
    ({"a": {"bad key": 1}}, "nested bad key"),
    ({"a": float("nan")}, "nan"),
    ({"a": float("inf")}, "inf"),
    ({"a": object()}, "non-json"),
    ({"a": {1: 2}}, "non-str key"),
    ({f"k{i}": "x" * 200 for i in range(50)}, "serialized > 8KiB"),
    ({f"k{i}": 1 for i in range(100000)}, "huge object fails fast"),
])
def test_detail_rejections(detail, why):
    with pytest.raises(ValueError):
        validate_detail(detail)
    with pytest.raises(ValueError):
        measure("p", "dns", "ok", detail=detail)


def test_detail_must_be_object():
    for bad in ([], "x", 1, [{"a": 1}]):
        with pytest.raises(ValueError):
            validate_detail(bad)


def test_detail_serialized_limit_is_bytes_not_chars():
    # 3-byte chars: 3000 chars = 9000 bytes > 8 KiB while each string stays < 1024 chars
    d = {f"k{i}": "€" * 1000 for i in range(3)}
    with pytest.raises(ValueError, match="bytes"):
        validate_detail(d)


def test_from_dict_ignores_unknown_fields_and_rejects_bad_types():
    m = Measurement.from_dict({"probe": "p", "test": "dns", "outcome": "ok", "future_field": 1})
    assert not hasattr(m, "future_field")
    for bad in ({"probe": 5}, {"labels": []}, {"metrics": "x"}, {"error": 3}, {"ts": 5}):
        d = {"probe": "p", "test": "dns", "outcome": "ok", **bad}
        with pytest.raises(ValueError):
            Measurement.from_dict(d)
