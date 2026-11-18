"""Tests for the measurement schema. Run: python3 shared/python/tests/test_schema_reference.py  (or pytest)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from exp_common.schema import Measurement, measure  # noqa: E402


def test_happy_path_and_series():
    m = measure("probe-a1", "dns", "ok", site="hall-b", target="www.example.com",
                duration_ms=23.4, metrics={"rtt_ms": 23.4, "rcode": 0}, labels={"resolver": "10.1.0.1"})
    names = {s["metric"] for s in m.series()}
    assert names == {"exp_dns_rtt_ms", "exp_dns_rcode", "exp_dns_duration_ms"}, names
    one = m.series()[0]["labels"]
    assert one["probe"] == "probe-a1" and one["site"] == "hall-b" and one["outcome"] == "ok"


def _rejected(**kw):
    try:
        measure("p", "dns", "ok", **kw)
        return False
    except ValueError:
        return True


def test_rejections():
    assert _rejected(labels={"probe": "spoof"})          # reserved
    assert _rejected(labels={"outcome": "ok"})           # reserved
    assert _rejected(labels={"__proto__": "x"})          # dunder
    assert _rejected(ts="not-a-timestamp")               # bad ts fails at validate, not series()
    assert _rejected(labels={"note": "a\nb"})            # control char
    assert _rejected(target="a\x00b")                    # control char in target
    assert _rejected(labels={f"l{i}": "x" for i in range(21)})  # too many labels
    assert _rejected(metrics={f"m{i}": 1.0 for i in range(51)})  # too many metrics
    assert _rejected(labels={"n": 5})                    # non-string label value
    assert _rejected(metrics={"x": float("nan")})        # non-finite metric
    assert _rejected(metrics={"x": float("inf")})        # infinity
    assert _rejected(metrics={"x": 10 ** 400})           # giant int → float overflow (fail-late DoS)
    assert _rejected(metrics={"x" * 65: 1.0})            # over-long metric name
    assert _rejected(labels={"k" * 65: "v"})             # over-long label key
    assert _rejected(ts="2026-11-18T00:00:00")           # naive timestamp (no timezone)
    assert _rejected(duration_ms=10 ** 400)              # giant int duration
    for bad in (("BAD ID", "dns", "ok"), ("p", "dns", "nope"), ("p", "bad test", "ok")):
        try:
            measure(*bad); assert False, bad
        except ValueError:
            pass


def test_trusted_labels_win_without_validate():
    # Even a hand-built record that never called validate() cannot override trusted labels.
    bad = Measurement(probe="real", test="dns", outcome="ok", ts="2026-11-18T00:00:00Z",
                      metrics={"rtt_ms": 1.0}, labels={"probe": "SPOOF", "outcome": "fail"})
    labels = bad.series()[0]["labels"]
    assert labels["probe"] == "real" and labels["outcome"] == "ok", labels


def test_roundtrip():
    m = measure("p", "gateway", "fail", error="no reply", metrics={"loss": 1.0})
    assert Measurement.from_dict(m.to_dict()).to_dict() == m.to_dict()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("PASS", fn.__name__)
    print(f"\n{len(fns)} passed")
