"""Hostile and malformed records never crash the rules, and whatever they say, the State stays schema-valid
(input validation on everything a remote party sends)."""
from __future__ import annotations

import datetime

from colhelpers import check_schema_file
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from exp_collector.engine import state_doc
from exp_collector.rules import Rec, evaluate_records

T = 1_800_000_000_000


def iso(ms: int) -> str:
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


scalars = st.none() | st.booleans() | st.integers(-10**12, 10**12) | st.floats(allow_nan=True, allow_infinity=True) | st.text(max_size=60)
jsonish = st.recursive(scalars, lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=10), c, max_size=4),
                       max_leaves=12)
TESTS = ["gateway", "dhcp_hb", "dns_hb", "trace", "ping", "app", "wifi_hb", "path", "probe_self", "throughput", "x"]
KEYS = ["port", "iface", "path", "resolver", "resolver_kind", "server", "ssid", "app"]
MKEYS = ["link_up", "reached", "last_ttl", "hops", "gw_rtt_ms", "rtt_ms", "loss_pct"]
DKEYS = ["gateway_ip", "last_ip", "target", "dest_ttl", "target_ssid", "on_target"]
labels = st.dictionaries(st.sampled_from(KEYS), st.text(max_size=40) | st.sampled_from(["c01", "test", "control", "alternate", "dhcp"]),
                         max_size=6)
metrics = st.dictionaries(st.sampled_from(MKEYS), scalars, max_size=6)
detail = st.dictionaries(st.sampled_from(DKEYS), jsonish | st.sampled_from(["10.1.0.1", "8.8.8.8", "::1", "<x>"]), max_size=6)
record = st.fixed_dictionaries({
    "ts": st.integers(T - 400_000, T + 50_000).map(iso),
    "id": st.text(min_size=1, max_size=30),
    "test": st.sampled_from(TESTS),
    "outcome": st.sampled_from(["ok", "degraded", "fail", "error", "ok", "fail"]),
    "labels": labels, "metrics": metrics, "detail": detail,
    "error": st.none() | st.text(max_size=300), "target": st.none() | st.text(max_size=100),
    "probe": st.just("probe-a1"), "site": st.just("hall-b")})


@given(st.lists(record, max_size=80), st.integers(T - 100_000, T + 20_000), st.sampled_from(["plain", "sysadmin"]))
@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
def test_garbage_records_never_crash_and_the_state_stays_schema_valid(recs, at, voice):
    ev = evaluate_records(recs, at, probe="probe-a1", site="hall-b")
    doc = state_doc(ev, voice=voice, tz="America/Chicago", edge_label="EC")
    check_schema_file("state.schema.json", doc)
    for line in doc["failing"]:
        assert all(0 < len(i["text"]) <= 512 for i in line["items"])


@given(st.lists(st.one_of(st.none(), st.text(), st.integers(), st.lists(st.integers(), max_size=3),
                          st.dictionaries(st.text(max_size=6), jsonish, max_size=5)), max_size=20))
@settings(max_examples=100, deadline=None)
def test_rec_from_dict_accepts_anything_and_returns_none_or_a_record(items):
    for it in items:
        r = Rec.from_dict(it)
        assert r is None or isinstance(r, Rec)


def test_non_finite_and_wrong_typed_metrics_are_dropped():
    r = Rec.from_dict({"ts": iso(T), "test": "gateway", "outcome": "ok",
                       "metrics": {"a": float("nan"), "b": float("inf"), "c": "7", "d": True, "e": 1.5}})
    assert r is not None and r.metrics == {"e": 1.5}
