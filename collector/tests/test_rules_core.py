"""Rules engine core: beats, state_of, since_of, last_outage, flaps, determinism, ring buffer == time travel."""
from __future__ import annotations

import random

import synth

from exp_collector import rules
from exp_collector.rules import (
    BeatStore,
    Rec,
    beats,
    evaluate,
    evaluate_records,
    flaps,
    last_outage,
    since_of,
    state_of,
)

T0 = 1_800_000_000_000


def recs(dicts):
    return [Rec.from_dict(d) for d in dicts]


# ---------------------------------------------------------------------------------------------- beats
def test_error_outcome_is_beat_3_never_a_failure():
    r = [synth.trace(T0 + i * 10_000, error=True) for i in range(6)]
    bs = beats(r, "internet")
    assert [b.v for b in bs] == [3] * 6
    st = state_of(bs, "internet", T0 + 60_000)
    assert st.s == "unknown" and st.n == 0               # nothing counts: not fail, not ok


def test_error_records_do_not_dilute_or_fail_a_cluster():
    g = synth.gateway(T0, ports=4)
    g[0]["outcome"] = "error"
    g[0]["error"] = "could not run"
    assert beats(g, "network")[0].v == 0                  # 3 ok + 1 error: ok
    for d in g[1:]:
        d["outcome"], d["error"] = "fail", "x"
    assert beats(g, "network")[0].v == 2                  # all valid ones failing


def test_multi_port_aggregation_rules():
    def v(bad, ports=12, degraded=0):
        return beats(synth.gateway(T0, ports=ports, bad=bad, degraded=degraded), "network")[0].v
    assert v(0) == 0
    assert v(1) == 1 and v(5) == 1                        # some failing: warn
    assert v(6) == 2 and v(11) == 2 and v(12) == 2        # >= half failing: fail
    assert v(0, degraded=2) == 1                          # degraded only: warn


def test_one_record_per_port_become_one_beat_and_beats_ten_seconds_apart_stay_apart():
    r = synth.gateway(T0, ports=12) + synth.gateway(T0 + 10_000, ports=12, bad=12)
    bs = beats(r, "network")
    assert [b.t for b in bs] == [T0, T0 + 10_000] and [b.v for b in bs] == [0, 2]
    assert len(bs[0].group.recs) == 12


def test_apps_collapse_per_port_run_into_one_beat():
    run1 = [synth.app(T0 + i * 500, name=f"a{i}", ok=i % 3 != 0) for i in range(6)]       # 2 of 6 fail
    run2 = [synth.app(T0 + i * 500 + 100_000, name=f"a{i}", port="c02") for i in range(3)]
    bs = beats(run1 + run2, "apps")
    assert len(bs) == 2 and [b.v for b in bs] == [1, 0]   # fewer than half failed: warn; the other port's run is ok
    assert len(bs[0].group.recs) == 6
    for d in run1[:4]:
        d["outcome"], d["error"] = "fail", "x"            # 5 of 6 now
    assert beats(run1, "apps")[0].v == 2


def test_unordered_input_gives_same_beats():
    r = synth.healthy(T0, T0 + 120_000)
    a = [(b.t, b.v) for b in beats(r, "network")]
    random.Random(1).shuffle(r)  # noqa: S311 - deterministic test shuffle
    assert [(b.t, b.v) for b in beats(r, "network")] == a


# -------------------------------------------------------------------------------------------- states
def _series(line, values, step=10_000, t0=T0):
    out = []
    for i, v in enumerate(values):
        t = t0 + i * step
        if line == "network":
            out += synth.gateway(t, ports=4, bad=4 if v == 2 else 1 if v == 1 else 0)
        elif line == "dhcp":
            out.append(synth.dhcp_hb(t, ok=v == 0))
    return out


def test_state_of_fail_when_half_fail_warn_on_any_failure():
    r = _series("network", [0, 0, 2])
    bs = beats(r, "network")
    assert state_of(bs, "network", T0 + 20_000).s == "warn"            # 1 of 3 failed
    r = _series("network", [0, 2, 2])
    assert state_of(beats(r, "network"), "network", T0 + 20_000).s == "fail"
    assert state_of(beats(_series("network", [0, 0, 0]), "network"), "network", T0 + 20_000).s == "ok"
    assert state_of(bs, "network", T0 + 20_000 + 31_000).s == "unknown"  # stale: beyond the 30 s window


def test_slow_beats_warn_per_line_rule():
    # network: any slow beat warns; internet: only when a third of the beats were slow
    g = [x for i in range(3) for x in synth.gateway(T0 + i * 10_000, ports=2, degraded=1 if i == 0 else 0)]
    assert state_of(beats(g, "network"), "network", T0 + 20_000).s == "warn"
    t = [synth.trace(T0, reached=True)] * 0
    tr = [synth.trace(T0 + i * 10_000) for i in range(6)]
    tr[0]["outcome"] = "degraded"
    assert state_of(beats(tr, "internet"), "internet", T0 + 50_000).s == "ok"      # 1 of 6 slow: below a third
    tr[1]["outcome"] = "degraded"
    assert state_of(beats(tr, "internet"), "internet", T0 + 50_000).s == "warn"    # 2 of 6
    assert t == []


def test_since_of_needs_three_good_in_a_row_and_flags_open():
    vals = [0, 0, 0, 2, 0, 2, 2, 2]
    bs = beats(_series("network", vals), "network")
    s = since_of(bs, True)
    assert s.t == T0 + 3 * 10_000 and not s.open          # one ok beat between failures does not end it
    bs2 = beats(_series("network", [2, 2, 2]), "network")
    s2 = since_of(bs2, True)
    assert s2.t == T0 and s2.open                         # history ran out: older than we can see
    assert since_of(beats(_series("network", [0, 0, 0]), "network"), True).t is None


def test_since_of_ignores_a_slow_beat_just_before_a_failure():
    bs = beats(_series("network", [0, 0, 0, 1, 2, 2]), "network")
    assert since_of(bs, True).t == T0 + 4 * 10_000       # failure start, not the slow one
    assert since_of(bs, False).t == T0 + 3 * 10_000      # warn: any non-ok counts


def test_last_outage_and_flaps():
    vals = [0] * 5 + [2] * 6 + [0] * 8
    bs = beats(_series("network", vals), "network")
    now = T0 + (len(vals) - 1) * 10_000
    lo = last_outage(bs, "network", now, 900_000)
    assert lo is not None and not lo.open
    assert lo.start == T0 + 5 * 10_000                    # first failing beat
    assert lo.end > T0 + 10 * 10_000 and lo.end <= now
    # still failing: no "last outage"
    assert last_outage(bs, "network", T0 + 8 * 10_000, 900_000) is None
    # never failed
    assert last_outage(beats(_series("network", [0] * 10), "network"), "network", T0 + 90_000) is None
    # three separate failures in 10 minutes
    vals = ([0] * 4 + [2] * 3) * 3 + [0] * 4
    bs = beats(_series("network", vals), "network")
    assert flaps(bs, "network", T0 + (len(vals) - 1) * 10_000, 600_000) == 3


def test_time_window_arguments_are_inclusive_like_exm():
    bs = beats(_series("network", [2]), "network")
    assert state_of(bs, "network", T0 + 30_000).s == "fail"        # exactly the window
    assert state_of(bs, "network", T0 + 30_001).s == "unknown"


# --------------------------------------------------------------------------------------- determinism
def test_time_travel_is_pure_same_records_same_state():
    r = synth.healthy(T0, T0 + 300_000)
    r += synth.gateway(T0 + 300_000, bad=4)
    at = T0 + 305_000
    a = evaluate_records(r, at, probe="p", site="s")
    random.Random(7).shuffle(r)  # noqa: S311 - deterministic test shuffle
    b = evaluate_records(r + r[:50], at, probe="p", site="s")             # shuffled, with duplicates
    assert a.states == b.states and a.where == b.where and a.newest == b.newest
    assert {k: (v.since, v.flaps, v.last_outage) for k, v in a.lines.items()} == \
           {k: (v.since, v.flaps, v.last_outage) for k, v in b.lines.items()}
    # records after `at` never matter
    c = evaluate_records(r + synth.gateway(at + 1000, bad=4), at, probe="p", site="s")
    assert c.states == a.states


def test_incremental_ring_buffer_equals_pure_evaluation_with_out_of_order_arrival():
    r = synth.healthy(T0, T0 + 200_000)
    r += synth.gateway(T0 + 200_000, bad=4) + synth.gateway(T0 + 210_000, bad=4)
    r += [synth.wifi(T0 + 205_000, gw=False)]
    live = BeatStore()
    order = list(r)
    random.Random(3).shuffle(order)  # noqa: S311 - backfill arrives in any order
    for d in order:
        live.add(Rec.from_dict(d))
    at = T0 + 215_000
    a = evaluate(live, at, probe="p")
    b = evaluate_records(r, at, probe="p")
    assert a.states == b.states and a.where == b.where
    assert [(x.t, x.v) for x in a.lines["network"].beats] == [(x.t, x.v) for x in b.lines["network"].beats]


def test_trim_forgets_old_records():
    live = BeatStore()
    for d in synth.healthy(T0, T0 + 600_000):
        live.add(Rec.from_dict(d))
    live.trim(T0 + 400_000)
    bs, _ = live.line("network")
    assert bs and bs[0].t >= T0 + 400_000
    assert live.newest_ts() is not None


def test_duplicate_ids_are_ignored():
    live = BeatStore()
    d = synth.gateway(T0)[0]
    assert live.add(Rec.from_dict(d)) and not live.add(Rec.from_dict(d))


def test_unknown_when_probe_never_spoke_and_no_crash_on_garbage_records():
    ev = evaluate(BeatStore(), T0, probe="p")
    assert set(ev.states.values()) == {"unknown"} and ev.newest is None and ev.where is None
    assert Rec.from_dict({"ts": "nope"}) is None and Rec.from_dict([]) is None
    assert Rec.from_dict({"ts": "2026-01-01T00:00:00Z", "test": "x", "outcome": "weird"}) is None
    bad = {"ts": "2026-01-01T00:00:00Z", "test": "gateway", "outcome": "fail", "labels": "x", "metrics": {"a": "NaN"}}
    assert Rec.from_dict(bad) is not None                # tolerated: wrong types are dropped, not crashed on


def test_line_specs_follow_the_spec_table():
    assert rules.RECENT_MS == 60_000 and rules.TRACE_HOLD_MS == 30_000 and rules.FLAP_SPAN_MS == 600_000
    assert rules.LAST_OUTAGE_MS == 900_000
    assert rules.LINE_SPECS["network"].window_ms == 30_000 and rules.LINE_SPECS["internet"].window_ms == 120_000
    assert set(rules.LINE_SPECS) == set(rules.LINE_KEYS)


def test_a_port_testing_back_to_back_never_builds_one_endless_beat():
    r = [synth.app(T0 + i * 10_000, ok=not 10 <= i < 20) for i in range(40)]     # every 10 s on one port: 400 s
    bs = beats(r, "apps")
    assert len(bs) >= 6 and all(b.group.t - b.group.t0 < rules.CHAIN_SPAN_MS for b in bs)
    assert [b.v for b in bs][-1] == 0 and bs[-1].t >= T0 + 390_000          # the recovery is seen
