"""Heartbeat cadence (CR-heartbeat-cadence): line states are judged on a window that holds at least WINDOW_BEATS beats
of the probe's measured cadence, so a slow heartbeat never reads "unknown" between beats and a fast one never makes
the board react faster than the spec windows allow. The cadence is measured from the beats, never configured."""
from __future__ import annotations

import synth
from colhelpers import check_schema_file

from exp_collector.engine import state_doc
from exp_collector.rules import LINE_SPECS, WINDOW_CAP_MS, cadence_ms, evaluate_records, window_for

T0 = 1_800_000_000_000


def test_default_and_fast_heartbeats_keep_the_spec_windows():
    for step in (10_000, 5_000):
        recs = synth.healthy(T0, T0 + 20 * step, step=step)
        ev = evaluate_records(recs, T0 + 20 * step)
        net = ev.lines["network"]
        assert net.cadence_ms == step and ev.cadence_ms == step
        assert net.window_ms == LINE_SPECS["network"].window_ms == 30_000      # 2.5 beats < 30 s: unchanged
        assert net.state == "ok"


def test_slow_heartbeat_is_not_unknown_between_beats():
    step = 60_000
    recs = synth.healthy(T0, T0 + 10 * step, step=step)
    last = T0 + 9 * step
    at = last + 45_000                                    # 45 s after the last beat: outside a fixed 30 s window
    ev = evaluate_records(recs, at)
    net = ev.lines["network"]
    assert net.cadence_ms == step and net.window_ms == 150_000
    assert net.state == "ok", "a 60 s heartbeat must not flip to unknown between beats"
    for key in ("dhcp", "dns", "wifi"):
        assert ev.lines[key].state == "ok", key


def test_slow_heartbeat_failure_is_still_seen():
    step = 60_000
    recs = synth.healthy(T0, T0 + 8 * step, step=step)
    t = T0 + 8 * step
    recs += synth.gateway(t, bad=4) + synth.gateway(t + step, bad=4)    # every port fails twice
    ev = evaluate_records(recs, t + step + 30_000)
    assert ev.lines["network"].state == "fail"


def test_an_outage_gap_is_not_the_cadence():
    recs = synth.healthy(T0, T0 + 60_000, step=10_000)
    recs += synth.healthy(T0 + 660_000, T0 + 700_000, step=10_000)     # 10 min silence, then normal beats
    ev = evaluate_records(recs, T0 + 700_000)
    assert ev.lines["network"].cadence_ms == 10_000


def test_too_few_beats_means_no_cadence_and_the_spec_window():
    recs = synth.healthy(T0, T0 + 20_000, step=10_000)                  # two beats, one gap
    ev = evaluate_records(recs, T0 + 20_000)
    assert ev.lines["network"].cadence_ms is None and ev.cadence_ms is None
    assert ev.lines["network"].window_ms == 30_000


def test_window_is_capped_and_never_below_the_spec():
    assert window_for("network", 1_000) == 30_000
    assert window_for("network", 120_000) == WINDOW_CAP_MS
    assert window_for("internet", 10_000) == LINE_SPECS["internet"].window_ms
    assert cadence_ms([], T0) is None


def test_state_doc_reports_cadence_and_windows_and_stays_valid():
    step = 60_000
    recs = synth.healthy(T0, T0 + 10 * step, step=step)
    doc = state_doc(evaluate_records(recs, T0 + 9 * step + 45_000, probe=synth.PROBE, site=synth.SITE))
    assert doc["cadence_s"] == 60.0
    lines = {ln["key"]: ln for ln in doc["lines"]}
    assert lines["network"]["window_s"] == 150 and lines["internet"]["window_s"] >= 120
    check_schema_file("state.schema.json", doc)
