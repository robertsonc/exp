"""ICMP parsing, echo accounting and the paced TTL sweep -- all on virtual time (netfakes.FakeIcmp)."""
from __future__ import annotations

import struct

from hypothesis import given
from hypothesis import strategies as st
from netfakes import (
    FakeIcmp,
    answer_all,
    echo_reply,
    path_responder,
    recorded,
    silent,
    time_exceeded,
    unreachable,
)

from exp_probe.icmp import (
    build_echo,
    checksum,
    parse_icmp,
    parse_ping_output,
    ping_many,
    trace_sweep,
)

# ------------------------------------------------------------------------------------- packets

def test_echo_checksum_is_valid():
    pkt = build_echo(0x1234, 7)
    assert checksum(pkt) == 0                      # a correct internet checksum folds to zero
    assert pkt[0] == 8 and struct.unpack("!HH", pkt[4:8]) == (0x1234, 7)


def test_parse_reply_and_errors():
    ev = parse_icmp(echo_reply(5, 9, "10.0.0.1"), "10.0.0.1")
    assert (ev.kind, ev.ident, ev.seq, ev.src) == ("reply", 5, 9, "10.0.0.1")
    ev = parse_icmp(time_exceeded(5, 3, "10.1.0.1"), "10.1.0.1")
    assert (ev.kind, ev.ident, ev.seq) == ("time_exceeded", 5, 3)
    ev = parse_icmp(unreachable(5, 4, "10.1.0.1", code=1), "10.1.0.1")
    assert (ev.kind, ev.seq, ev.code) == ("unreachable", 4, 1)


def test_parse_rejects_junk_without_raising():
    good = echo_reply(1, 1, "10.0.0.1")
    for junk in (b"", b"\x00" * 3, good[:19], good[:22], b"\x60" + good[1:], good[:9] + b"\x06" + good[10:],
                 time_exceeded(1, 1, "10.1.0.1")[:40]):
        assert parse_icmp(junk, "10.0.0.1") is None


@given(st.binary(max_size=200))
def test_parse_never_raises_on_arbitrary_bytes(data):
    parse_icmp(data, "10.0.0.1")


# --------------------------------------------------------------------------------------- ping

def test_ping_counts_loss_and_rtt():
    replies = {"n": 0}

    def resp(dst, ident, seq, ttl, t):
        replies["n"] += 1
        return [] if replies["n"] == 2 else [(0.010, echo_reply(ident, seq, dst), dst)]
    ep = FakeIcmp(resp)
    res = ping_many(ep, ["10.0.0.1"], count=4, interval_s=0.1, timeout_s=1.0)["10.0.0.1"]
    assert (res.sent, res.received, res.loss_pct) == (4, 3, 25.0)
    assert res.rtt_ms == 10.0


def test_ping_all_lost_and_wrong_source_is_ignored():
    res = ping_many(FakeIcmp(silent), ["10.0.0.1"], 3, 0.1, 1.0)["10.0.0.1"]
    assert res.loss_pct == 100.0 and res.rtt_ms is None
    # a reply from a different address than the target must not count
    spoof = FakeIcmp(lambda dst, ident, seq, ttl, t: [(0.001, echo_reply(ident, seq, "9.9.9.9"), "9.9.9.9")])
    assert ping_many(spoof, ["10.0.0.1"], 2, 0.1, 1.0)["10.0.0.1"].received == 0


def test_ping_ignores_other_ident_and_stop_on_reply():
    ep = FakeIcmp(answer_all(0.002))
    res = ping_many(ep, ["a.b", "10.0.0.2"], count=2, interval_s=0.5, timeout_s=1.0, stop_on_reply=True)
    assert res["10.0.0.2"].sent == 1 and res["10.0.0.2"].received == 1          # answered -> no second try
    other = FakeIcmp(lambda dst, ident, seq, ttl, t: [(0.001, echo_reply(ident ^ 1, seq, dst), dst)])
    assert ping_many(other, ["10.0.0.3"], 2, 0.1, 0.5)["10.0.0.3"].received == 0


def test_ping_send_error_is_reported_not_raised():
    ep = FakeIcmp(answer_all())
    ep.fail_send_at = 1
    res = ping_many(ep, ["10.0.0.4"], 2, 0.1, 0.5)["10.0.0.4"]
    assert res.sent == 0 and "unreachable" in res.error.lower()


def test_ping_two_tries_half_second_apart():
    ep = FakeIcmp(silent)
    ping_many(ep, ["10.0.0.5"], 2, 0.5, 1.0, stop_on_reply=True)
    t = [s[0] for s in ep.sent]
    assert len(t) == 2 and abs((t[1] - t[0]) - 0.5) < 1e-9


# ---------------------------------------------------------------------------- recorded ping output

def test_parse_recorded_iputils_and_busybox_ping():
    ok = parse_ping_output(recorded("ping_ok.txt"))
    assert (ok.sent, ok.received, ok.loss_pct, ok.rtt_ms) == (4, 4, 0.0, 0.03)
    lost = parse_ping_output(recorded("ping_loss.txt"))
    assert (lost.sent, lost.received, lost.loss_pct, lost.rtt_ms) == (3, 0, 100.0, None)
    bb = parse_ping_output(recorded("ping_busybox.txt"))
    assert (bb.sent, bb.received, bb.rtt_ms) == (3, 3, 0.05)
    assert parse_ping_output("") is None and parse_ping_output("ping: unknown host") is None


# --------------------------------------------------------------------------------------- trace

TARGET = "8.8.8.8"


def test_trace_reaches_target_and_stops_sending():
    ep = FakeIcmp(path_responder(["10.1.0.2", "10.1.0.1", None], TARGET))
    r = trace_sweep(ep, TARGET, max_hops=30, pace_s=0.02, timeout_s=2.0)
    assert r.reached and r.dest_ttl == 4 and r.last_ttl == 4 and r.last_ip == TARGET
    assert [(h.ttl, h.ip) for h in r.hops] == [(1, "10.1.0.2"), (2, "10.1.0.1"), (3, None), (4, TARGET)]
    assert max(s[2] for s in ep.sent) <= 5            # nothing like 30 probes once the target answered
    assert r.rtt_ms == 4.0


def test_trace_paces_every_probe_and_never_sends_two_at_once():
    ep = FakeIcmp(silent)
    trace_sweep(ep, TARGET, max_hops=10, pace_s=0.020, timeout_s=0.5)
    times = [s[0] for s in ep.sent]
    assert [s[2] for s in ep.sent] == list(range(1, 11))
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    assert all(abs(g - 0.020) < 1e-9 for g in gaps), gaps       # the pace holds even when nothing answers


def test_trace_unreached_names_the_last_hop():
    ep = FakeIcmp(path_responder(["10.1.0.2", None, None, None], TARGET, rtts=[0.3], reach=False))
    # egress is cut past the gateway: nothing past hop 1 answers and the target is silent too
    r = trace_sweep(ep, TARGET, max_hops=6, pace_s=0.02, timeout_s=1.0)
    assert not r.reached and r.last_ttl == 1 and r.last_ip == "10.1.0.2"
    assert len(r.hops) == 1 and r.rtt_ms is None
    assert len(ep.sent) == 6                                    # unreached: sweeps all the way to max_hops


def test_trace_unreachable_message_ends_the_sweep():
    ep = FakeIcmp(path_responder(["10.1.0.2", "10.1.0.1"], TARGET, unreach_at=2))
    r = trace_sweep(ep, TARGET, max_hops=30, pace_s=0.02, timeout_s=1.0)
    assert not r.reached and r.unreachable == {"ip": "10.1.0.1", "code": 1, "ttl": 2}
    assert r.last_ip == "10.1.0.1" and max(s[2] for s in ep.sent) <= 3


def test_trace_send_failure_at_first_hop_is_an_error():
    ep = FakeIcmp(silent)
    ep.fail_send_at = 1
    r = trace_sweep(ep, TARGET)
    assert r.error and "cannot send" in r.error and not r.hops


def test_trace_ignores_foreign_icmp():
    def noisy(dst, ident, seq, ttl, t):
        return [(0.001, time_exceeded(ident ^ 0xFF, seq, "6.6.6.6", dst), "6.6.6.6")]
    r = trace_sweep(FakeIcmp(noisy), TARGET, max_hops=3, pace_s=0.01, timeout_s=0.3)
    assert not r.hops and not r.reached


def test_trace_waits_only_briefly_for_a_silent_hop_before_the_target():
    ep = FakeIcmp(path_responder([None, None], TARGET, rtts=[0.001, 0.001, 0.010]))
    t0 = ep.t
    r = trace_sweep(ep, TARGET, max_hops=30, pace_s=0.02, timeout_s=2.0)
    assert r.reached and ep.t - t0 < 1.0                        # not the full 2 s timeout
