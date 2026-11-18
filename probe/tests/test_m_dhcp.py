"""`dhcp_hb` (discover-only heartbeat) and `dhcp` (DORA re-confirmation)."""
from __future__ import annotations

import os
import signal

import pytest
from measure_support import BOUND, make_ctx
from netfakes import FakeEnv, FakePacketIO, frame_summary, validate_measurements

from exp_probe import dhcpwire as W
from exp_probe.tests import dhcp as D

S1 = {"ip": "10.1.0.2", "offer_delay": 0.0124, "ack_delay": 0.025, "yiaddr": "10.1.0.31", "dns": ["8.8.8.8"]}
ROGUE = {"ip": "10.1.0.66", "offer_delay": 0.4, "ack_delay": 0.4, "yiaddr": "10.1.0.200", "mac": b"\x02\x66\x66\x66\x66\x66",
         "router": "10.1.0.66"}


def hb(tmp_path, servers, **kw):
    io = FakePacketIO(servers)
    kw.setdefault("env", FakeEnv(packet_io=io))
    ctx = make_ctx(tmp_path, **kw)
    return D.dhcp_hb(ctx), io


# ------------------------------------------------------------------------------------- dhcp_hb

def test_hb_ok_record_shape(tmp_path):
    (m,), io = hb(tmp_path, [S1])
    validate_measurements([m])
    assert m.test == "dhcp_hb" and m.outcome == "ok"
    assert m.labels == {"port": "c01", "server": "10.1.0.2"}
    assert set(m.metrics) == {"offer_ms", "offers"} and m.metrics["offers"] == 1 and m.metrics["offer_ms"] == pytest.approx(12.4)
    assert m.detail["offered_ip"] == "10.1.0.31" and m.detail["rogue_suspect"] is False
    assert m.detail["options"]["router"] == "10.1.0.1" or m.detail["options"]["router"] == ["10.1.0.1"]
    assert m.detail["options"]["lease_time"] == 598
    assert set(io.msg_types_sent()) == {W.MSG_DISCOVER} and io.closed         # SR-18, and the socket is closed


def test_hb_never_sends_a_request_even_with_a_server_waiting_for_one(tmp_path):
    (m,), io = hb(tmp_path, [S1, ROGUE])
    assert W.MSG_REQUEST not in io.msg_types_sent()


def test_hb_no_offer_is_fail_with_server_none(tmp_path):
    (m,), io = hb(tmp_path, [{**S1, "offer_delay": None}])
    validate_measurements([m])
    assert m.outcome == "fail" and m.labels["server"] == "none" and m.metrics == {"offers": 0}
    assert m.error == "no DHCPOFFER within 3 s"
    assert io.msg_types_sent() == [W.MSG_DISCOVER, W.MSG_DISCOVER]          # one retransmit, still no REQUEST


def test_hb_slow_offer_is_degraded(tmp_path):
    (m,), _ = hb(tmp_path, [{**S1, "offer_delay": 1.2}])
    validate_measurements([m])
    assert m.outcome == "degraded" and m.metrics["offer_ms"] == pytest.approx(1200.0)


def test_hb_threshold_is_configurable(tmp_path):
    (m,), _ = hb(tmp_path, [{**S1, "offer_delay": 0.3}], tests={"dhcp": {"thresholds": {"offer_ms": 100}}})
    assert m.outcome == "degraded"


def test_hb_rogue_second_server_is_flagged_in_label_and_detail(tmp_path):
    (m,), _ = hb(tmp_path, [S1, ROGUE])
    validate_measurements([m])
    assert m.outcome == "degraded" and m.detail["rogue_suspect"] is True
    assert m.labels["server"] == "10.1.0.2" and m.metrics["offers"] == 2        # the first responder labels the record
    assert set(m.detail["servers"]) == {"10.1.0.2", "10.1.0.66"} and "multiple DHCP servers" in m.error
    assert {o["server"] for o in m.detail["offer_list"]} == {"10.1.0.2", "10.1.0.66"}


def test_hb_late_rogue_inside_the_collect_window_is_still_seen(tmp_path):
    (m,), _ = hb(tmp_path, [S1, {**ROGUE, "offer_delay": 2.4}])              # a ping-checking rogue answers ~2 s late
    assert m.detail["rogue_suspect"] is True and m.metrics["offers"] == 2


def test_hb_server_outside_allowed_list_is_rogue_even_if_alone(tmp_path):
    (m,), _ = hb(tmp_path, [S1], tests={"dhcp": {"allowed_servers": ["10.1.0.9"]}})
    assert m.detail["rogue_suspect"] is True and m.outcome == "degraded" and "not in the allowed list" in m.error


def test_hb_collect_window_is_configurable(tmp_path):
    (m,), io = hb(tmp_path, [{**S1, "offer_delay": None}], tests={"dhcp": {"offer_collect_s": 1.0}})
    assert m.error == "no DHCPOFFER within 1 s" and io.now() - io.sent[0][0] == pytest.approx(1.0, abs=1e-6)


def test_hb_retransmitted_discover_answered_twice_counts_one_offer(tmp_path):
    (m,), _ = hb(tmp_path, [{**S1, "offer_delay": 2.0}])
    assert m.metrics["offers"] == 1 and m.detail.get("resent") is True


def test_hb_no_link_is_error_and_explicit_does_not_fall_back(tmp_path):
    (m,), _ = hb(tmp_path, [S1], env=FakeEnv(packet_io=FakePacketIO([S1]), running=False), explicit=True)
    validate_measurements([m])
    assert m.outcome == "error" and "no link" in m.error and m.labels["server"] == "none"


def test_hb_all_ports_unusable_says_no_client_could_run_it(tmp_path):
    ctx = make_ctx(tmp_path, env=FakeEnv(packet_io=FakePacketIO([S1]), running=False))
    (m,) = D.dhcp_hb(ctx)
    validate_measurements([m])
    assert m.outcome == "error" and m.error.startswith("no client could run it:") and "c01 no link" in m.error and "c02 no link" in m.error
    assert "null" not in m.error.lower()


def test_hb_raw_socket_denied_is_error(tmp_path):
    (m,) = D.dhcp_hb(make_ctx(tmp_path, env=FakeEnv(packet_io=None)))
    assert m.outcome == "error" and "raw socket denied" in m.error


def test_hb_falls_back_to_the_next_port_when_the_rotated_one_has_no_link(tmp_path):
    envs = {"c01": FakeEnv(packet_io=FakePacketIO([S1]), running=False), "c02": FakeEnv(packet_io=FakePacketIO([S1]))}
    ctx = make_ctx(tmp_path)
    ctx.net = lambda cfg, port, control=False: envs[port.id]
    (m,) = D.dhcp_hb(ctx)
    assert m.outcome == "ok" and m.labels["port"] == "c02"


def test_hb_uses_the_lease_holders_identity(tmp_path):
    (m,), io = hb(tmp_path, [S1], ports=[{"id": "c01", "iface": "t0", "role": "client",
                                          "dhcp": {"hostname": "exp-c01", "vendor_class": "vc", "client_id": "hostname"}}],
                  leased=("c01",))
    raw = frame_summary(io.sent[0][1])[2]
    assert raw[12] == b"exp-c01" and raw[60] == b"vc" and raw[61] == b"\x00exp-c01"


# ------------------------------------------------------------------------------------- dhcp (DORA)

def dora(tmp_path, servers, **kw):
    io = FakePacketIO(servers)
    ctx = make_ctx(tmp_path, env=FakeEnv(packet_io=io), **kw)
    return D.dhcp(ctx), io, ctx


def test_dora_ok_record_shape_and_timings(tmp_path):
    (m,), io, _ = dora(tmp_path, [S1])
    validate_measurements([m])
    assert m.test == "dhcp" and m.outcome == "ok" and m.labels == {"port": "c01", "server": "10.1.0.2"}
    assert set(m.metrics) == {"discover_offer_ms", "request_ack_ms", "total_ms", "lease_s", "offers"}
    assert m.metrics["discover_offer_ms"] == pytest.approx(12.4) and m.metrics["request_ack_ms"] == pytest.approx(25.0)
    assert m.metrics["total_ms"] == pytest.approx(37.4) and m.metrics["lease_s"] == 598 and m.metrics["offers"] == 1
    assert m.duration_ms == m.metrics["total_ms"]
    assert m.detail["ip"] == "10.1.0.31" and m.detail["router"] == "10.1.0.1" and m.detail["dns"] == ["8.8.8.8"]
    assert m.detail["options"]["subnet_mask"] == "255.255.255.0"
    assert io.msg_types_sent()[:2] == [W.MSG_DISCOVER, W.MSG_REQUEST]


def test_dora_reconfirms_the_held_binding_and_takes_no_second_lease(tmp_path):
    (m,), io, _ = dora(tmp_path, [S1])
    d_op, _, d_raw = frame_summary(io.sent[0][1])
    _, _, r_raw = frame_summary(io.sent[1][1])
    assert d_raw[50] == bytes([10, 1, 0, 31])                               # DISCOVER asks for the held address
    assert r_raw[50] == bytes([10, 1, 0, 31]) and r_raw[54] == bytes([10, 1, 0, 2])
    assert d_raw[61] == r_raw[61] == b"\x01" + io.mac                       # same client-id as the lease holder
    sent = io.msg_types_sent()
    assert W.MSG_DECLINE not in sent and 7 not in sent                      # no DECLINE / RELEASE
    assert m.detail["held_ip"] == "10.1.0.31" and "flags" in m.detail and m.detail["flags"] == []


def test_dora_without_a_held_lease_is_an_error_not_a_second_lease(tmp_path):
    (m,), io, _ = dora(tmp_path, [S1], leased=())
    validate_measurements([m])
    assert m.outcome == "error" and "no lease" in m.error and io.sent == []


def test_dora_no_offer_is_fail_after_three_discovers(tmp_path):
    (m,), io, _ = dora(tmp_path, [{**S1, "offer_delay": None}])
    validate_measurements([m])
    assert m.outcome == "fail" and m.error == "no DHCPOFFER after 3 discovers"
    assert m.labels["server"] == "none" and m.metrics == {"offers": 0}
    assert io.msg_types_sent() == [W.MSG_DISCOVER] * 3


def test_dora_no_ack_is_fail(tmp_path):
    (m,), io, _ = dora(tmp_path, [{**S1, "ack_delay": None}])
    validate_measurements([m])
    assert m.outcome == "fail" and m.error == "no DHCPACK/NAK after 3 requests" and m.metrics["discover_offer_ms"] > 0


def test_dora_nak_is_fail_with_the_servers_message(tmp_path):
    (m,), _, _ = dora(tmp_path, [{**S1, "nak": True}])
    validate_measurements([m])
    assert m.outcome == "fail" and m.error == "DHCPNAK: wrong network"


def test_dora_slow_is_degraded(tmp_path):
    (m,), _, _ = dora(tmp_path, [{**S1, "ack_delay": 1.7}])
    assert m.outcome == "degraded" and "slow" in m.detail["flags"]


def test_dora_retry_is_degraded_and_counted(tmp_path):
    io = FakePacketIO([S1])
    io.drop_first_discovers = 1
    ctx = make_ctx(tmp_path, env=FakeEnv(packet_io=io))
    (m,) = D.dhcp(ctx)
    assert m.outcome == "degraded" and m.detail["retries"] == 1 and "retries" in m.detail["flags"]
    assert m.metrics["discover_offer_ms"] == pytest.approx(12.4)            # measured from the discover that worked


def test_dora_rogue_offer_is_flagged(tmp_path):
    (m,), _, _ = dora(tmp_path, [S1, ROGUE])
    validate_measurements([m])
    assert m.outcome == "degraded" and "multiple_dhcp_servers" in m.detail["flags"] and m.metrics["offers"] == 2
    assert m.labels["server"] == "10.1.0.2"                                  # re-confirmed with the lease holder's server


def test_dora_prefers_the_lease_holders_server_even_if_a_rogue_answers_first(tmp_path):
    (m,), io, _ = dora(tmp_path, [{**ROGUE, "offer_delay": 0.002, "ack_delay": 0.002}, {**S1, "offer_delay": 0.05}])
    assert m.labels["server"] == "10.1.0.2" and m.outcome == "degraded"
    req = [f for _, f in io.sent if frame_summary(f)[2][53][0] == W.MSG_REQUEST][0]
    assert frame_summary(req)[2][54] == bytes([10, 1, 0, 2])


def test_dora_ack_with_a_different_address_nudges_the_lease_holder(tmp_path, monkeypatch):
    ctx_args = dict(env=FakeEnv(packet_io=FakePacketIO([{**S1, "ack_yiaddr": "10.1.0.77"}])))
    ctx = make_ctx(tmp_path, **ctx_args)
    pid = 4242
    ctx.paths.pid_file("c01").write_text(f"{pid}\n")
    (ctx.paths.proc / str(pid)).mkdir(parents=True)
    (ctx.paths.proc / str(pid) / "comm").write_text("udhcpc\n")
    killed = []
    monkeypatch.setattr(os, "kill", lambda p, s: killed.append((p, s)))
    (m,) = D.dhcp(ctx)
    assert m.outcome == "degraded" and "ack_ip_differs_from_held_lease" in m.detail["flags"]
    assert m.detail["renew_signalled"] is True and killed == [(pid, signal.SIGUSR1)]


def test_nudge_refuses_a_pid_that_is_not_udhcpc(tmp_path, monkeypatch):
    ctx = make_ctx(tmp_path)
    ctx.paths.pid_file("c01").write_text("999\n")
    (ctx.paths.proc / "999").mkdir(parents=True)
    (ctx.paths.proc / "999" / "comm").write_text("sshd\n")
    monkeypatch.setattr(os, "kill", lambda *a: pytest.fail("must not signal an unrelated process"))
    assert D.nudge_lease_holder(ctx, ctx.port) is False
    ctx.paths.pid_file("c01").write_text("1\n")
    assert D.nudge_lease_holder(ctx, ctx.port) is False
    ctx.paths.pid_file("c01").write_text("not-a-pid")
    assert D.nudge_lease_holder(ctx, ctx.port) is False


def test_dora_identity_is_recorded_without_touching_the_lease_file(tmp_path):
    (_, ), _, ctx = dora(tmp_path, [S1])
    from exp_probe.lease import read_lease
    doc = read_lease(ctx.paths, "c01")
    assert doc["ip"] == BOUND["ip"] and doc["state"] == "bound"            # the held lease record is untouched


# ------------------------------------------------------------------ hostile input from the network (SR-3)

def test_hostile_nak_text_and_option_floods_cannot_break_the_record(tmp_path):
    from netfakes import server_frame

    class Hostile(FakePacketIO):
        def send(self, frame):
            super().send(frame)
            op, xid, raw = frame_summary(frame)
            if raw[53][0] == W.MSG_REQUEST:
                self.queue.clear()
                self.queue.append((self.t + 0.01, server_frame(W.MSG_NAK, xid, self.mac, server_ip="10.1.0.2", yiaddr="0.0.0.1",
                                                                message="bad\x00\x1b[31m\n" + "A" * 240)))
    io = Hostile([S1])
    (m,) = D.dhcp(make_ctx(tmp_path, env=FakeEnv(packet_io=io)))
    validate_measurements([m])
    assert m.outcome == "fail" and m.error.startswith("DHCPNAK: ") and all(ch.isprintable() for ch in m.error)


def test_offer_option_lists_are_bounded(tmp_path):
    import socket

    from netfakes import server_frame
    mac = b"\x02" * 6
    f = server_frame(W.MSG_OFFER, 1, mac, server_ip="10.1.0.2", yiaddr="10.1.0.31", dns=[f"10.2.0.{i}" for i in range(1, 60)])
    r = W.parse_reply(f, 1, mac)
    assert r is not None and len(r.options["dns"]) == 8 and socket.inet_aton(r.yiaddr)
