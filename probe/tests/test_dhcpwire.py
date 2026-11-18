"""DHCP packet build/parse, and the SR-18 guarantee: the heartbeat builds DISCOVER only."""
from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st
from netfakes import FakePacketIO, frame_summary, server_frame

from exp_probe import dhcpwire as W
from exp_probe.checks import dhcp as dhcp_mod

MAC = b"\x02\xaa\xbb\xcc\xdd\x01"


def test_discover_is_a_wellformed_dhcpdiscover():
    p = W.build_discover(MAC, 0xCAFEBABE, hostname="exp-p-c01", vendor="exp-probe")
    assert len(p) >= 300                                          # BOOTP minimum
    assert p[0] == 1 and struct.unpack("!I", p[4:8])[0] == 0xCAFEBABE and p[28:34] == MAC
    assert p[236:240] == W.MAGIC
    opts = W._decode_opts(p[240:])
    assert opts[53] == bytes([W.MSG_DISCOVER])
    assert opts[61] == b"\x01" + MAC                              # client-id type 1 = busybox default
    assert opts[12] == b"exp-p-c01" and opts[60] == b"exp-probe"
    assert 50 not in opts and 54 not in opts                      # nothing a REQUEST would carry


def test_client_id_hostname_mode_matches_the_lease_holder():
    p = W.build_discover(MAC, 1, hostname="exp-p-c01", vendor="v", client_id="hostname")
    assert W._decode_opts(p[240:])[61] == b"\x00exp-p-c01"


def test_request_carries_server_and_address_and_is_a_request():
    p = W.build_request(MAC, 5, hostname="h", vendor="v", client_id="mac", requested_ip="10.1.0.31",
                        server_id="10.1.0.2")
    o = W._decode_opts(p[240:])
    assert o[53] == bytes([W.MSG_REQUEST]) and o[50] == bytes([10, 1, 0, 31]) and o[54] == bytes([10, 1, 0, 2])


def test_frame_wrapping_is_broadcast_ipv4_udp_68_to_67_with_valid_ip_checksum():
    payload = W.build_discover(MAC, 9, hostname="h", vendor="v")
    f = W.wrap_frame(MAC, payload)
    assert f[:6] == b"\xff" * 6 and f[6:12] == MAC and f[12:14] == b"\x08\x00"
    iph = f[14:34]
    assert iph[9] == 17 and iph[12:16] == bytes(4) and iph[16:20] == b"\xff\xff\xff\xff"
    s = sum(struct.unpack("!10H", iph))
    s = (s >> 16) + (s & 0xFFFF)
    assert (s + (s >> 16)) & 0xFFFF == 0xFFFF                     # valid header checksum
    assert struct.unpack("!HH", f[34:38]) == (68, 67)


def test_parse_offer_extracts_server_options_and_applies_filters():
    f = server_frame(W.MSG_OFFER, 77, MAC, server_ip="10.1.0.2", yiaddr="10.1.0.31", dns=["8.8.8.8", "1.1.1.1"])
    r = W.parse_reply(f, 77, MAC)
    assert r.msg_type == W.MSG_OFFER and r.yiaddr == "10.1.0.31" and r.server == "10.1.0.2"
    assert r.options["router"] == ["10.1.0.1"] and r.options["lease_time"] == 598
    assert r.options["subnet_mask"] == "255.255.255.0" and r.options["dns"] == ["8.8.8.8", "1.1.1.1"]
    assert W.parse_reply(f, 78, MAC) is None                      # someone else's transaction
    assert W.parse_reply(f, 77, b"\x02" * 6) is None              # someone else's client
    assert W.parse_reply(f).server_id == "10.1.0.2"


def test_server_without_server_id_falls_back_to_source_ip():
    f = server_frame(W.MSG_OFFER, 1, MAC, server_ip="10.1.0.9", yiaddr="10.1.0.40", include_server_id=False)
    assert W.parse_reply(f, 1, MAC).server == "10.1.0.9"


def test_client_frames_are_not_replies():
    own = W.wrap_frame(MAC, W.build_discover(MAC, 1, hostname="h", vendor="v"))
    assert W.parse_reply(own) is None


def test_truncated_and_corrupt_frames_never_raise():
    good = server_frame(W.MSG_OFFER, 1, MAC, server_ip="10.1.0.2", yiaddr="10.1.0.31")
    for cut in range(0, len(good), 17):
        got = W.parse_reply(good[:cut])               # never raises; padding after `end` may be cut safely
        assert got is None or cut >= 14 + 28 + 240 + 1
    bad_opt = good[:14 + 20 + 8 + 240] + bytes([53, 1, 2, 3, 200, 1]) + b"\xff"      # option overruns the packet
    assert W.parse_reply(bad_opt) is None
    nomagic = bytearray(good)
    nomagic[14 + 28 + 236:14 + 28 + 240] = b"\0\0\0\0"
    assert W.parse_reply(bytes(nomagic)) is None


@given(st.binary(max_size=400))
def test_parse_reply_fuzz(data):
    W.parse_reply(data)
    W.parse_reply(data, 1, MAC)


@given(st.binary(min_size=240, max_size=500))
def test_parse_reply_fuzz_with_valid_framing(blob):
    good = server_frame(W.MSG_OFFER, 1, MAC, server_ip="10.1.0.2", yiaddr="10.1.0.31")
    W.parse_reply(good[:14 + 28] + blob)


# ------------------------------------------------------------------------------ SR-18: DISCOVER only

def test_discover_run_sends_only_discovers_even_when_offered(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the heartbeat must never build a DHCPREQUEST (SR-18)")
    monkeypatch.setattr(W, "build_request", boom)
    io = FakePacketIO([{"ip": "10.1.0.2", "offer_delay": 0.012, "yiaddr": "10.1.0.31"}])
    res = dhcp_mod.discover_run(io, hostname="h", vendor="v", client_id="mac", collect_s=3.0)
    assert len(res.offers) == 1 and res.offers[0].ms == pytest.approx(12.0)
    assert set(io.msg_types_sent()) == {W.MSG_DISCOVER}


def test_discover_run_retransmits_once_at_half_the_window():
    io = FakePacketIO([{"ip": "10.1.0.2", "offer_delay": None, "yiaddr": "10.1.0.31"}])
    res = dhcp_mod.discover_run(io, hostname="h", vendor="v", client_id="mac", collect_s=3.0)
    assert not res.offers and res.resent
    assert io.msg_types_sent() == [W.MSG_DISCOVER, W.MSG_DISCOVER]
    assert abs(io.sent[1][0] - io.sent[0][0] - 1.5) < 1e-6
    assert io.now() - io.sent[0][0] == pytest.approx(3.0, abs=1e-6)         # waited the whole window
    assert frame_summary(io.sent[0][1])[1] == res.xid == frame_summary(io.sent[1][1])[1]


def test_the_heartbeat_module_cannot_even_reach_build_request():
    import inspect
    src = inspect.getsource(dhcp_mod.discover_run) + inspect.getsource(dhcp_mod.dhcp_hb)
    assert "build_request" not in src and "MSG_REQUEST" not in src
