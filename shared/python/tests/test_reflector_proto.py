import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from exp_common import ids
from exp_common import reflector_proto as rp
from exp_common.reflector_proto import Packet, ProtocolError

SID = bytes(range(16))


def test_header_layout_is_fixed():
    assert rp.HEADER_LEN == 56 and rp.MAX_DATAGRAM == 1400
    raw = rp.probe_packet(SID, 7, 123456789, 100)
    assert len(raw) == 100 and raw[:4] == b"EXP1" and raw[4] == 1 and raw[5] == 1
    assert raw[6:22] == SID and struct.unpack_from("!I", raw, 22)[0] == 7
    assert struct.unpack_from("!Q", raw, 30)[0] == 123456789
    assert struct.unpack_from("!H", raw, 54)[0] == 100 - 56


def test_pack_unpack_roundtrip():
    p = Packet(rp.TYPE_REFLECT, SID, 2**32 - 1, 2**64 - 1, pad_len=rp.MAX_PAD, reply_seq=9, t2_ns=5, t3_ns=6)
    assert rp.unpack(rp.pack(p)) == p
    assert len(rp.pack(p)) == rp.MAX_DATAGRAM


def test_reflect_is_pure_and_same_size():
    req = rp.probe_packet(SID, 42, 1000, 700)
    rep = rp.reflect(req, rx_ns=2000, tx_ns=2500, reply_seq=3)
    assert rep == rp.reflect(req, 2000, 2500, 3)
    p = rp.unpack(rep)
    assert (p.type, p.session, p.seq, p.t1_ns, p.t2_ns, p.t3_ns, p.reply_seq, p.pad_len) == \
        (rp.TYPE_REFLECT, SID, 42, 1000, 2000, 2500, 3, 700 - 56)
    assert len(rep) == len(req)                       # never an amplifier
    assert set(rep[56:]) <= {0}


def test_padding_content_is_not_reflected():
    req = bytearray(rp.probe_packet(SID, 1, 1, 200))
    req[56:] = (b"ATTACKER-CONTROLLED" * 20)[:len(req) - 56]
    assert b"ATTACKER" not in rp.reflect(bytes(req), 1, 2)


def test_reflect_refuses_non_probes():
    rep = rp.reflect(rp.probe_packet(SID, 1, 1), 1, 2)
    with pytest.raises(ProtocolError):
        rp.reflect(rep, 1, 2)                          # no reflect-of-reflect loops
    with pytest.raises(ProtocolError):
        rp.reflect(b"garbage", 1, 2)


def _good():
    return bytearray(rp.probe_packet(SID, 1, 1, 80))


@pytest.mark.parametrize("mutate", [
    lambda b: b.__setitem__(slice(0, 4), b"NOPE"),
    lambda b: b.__setitem__(4, 2),                       # version
    lambda b: b.__setitem__(4, 0),
    lambda b: b.__setitem__(5, 0),                       # type
    lambda b: b.__setitem__(5, 3),
    lambda b: b.__setitem__(slice(54, 56), struct.pack("!H", 25)),   # pad_len shorter than data
    lambda b: b.__setitem__(slice(54, 56), struct.pack("!H", 27)),   # pad_len longer than data
    lambda b: b.__setitem__(slice(54, 56), struct.pack("!H", 65535)),
    lambda b: b.extend(b"x"),                            # trailing byte
    lambda b: b.__delitem__(slice(-1, None)),            # truncated
    lambda b: b.__delitem__(slice(20, None)),            # shorter than header
    lambda b: b.clear(),
])
def test_unpack_rejects_malformed(mutate):
    b = _good()
    mutate(b)
    with pytest.raises(ProtocolError):
        rp.unpack(bytes(b))
    with pytest.raises(ProtocolError):
        rp.reflect(bytes(b), 1, 2)


def test_oversize_rejected_both_ways():
    with pytest.raises(ProtocolError):
        rp.unpack(b"\x00" * 1401)
    with pytest.raises(ProtocolError):
        rp.pack(Packet(rp.TYPE_PROBE, SID, 1, 1, pad_len=rp.MAX_PAD + 1))
    for size in (55, 1401, -1, 0, True, "100"):
        with pytest.raises(ProtocolError):
            rp.probe_packet(SID, 1, 1, size)


@pytest.mark.parametrize("kw", [{"seq": -1}, {"seq": 2**32}, {"t1_ns": -1}, {"t1_ns": 2**64},
                                {"t2_ns": 2**64}, {"reply_seq": 2**32}, {"pad_len": -1}, {"seq": 1.5},
                                {"seq": True}, {"session": b"short"}, {"session": "x" * 16}, {"type": 9}])
def test_pack_rejects_out_of_range_fields(kw):
    args = dict(type=rp.TYPE_PROBE, session=SID, seq=1, t1_ns=1)
    args.update(kw)
    with pytest.raises(ProtocolError):
        rp.pack(Packet(**args))


@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=1500))
def test_fuzz_unpack_never_raises_anything_but_protocolerror(data):
    try:
        p = rp.unpack(data)
    except ProtocolError:
        return
    assert rp.pack(p)[:rp.HEADER_LEN] == data[:rp.HEADER_LEN]       # accepted => canonical
    assert len(data) == rp.HEADER_LEN + p.pad_len <= rp.MAX_DATAGRAM


@settings(max_examples=300, deadline=None)
@given(st.binary(min_size=rp.HEADER_LEN, max_size=rp.HEADER_LEN + 20), st.binary(max_size=1400))
def test_fuzz_header_prefixed_noise(head, tail):
    data = b"EXP1\x01\x01" + head[6:] + tail
    try:
        rp.reflect(data, 1, 2)
    except ProtocolError:
        pass


@settings(max_examples=300, deadline=None)
@given(st.integers(0, 2**32 - 1), st.integers(0, 2**64 - 1), st.integers(rp.HEADER_LEN, rp.MAX_DATAGRAM),
       st.integers(0, 2**64 - 1), st.integers(0, 2**64 - 1), st.integers(0, 2**32 - 1))
def test_property_reflect_roundtrip(seq, t1, size, rx, tx, rseq):
    rep = rp.unpack(rp.reflect(rp.probe_packet(SID, seq, t1, size), rx, tx, rseq))
    assert (rep.seq, rep.t1_ns, rep.t2_ns, rep.t3_ns, rep.reply_seq) == (seq, t1, rx, tx, rseq)


# ---- TCP framing
def test_frame_roundtrip_and_fragmentation():
    pkts = [rp.probe_packet(SID, i, i, 56 + i) for i in range(5)]
    wire = b"".join(rp.frame(p) for p in pkts)
    r = rp.FrameReader()
    got = []
    for i in range(0, len(wire), 7):                     # dribble 7 bytes at a time
        got += r.feed(wire[i:i + 7])
    assert got == pkts and r.pending == 0
    r2 = rp.FrameReader()
    assert r2.feed(wire) == pkts


def test_frame_reader_rejects_bad_lengths():
    for bad in (b"\x00\x00", struct.pack("!H", 1401), b"\xff\xff"):
        with pytest.raises(ProtocolError):
            rp.FrameReader().feed(bad + b"x" * 10)
    with pytest.raises(ProtocolError):
        rp.frame(b"")
    with pytest.raises(ProtocolError):
        rp.frame(b"x" * 1401)


def test_frame_reader_buffer_bounded():
    r = rp.FrameReader()
    r.feed(struct.pack("!H", 1400) + b"x" * 100)
    assert r.pending <= rp.MAX_DATAGRAM + 2


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=4000))
def test_fuzz_frame_reader(data):
    r = rp.FrameReader()
    try:
        out = r.feed(data)
    except ProtocolError:
        return
    assert all(0 < len(p) <= rp.MAX_DATAGRAM for p in out) and r.pending <= rp.MAX_DATAGRAM + 2


# ---- control line
def test_hello_roundtrip_and_strictness():
    tok = ids.new_token("expi_")
    line = rp.format_hello(SID, "probe-a1", tok)
    assert rp.parse_hello(line) == (SID, "probe-a1", tok)
    for bad in (line[:-1], line + b"x", b"HELLO", line.replace(b"HELLO", b"HELO"), line.replace(b"probe-a1", b"Probe A"),
                line.replace(b"expi_", b"expz_"), b"HELLO " + b"zz" * 16 + b" p " + tok.encode() + b"\n", b"x" * 300,
                line.replace(b"\n", b"\r\n"), line.upper()):
        with pytest.raises(ProtocolError):
            rp.parse_hello(bad)
    with pytest.raises(ProtocolError):
        rp.format_hello(SID, "bad id", tok)
    with pytest.raises(ProtocolError):
        rp.format_hello(b"short", "p", tok)


def test_one_way_loss_from_sequence_counts():
    assert rp.one_way_loss(100, 90, 90) == (0.1, 0.0)
    f, r = rp.one_way_loss(100, 100, 80)
    assert f == 0.0 and r == pytest.approx(0.2)
    f, r = rp.one_way_loss(100, 50, 25)
    assert f == 0.5 and r == 0.5
    assert rp.one_way_loss(0, 0, 0) == (0.0, 0.0) and rp.one_way_loss(10, 0, 0) == (1.0, 0.0)
