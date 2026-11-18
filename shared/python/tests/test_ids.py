import re

import pytest

from exp_common import ids


def test_ulid_shape_and_timestamp():
    u = ids.new_ulid(now_ms=1_700_000_000_123)
    assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", u) and ids.is_ulid(u)
    assert ids.ulid_timestamp_ms(u) == 1_700_000_000_123


def test_monotonic_within_same_ms_and_backwards_clock():
    out = [ids.new_ulid(now_ms=5_000_000_000_000) for _ in range(1000)]
    out.append(ids.new_ulid(now_ms=4_000_000_000_000))   # clock stepped back: still ordered
    assert out == sorted(out) and len(set(out)) == len(out)


def test_ordering_across_ms():
    a = ids.new_ulid(now_ms=6_000_000_000_000)
    b = ids.new_ulid(now_ms=6_000_000_000_001)
    assert a < b


def test_ulid_range_guard():
    with pytest.raises(ValueError):
        ids.new_ulid(now_ms=-1)
    with pytest.raises(ValueError):
        ids.new_ulid(now_ms=1 << 48)


@pytest.mark.parametrize("bad", ["", "short", "I" * 26, "L" * 26, "O" * 26, "U" * 26, "a" * 26,
                                 "0" * 27, None, 5, b"0" * 26])
def test_is_ulid_rejects(bad):
    assert not ids.is_ulid(bad)


def test_ulid_timestamp_rejects_non_ulid():
    with pytest.raises(ValueError):
        ids.ulid_timestamp_ms("nope")


@pytest.mark.parametrize("prefix", ids.ID_PREFIXES)
def test_prefixed_ids(prefix):
    v = ids.new_id(prefix)
    assert v.startswith(prefix) and ids.is_ulid(v[len(prefix):])
    assert ids.is_prefixed_id(v) and ids.is_prefixed_id(v, prefix)


def test_prefixed_id_refusals():
    with pytest.raises(ValueError):
        ids.new_id("xyz_")
    assert not ids.is_prefixed_id(ids.new_id("h_"), "cmp_")
    assert not ids.is_prefixed_id("h_nope")
    assert not ids.is_prefixed_id("zz_" + ids.new_ulid())
    assert not ids.is_prefixed_id(None)


@pytest.mark.parametrize("kind", ["expe_", "expa_", "expi_", "expd_", "expn_"])
def test_tokens(kind):
    t = ids.new_token(kind)
    assert re.fullmatch(kind + r"[A-Za-z0-9_-]{43}", t)
    assert ids.is_token(t) and ids.is_token(t, kind) and ids.new_token(kind[:-1])[:5] == kind
    assert t != ids.new_token(kind)


def test_token_refusals():
    with pytest.raises(ValueError):
        ids.new_token("expx_")
    t = ids.new_token("expi_")
    assert not ids.is_token(t, "expn_")
    assert not ids.is_token(t + "=") and not ids.is_token(t[:-1]) and not ids.is_token(None)
    assert not ids.is_token("expz_" + "A" * 43)


def test_token_hash_and_equality():
    t = ids.new_token("expi_")
    h = ids.token_hash(t)
    assert re.fullmatch(r"[0-9a-f]{64}", h)
    import hashlib
    assert h == hashlib.sha256(t.encode()).hexdigest()
    assert ids.tokens_equal(t, t) and not ids.tokens_equal(t, ids.new_token("expi_"))
    assert not ids.tokens_equal(t, None) and not ids.tokens_equal(1, 1)
    assert ids.tokens_equal("é", "é") and not ids.tokens_equal("é", "e")   # non-ASCII must not raise


def test_slugs():
    for ok in ("a", "probe-a1", "0abc", "a" * 64):
        assert ids.is_slug(ok)
    for bad in ("", "-a", "A", "a_b", "a" * 65, "a b", "a\n", None, "é"):
        assert not ids.is_slug(bad)
