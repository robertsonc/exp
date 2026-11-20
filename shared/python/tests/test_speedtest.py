"""exp_common.speedtest: ids, score (worked examples), counters, device_key, view-proof scheme."""
import hashlib
import hmac
import re

import pytest

from exp_common import ids, speedtest as st


def test_speedtest_id():
    i = st.new_speedtest_id()
    assert re.fullmatch(r"st_[0-9A-HJKMNP-TV-Z]{26}", i) and st.is_speedtest_id(i)
    assert not st.is_speedtest_id("st_nope") and not st.is_speedtest_id(ids.new_id("h_")) and not st.is_speedtest_id(None)


# --- score: worked examples (12 section 4.2) ------------------------------------------------------------
T = {"down_mbps": 25, "up_mbps": 10}


def leg(**kw):
    return {"down_mbps": 100.0, "up_mbps": 50.0, "idle_ms": 10.0, "loaded_down_ms": 30.0, "loaded_up_ms": 30.0, "cv": 0.0, **kw}


def test_perfect_score_is_100():
    assert st.compute_score({"internet": leg()}, T) == {"total": 100, "speed": 100, "responsiveness": 100, "stability": 100}


def test_spec_example_parts():
    # speed 92: (min(212/25,1)=1 + min(x/10,1)) / 2 => up 8.4 Mb/s gives 0.84, mean 0.92; responsiveness 55: loaded 151.5 ms
    # => (300-151.5)/270 = 0.55; stability 80: cv 0.1 => 1 - 0.1/0.5 = 0.8
    s = st.compute_score({"internet": leg(down_mbps=212.0, up_mbps=8.4, loaded_down_ms=96.0, loaded_up_ms=151.5, cv=0.1)}, T)
    assert s == {"total": 74, "speed": 92, "responsiveness": 55, "stability": 80}  # 36.8 + 22 + 16 = 74.8 floors to 74


def test_total_floors_never_rounds_up():
    s = st.compute_score({"internet": leg(down_mbps=24.9, up_mbps=10.0)}, T)  # speed 0.998 -> 99.92 total
    assert s["total"] == 99 and s["speed"] == 100


def test_responsiveness_linear_and_clamped():
    f = lambda ms: st.compute_score({"internet": leg(loaded_down_ms=ms, loaded_up_ms=ms)}, T)["responsiveness"]  # noqa: E731
    assert f(0) == 100 and f(30) == 100 and f(300) == 0 and f(5000) == 0
    assert f(165) == 50  # midpoint


def test_loaded_latency_is_the_worse_direction_and_falls_back_to_idle():
    a = st.compute_score({"internet": leg(loaded_down_ms=20.0, loaded_up_ms=300.0)}, T)
    assert a["responsiveness"] == 0
    b = st.compute_score({"internet": {"down_mbps": 50, "up_mbps": 20, "idle_ms": 30.0, "cv": 0}}, T)
    assert b["responsiveness"] == 100
    c = st.compute_score({"internet": {"down_mbps": 50, "up_mbps": 20, "cv": 0}}, T)
    assert c["responsiveness"] == 0 and c["total"] == 60


def test_stability_cv_and_failures():
    g = lambda **kw: st.compute_score({"internet": leg(**kw)}, T, kw.pop("failures", 0))["stability"]  # noqa: E731
    assert g(cv=0.0) == 100 and g(cv=0.25) == 50 and g(cv=0.5) == 0 and g(cv=9) == 0
    assert st.compute_score({"internet": leg()}, T, failures=3)["stability"] == 70
    assert st.compute_score({"internet": leg()}, T, failures=50)["stability"] == 0
    assert st.compute_score({"internet": {"down_mbps": 50, "up_mbps": 20, "loaded_down_ms": 30}}, T)["stability"] == 0  # no cv


def test_basis_prefers_internet_falls_back_to_local_and_none():
    both = {"internet": leg(down_mbps=5.0, up_mbps=2.0), "local": leg()}
    assert st.score_basis(both)[0] == "internet"
    assert st.compute_score(both, T)["speed"] == 20
    only_local = {"local": leg(), "internet": {"unavailable": True}}
    assert st.score_basis(only_local)[0] == "local" and st.compute_score(only_local, T)["total"] == 100
    assert st.compute_score({}, T) is None and st.compute_score({"local": {"idle_ms": 5}}, T) is None


def test_one_direction_only_and_default_targets():
    s = st.compute_score({"local": {"down_mbps": 12.5, "loaded_down_ms": 30, "cv": 0}})  # default 25 Mb/s
    assert s["speed"] == 50 and s["total"] == 80


@pytest.mark.parametrize("bad", [True, "50", None, float("nan"), float("inf"), -3])
def test_bad_numbers_are_no_data(bad):
    assert st.compute_score({"internet": {"down_mbps": bad, "up_mbps": bad}}) is None


def test_score_is_deterministic():
    legs = {"internet": leg(down_mbps=33.3, up_mbps=4.4, loaded_down_ms=88.8, cv=0.12)}
    assert st.compute_score(legs, T) == st.compute_score(legs, T)


# --- counters ---------------------------------------------------------------------------------------------
def test_counters_disagree():
    assert not st.counters_disagree(100, 100) and not st.counters_disagree(100, 120) and st.counters_disagree(100, 126)
    assert not st.counters_disagree(0, 0) and st.counters_disagree(0, 5) and st.counters_disagree(None, 5)
    assert st.counters_disagree(float("nan"), 1)


# --- device_key -------------------------------------------------------------------------------------------
def test_device_key_known_answer_and_normalisation():
    secret = "expk_" + "A" * 43
    key = bytes(32)  # 43 'A' base64url decodes to 32 zero bytes
    want = hmac.new(key, b"aa:bb:cc:dd:ee:ff", hashlib.sha256).hexdigest()
    assert st.device_key(secret, "aa:bb:cc:dd:ee:ff") == want
    for spelling in ("AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "AABBCCDDEEFF"):
        assert st.device_key(secret, spelling) == want
    assert re.fullmatch(r"[0-9a-f]{64}", want)
    assert st.device_key("expk_" + "B" * 43, "aa:bb:cc:dd:ee:ff") != want


@pytest.mark.parametrize("bad", ["", "aa:bb", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00", None])
def test_device_key_rejects_bad_mac(bad):
    with pytest.raises(ValueError):
        st.device_key("expk_" + "A" * 43, bad)


@pytest.mark.parametrize("bad", ["", "expi_" + "A" * 43, "expk_short", None])
def test_device_key_rejects_bad_secret(bad):
    with pytest.raises(ValueError):
        st.device_key(bad, "aa:bb:cc:dd:ee:ff")


def test_new_expk_secret_works():
    assert len(st.device_key(ids.new_token("expk_"), "00:11:22:33:44:55")) == 64


# --- view proof -------------------------------------------------------------------------------------------
def test_view_proof_roundtrip_and_binding():
    k, sid = st.new_view_key(), st.new_speedtest_id()
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", k)
    proof = st.view_proof(k, sid)
    assert ids.is_token(proof, "expv_") and proof != k
    verifier = st.view_verifier(proof)
    assert re.fullmatch(r"[0-9a-f]{64}", verifier) and verifier == ids.token_hash(proof)
    assert st.verify_view_proof(verifier, proof)
    # another session id or another key gives another proof
    assert not st.verify_view_proof(verifier, st.view_proof(k, st.new_speedtest_id()))
    assert not st.verify_view_proof(verifier, st.view_proof(st.new_view_key(), sid))
    assert not st.verify_view_proof(verifier, k)  # the raw key is not a proof


@pytest.mark.parametrize("bad", ["", "expv_", "expv_short", None, 5, "expi_" + "A" * 43])
def test_verify_never_raises(bad):
    assert st.verify_view_proof("0" * 64, bad) is False


def test_view_proof_input_checks():
    with pytest.raises(ValueError):
        st.view_proof("short", st.new_speedtest_id())
    with pytest.raises(ValueError):
        st.view_proof(st.new_view_key(), "not-an-id")


def test_new_prefixes_are_tokens():
    for kind in ("exps_", "expr_", "expl_", "expk_", "expt_", "expv_"):
        t = ids.new_token(kind)
        assert ids.is_token(t, kind) and ids.is_token(t)
