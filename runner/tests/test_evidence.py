"""Evidence envelopes: every placeholder is schema-valid (regression: baseline required fields), bounds."""
from __future__ import annotations

import pytest
from rthelpers import load_fixture

from exp_runner import evidence as ev

T = "st_01M7R3X9G0RBGD0H1DC76AJK35"
W = {"from": "2026-11-18T13:57:11.120Z", "to": "2026-11-18T14:04:27.540Z"}


@pytest.mark.parametrize("kind", ev.KINDS)
@pytest.mark.parametrize("status", ["unavailable", "error"])
def test_every_kind_has_a_valid_empty_unavailable_or_error_document(kind, status):
    d = ev.placeholder(T, kind, status, W, 1_795_000_000.0)
    assert d["data"] == {} and d["status"] == status and ev.validation_errors(d) == []


@pytest.mark.parametrize("kind", ev.KINDS)
def test_placeholder_default_source_is_allowed_for_the_kind(kind):
    assert ev.validation_errors(ev.placeholder(T, kind, "unavailable", W, 0.0)) == []


def test_a_populated_baseline_still_needs_probe_and_severity():
    d = ev.placeholder(T, "baseline", "ok", W, 0.0)
    d["data"] = {"site": "hall-b"}
    assert ev.validation_errors(d)
    good = load_fixture("evidence/baseline.ok.json")
    assert ev.validation_errors(good) == []


def test_bad_status_is_refused():
    with pytest.raises(ValueError):
        ev.envelope(T, "wifi", "mist", "great", {}, W, 0.0)


def test_raw_refs_are_bounded():
    d = ev.envelope(T, "security", "syslog", "ok", {"events": []}, W, 0.0, [f"syslog:{i}" for i in range(100)])
    assert len(d["raw_refs"]) == 20


@pytest.mark.parametrize("name", ["wifi.ok", "wired.ok", "flows.ok", "wan.ok", "security.policy-block", "baseline.ok", "dns.ok",
                                  "identity.mist", "identity.nat-suspected", "identity.dhcp-fallback"])
def test_contract_fixtures_validate_with_the_runner_side_validator(name):
    assert ev.validation_errors(load_fixture(f"evidence/{name}.json")) == []
