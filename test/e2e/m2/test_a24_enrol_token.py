"""A2.4 - the enrol token is single use and expires; the enrol endpoint is rate limited (> 10/min/IP -> 429).

Single use and expiry are exercised through the product's own one-liner in systemd containers (the installer must
surface the manager's 410 and leave the host exactly as it was). Time is simulated by moving `expires_at` in the
Worker's local D1 (cron does not run in `wrangler dev`; the enrol route itself checks the clock). The rate limit
is exercised directly against the Worker: the limiter key is CF-Connecting-IP, which Cloudflare sets in production
and the test sets explicitly (so the test's own enrols never share a bucket with the containers').
"""

from __future__ import annotations

import hashlib
import json

import pytest
from expharness.dockerhost import wait_for

from conftest import start_host

SITE = "hall-a24"
FACTS = {"hostname": "direct-call", "arch": "amd64"}


@pytest.fixture(scope="module")
def site(stack):
    stack.admin.post("/sites", {"site": SITE, "name": "Hall A24", "timezone": "UTC"}, ok=(201,))
    stack.admin.call("PATCH", f"/sites/{SITE}/release", {"version": stack.version}, ok=(200,))
    return SITE


def new_host(stack, name):
    r = stack.admin.post("/hosts", {"name": name, "site": SITE}, ok=(201,))
    return r["host"]["host_id"], r["enrol"]


def enrol_call(stack, token, ip="198.51.100.20"):
    body = json.dumps({"token": token, "facts": FACTS}).encode()
    return stack.mgr.request(
        "POST",
        "/api/agent/v1/enrol",
        body=body,
        headers={"Content-Type": "application/json", "CF-Connecting-IP": ip},
    )


def token_row(stack, host_id):
    rows = stack.mgr.sql(f"SELECT used_at, expires_at FROM enrol_tokens WHERE host_id = '{host_id}'")
    assert len(rows) == 1, rows
    return rows[0]


def agent_state(host):
    cfg = host.run("sha256sum /etc/exp/agent.json | cut -d' ' -f1").out.strip()
    return cfg, host.run("systemctl is-active exp-agent").out.strip()


def test_enrol_token_is_single_use(stack, site, host_image):
    hid, enrol = new_host(stack, "e2e-single-use")
    h1 = start_host(stack, "a24a")
    h2 = start_host(stack, "a24b")
    try:
        first = h1.run(enrol["command"], timeout=600)
        assert first.rc == 0, first
        wait_for(lambda: stack.admin.get(f"/hosts/{hid}")["state"] == "enrolled", 30, 2, "host enrolled")
        used = token_row(stack, hid)["used_at"]
        assert used
        cfg_before, active_before = agent_state(h1)
        assert active_before == "active"
        before = stack.admin.get(f"/hosts/{hid}")

        # 1. the same one-liner, run again on the enrolled host: refused with 410, nothing changes
        again = h1.run(enrol["command"], timeout=300)
        assert again.rc != 0, again
        assert "already used or has expired" in again.text, again
        assert agent_state(h1) == (cfg_before, "active"), "the agent identity changed on a refused re-run"
        assert token_row(stack, hid)["used_at"] == used

        # 2. the same one-liner on a different, fresh machine: refused, the host is not hijacked
        other = h2.run(enrol["command"], timeout=300)
        assert other.rc != 0 and "already used or has expired" in other.text, other
        assert not h2.run("test -e /etc/exp/agent.json").rc == 0, "a refused enrol left an identity behind"
        assert h2.run("systemctl is-active exp-agent").out.strip() != "active"
        after = stack.admin.get(f"/hosts/{hid}")
        assert after["facts"]["hostname"] == before["facts"]["hostname"] == "e2e-a24a"
        assert after["state"] == "enrolled"

        # 3. and straight against the API: 410 with the documented code, for a used token
        r = enrol_call(stack, enrol["token"], ip="198.51.100.21")
        assert r.status == 410 and r.json()["error"]["code"] == "token_used_or_expired", r
        assert token_row(stack, hid)["used_at"] == used
        assert hashlib.sha256(h1.read("/etc/exp/agent.json").encode()).hexdigest() == cfg_before
    finally:
        for h in (h1, h2):
            h.remove()


def test_enrol_token_expires(stack, site, host_image):
    hid, enrol = new_host(stack, "e2e-expiry")
    # a token that has not expired still works the instant before: prove it is the clock, not the token
    row = token_row(stack, hid)
    assert row["used_at"] is None
    stack.mgr.sql(f"UPDATE enrol_tokens SET expires_at = '2020-01-01T00:00:00.000Z' WHERE host_id = '{hid}'")
    h = start_host(stack, "a24c")
    try:
        r = h.run(enrol["command"], timeout=300)
        assert r.rc != 0 and "already used or has expired" in r.text, r
        assert h.run("test -e /etc/exp/agent.json").rc != 0
        assert stack.admin.get(f"/hosts/{hid}")["state"] == "pending"
        assert token_row(stack, hid)["used_at"] is None, "an expired token must not be consumed"
        direct = enrol_call(stack, enrol["token"], ip="198.51.100.22")
        assert direct.status == 410 and direct.json()["error"]["code"] == "token_used_or_expired", direct
        # a fresh token for the same pending host works (the old one stays dead)
        t = stack.admin.post(f"/hosts/{hid}/enrol-token", None, ok=(201,))
        ok = h.run(t["command"], timeout=600)
        assert ok.rc == 0, ok
        assert stack.admin.get(f"/hosts/{hid}")["state"] == "enrolled"
    finally:
        h.remove()


def test_unknown_token_is_401_not_410(stack, site):
    r = enrol_call(stack, "expe_" + "A" * 43, ip="198.51.100.23")
    assert r.status == 401 and r.json()["error"]["code"] == "invalid_token", r


def test_enrol_is_rate_limited_per_ip(stack, site):
    ip = "203.0.113.77"
    bogus = "expe_" + "B" * 43
    codes = [enrol_call(stack, bogus, ip).status for _ in range(12)]
    assert codes[:10] == [401] * 10, codes
    assert 429 in codes[10:], codes
    limited = enrol_call(stack, bogus, ip)
    assert limited.status == 429 and limited.json()["error"]["code"] == "rate_limited", limited
    assert limited.headers.get("retry-after"), limited.headers
    # per IP: another address is not affected
    assert enrol_call(stack, bogus, "203.0.113.78").status == 401
    # and a valid token from the limited address is refused too (the limiter runs before the lookup)
    hid, enrol = new_host(stack, "e2e-ratelimit")
    assert enrol_call(stack, enrol["token"], ip).status == 429
    assert token_row(stack, hid)["used_at"] is None
