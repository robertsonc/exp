"""SSO handoff (01-contracts.md section 12; 04-dashboard.md section 7 item 1)."""
from __future__ import annotations

import sqlite3
import time

import pytest

from conftest import make_jwt


def _sso(client, token, **kw):
    return client.post("/auth/sso", form={"token": token}, **kw)


def test_valid_token_creates_session(world):
    c = world.client()
    r = _sso(c, world.sso_token())
    assert r.status == 303 and r.headers["location"] == "/"
    cookie = r.set_cookies[0]
    assert cookie.startswith("__Host-exp_session=")
    for attr in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
        assert attr in cookie
    assert "Domain" not in cookie
    who = c.whoami().json()
    assert who["user"] == "admin@example.com" and who["role"] == "admin" and who["kind"] == "sso"
    assert who["csrf"]


def test_json_post_also_works_and_returns_csrf(world):
    c = world.client()
    r = c.post("/auth/sso", json_body={"token": world.sso_token(role="viewer")})
    assert r.status == 200 and r.json()["role"] == "viewer" and r.json()["csrf"]


def test_session_id_is_stored_hashed_and_survives_restart(world):
    c = world.client()
    _sso(c, world.sso_token())
    sid = c.cookie
    assert sid and len(sid) >= 43                       # 256 bits, urlsafe
    db = world.state_dir / "sessions.db"
    raw = b"".join(p.read_bytes() for p in world.state_dir.glob("sessions.db*"))
    assert sid.encode() not in raw
    rows = sqlite3.connect(str(db)).execute("SELECT id_hash FROM sessions").fetchall()
    assert len(rows) == 1 and len(rows[0][0]) == 64
    assert (db.stat().st_mode & 0o777) == 0o600
    world.restart()
    c2 = world.client()
    c2.cookie = sid
    assert c2.whoami().status == 200


@pytest.mark.parametrize("name,over", [
    ("expired", {"iat": int(time.time()) - 400, "exp": int(time.time()) - 280}),
    ("future-iat", {"iat": int(time.time()) + 300, "exp": int(time.time()) + 420}),
    ("wrong-aud", {"aud": "some-other-dashboard"}),
    ("wrong-iss", {"iss": "exp-manager:other-org"}),
    ("bad-role", {"role": "owner"}),
    ("no-jti", {"jti": None}),
    ("long-lived", {"exp": int(time.time()) + 100000}),
])
def test_bad_claims_refused(world, name, over):
    c = world.client()
    r = _sso(c, world.sso_token(**over))
    assert r.status == 401 and c.cookie is None
    assert world.client().whoami().status == 401


def test_clock_skew_within_60s_is_accepted(world):
    now = int(time.time())
    c = world.client()
    r = _sso(c, world.sso_token(iat=now + 30, exp=now + 150))
    assert r.status == 303


def test_bad_signature_alg_none_and_tamper_refused(world):
    c = world.client()
    assert _sso(c, make_jwt(b"x" * 32)).status == 401                      # wrong secret
    assert _sso(c, make_jwt(world.sso_secret, alg="none")).status == 401   # alg=none
    assert _sso(c, make_jwt(world.sso_secret, alg="HS512")).status == 401  # other algorithm
    good = world.sso_token()
    h, p, s = good.split(".")
    assert _sso(c, f"{h}.{p}x.{s}").status == 401                          # tampered payload
    assert _sso(c, "not-a-jwt").status == 401
    assert _sso(c, "").status == 401
    assert _sso(c, "a." * 5000).status == 401                              # oversize
    assert c.cookie is None


def test_replayed_jti_refused(world):
    token = world.sso_token()
    assert _sso(world.client(), token).status == 303
    c2 = world.client()
    assert _sso(c2, token).status == 401 and c2.cookie is None


def test_token_in_url_query_is_ignored(world):
    token = world.sso_token()
    c = world.client()
    r = c.post(f"/auth/sso?token={token}")
    assert r.status == 401 and c.cookie is None
    r = c.get(f"/auth/sso?token={token}")
    assert r.status in (404, 405) and c.cookie is None
    r = c.post(f"/auth/sso?token={token}", form={"other": "x"})
    assert r.status == 401 and c.cookie is None
    # and the unused token was not consumed by those attempts: it still works from the body
    assert _sso(c, token).status == 303


def test_sso_disabled_without_secret_or_config(make_world):
    w = make_world(sso=False)
    assert _sso(w.client(), w.sso_token()).status == 401
    w2 = make_world()
    (w2.creds / "sso_secret").write_text("")
    w2.app.creds.reload(force=True)
    assert _sso(w2.client(), w2.sso_token()).status == 401


def test_sso_session_ends_when_secret_rotates(world):
    c = world.client()
    _sso(c, world.sso_token())
    assert c.whoami().status == 200
    import base64
    import os
    (world.creds / "sso_secret").write_text(base64.b64encode(os.urandom(32)).decode())
    assert world.wait_for(lambda: c.whoami().status == 401, timeout=10)
