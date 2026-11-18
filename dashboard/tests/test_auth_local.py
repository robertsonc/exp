"""Local accounts, throttling, NOC exchange, logout, credential reload (spec section 7 items 2)."""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import time

from exp_dashboard.auth import hash_password, parse_hash, verify_password

from conftest import ROOT

MSG_BAD = "username or password is wrong"


def test_local_login_and_session(world):
    c = world.client()
    r = c.login("alice", "alice-pass-1")
    assert r.status == 200 and r.json()["role"] == "operator"
    assert r.set_cookies[0].startswith("__Host-exp_session=") and "SameSite=Lax" in r.set_cookies[0]
    who = c.whoami().json()
    assert who["user"] == "alice" and who["kind"] == "local"


def test_login_failures_are_generic_and_identical(world):
    c = world.client()
    bad_pw = c.post("/auth/login", json_body={"username": "alice", "password": "nope"})
    no_user = c.post("/auth/login", json_body={"username": "ghost", "password": "nope"})
    assert bad_pw.status == no_user.status == 401
    assert bad_pw.json() == no_user.json()
    assert MSG_BAD in bad_pw.body.decode()
    assert c.cookie is None
    for body in ({}, {"username": "alice"}, {"username": 5, "password": ["x"]}, {"username": "", "password": ""}):
        assert c.post("/auth/login", json_body=body).status == 401


def test_form_login_redirects(world):
    c = world.client()
    ok = c.post("/auth/login", form={"username": "vera", "password": "vera-pass-1"})
    assert ok.status == 303 and ok.headers["location"] == "/" and c.cookie
    c2 = world.client()
    bad = c2.post("/auth/login", form={"username": "vera", "password": "x"})
    assert bad.status == 303 and bad.headers["location"] == "/auth/login?e=1" and c2.cookie is None
    page = c2.get("/auth/login?e=1")
    assert page.status == 200 and "Username or password is wrong." in page.body.decode()
    assert "<script" not in page.body.decode()


def test_login_page_escapes_and_ignores_unknown_error_codes(world):
    page = world.client().get("/auth/login?e=%3Cscript%3E")
    assert page.status == 200 and "<script>" not in page.body.decode()


def test_throttle_per_username_429_even_with_correct_password(world):
    c = world.client()
    for _ in range(5):
        assert c.post("/auth/login", json_body={"username": "alice", "password": "wrong"}).status == 401
    r = c.post("/auth/login", json_body={"username": "alice", "password": "alice-pass-1"})
    assert r.status == 429 and int(r.headers["retry-after"]) > 0
    assert c.cookie is None
    # another user is not locked out
    assert c.login("vera", "vera-pass-1").status == 200
    # username match is case-insensitive for throttling purposes
    assert c.post("/auth/login", json_body={"username": "ALICE", "password": "alice-pass-1"}).status == 429


def test_throttle_per_ip_20(world):
    c = world.client()
    for i in range(20):
        assert c.post("/auth/login", json_body={"username": f"user{i}", "password": "x"}).status == 401
    assert c.post("/auth/login", json_body={"username": "vera", "password": "vera-pass-1"}).status == 429
    assert c.cookie is None


def test_throttle_window_expires(world):
    t = [time.time()]
    world.app.auth.throttle._clock = lambda: t[0]
    c = world.client()
    for _ in range(5):
        c.post("/auth/login", json_body={"username": "alice", "password": "wrong"})
    assert c.post("/auth/login", json_body={"username": "alice", "password": "alice-pass-1"}).status == 429
    t[0] += 15 * 60 + 1
    assert c.post("/auth/login", json_body={"username": "alice", "password": "alice-pass-1"}).status == 200


def test_login_failures_counted_for_health(world):
    c = world.client()
    c.post("/auth/login", json_body={"username": "alice", "password": "wrong"})
    assert world.app.health()["metrics"]["login_failures_1h"] == 1


def test_password_hash_format_and_verify():
    h = hash_password("s3cret", 100_000)
    scheme, iters, salt, dk = h.split("$")
    assert scheme == "pbkdf2_sha256" and iters == "100000" and parse_hash(h)
    assert verify_password("s3cret", h) and not verify_password("S3cret", h)
    assert not verify_password("s3cret", "plaintext") and not verify_password("s3cret", "pbkdf2_sha256$1$aa$bb")
    assert not verify_password("x" * 5000, h)


def test_hash_password_cli_reads_stdin():
    out = subprocess.run([sys.executable, str(ROOT / "dashboard/bin/exp-dashboard"), "hash-password",
                          "--iterations", "100000"], input="hunter2\n", capture_output=True, text=True,
                         timeout=60, check=True)
    h = out.stdout.strip()
    assert verify_password("hunter2", h) and "hunter2" not in out.stdout + out.stderr


def test_logout_requires_csrf_and_ends_session(world):
    c = world.as_user("vera")
    assert c.post("/auth/logout", csrf=False).status == 403
    assert c.post("/auth/logout", origin="https://evil.example").status == 403
    assert c.whoami().status == 200                      # still signed in
    r = c.post("/auth/logout")
    assert r.status == 204 and "Max-Age=0" in r.set_cookies[0]
    assert c.cookie is None
    assert c.whoami().status == 401


def test_logged_out_cookie_is_dead_server_side(world):
    c = world.as_user("vera")
    old = c.cookie
    c.post("/auth/logout")
    c.cookie = old
    assert c.whoami().status == 401


def test_removed_user_session_ends_within_30s_of_creds_update(world):
    alice, vera = world.as_user("alice"), world.as_user("vera")
    assert alice.whoami().status == 200
    t0 = time.time()
    world.write_creds(users=["vera"])                    # alice removed
    assert world.wait_for(lambda: alice.whoami().status == 401, timeout=30)
    assert time.time() - t0 < 30
    assert vera.whoami().status == 200                   # unaffected
    assert world.client().post("/auth/login", json_body={"username": "alice",
                                                          "password": "alice-pass-1"}).status == 401


def test_password_change_and_role_change_invalidate_sessions(world):
    vera = world.as_user("vera")
    users = json.loads((world.creds / "local_users.json").read_text())
    for u in users:
        if u["username"] == "vera":
            u["role"] = "operator"
    (world.creds / "local_users.json").write_text(json.dumps(users))
    assert world.wait_for(lambda: vera.whoami().status == 401, timeout=10)


def test_corrupt_credentials_fail_closed(world):
    alice = world.as_user("alice")
    (world.creds / "local_users.json").write_text("{not json")
    assert world.wait_for(lambda: alice.whoami().status == 401, timeout=10)
    assert world.client().post("/auth/login", json_body={"username": "alice",
                                                          "password": "alice-pass-1"}).status == 401


def test_local_admin_role_is_downgraded(world):
    users = json.loads((world.creds / "local_users.json").read_text())
    users.append({"username": "root-ish", "role": "admin", "hash": world.hashes["bob"]})
    (world.creds / "local_users.json").write_text(json.dumps(users))
    world.app.creds.reload(force=True)
    c = world.client()
    r = c.login("root-ish", "bob-pass-1")
    assert r.json()["role"] == "operator"


def test_sessions_expire(make_world):
    w = make_world(session_hours=1)
    c = w.as_user("vera")
    assert c.whoami().status == 200
    w.offset = 3600 + 5
    assert c.whoami().status == 401


# ----------------------------------------------------------------------------------------- NOC

def test_noc_exchange_issues_read_only_session(world):
    c = world.client()
    r = c.noc(world.noc_token)
    assert r.status == 200 and r.json()["role"] == "viewer" and r.json()["kind"] == "noc"
    assert c.whoami().json()["user"] == "noc:noc-1"
    assert c.get("/api/v1/probes").status == 200


def test_noc_bad_tokens_refused(world):
    from exp_common import ids
    c = world.client()
    for tok in (ids.new_token("expn"), "expn_short", "x", world.noc_token + "A", "", 5, None):
        r = c.post("/auth/noc", json_body={"token": tok})
        assert r.status == 401, tok
    assert c.cookie is None


def test_noc_token_in_query_or_wrong_type_ignored(world):
    c = world.client()
    assert c.post(f"/auth/noc?token={world.noc_token}").status == 401
    assert c.post(f"/auth/noc?t={world.noc_token}", json_body={}).status == 401
    # an expd_/expi_ token does not become a NOC token
    from exp_common import ids
    assert c.post("/auth/noc", json_body={"token": ids.new_token("expd")}).status == 401


def test_noc_expired_token_refused_and_session_ends_on_expiry(world, tmp_path):
    from exp_common import ids
    tok = ids.new_token("expn")
    soon = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3))
    world.write_creds(noc=[{"id": "noc-9", "sha256": ids.token_hash(tok), "label": "x", "role": "viewer",
                            "expires": soon}])
    world.app.creds.reload(force=True)
    c = world.client()
    assert c.noc(tok).status == 200
    assert world.wait_for(lambda: c.whoami().status == 401, timeout=15)
    assert world.client().post("/auth/noc", json_body={"token": tok}).status == 401
    past = "2001-01-01T00:00:00Z"
    world.write_creds(noc=[{"id": "noc-8", "sha256": ids.token_hash(tok), "label": "x", "role": "viewer",
                            "expires": past}])
    world.app.creds.reload(force=True)
    assert world.client().post("/auth/noc", json_body={"token": tok}).status == 401


def test_noc_token_revoked_by_creds_update(world):
    c = world.client()
    c.noc(world.noc_token)
    world.write_creds(noc=[])
    assert world.wait_for(lambda: c.whoami().status == 401, timeout=10)


def test_noc_sessions_renew_while_in_use(make_world):
    w = make_world(session_hours=1)
    c = w.client()
    c.noc(w.noc_token)
    w.offset = 40 * 60
    assert c.whoami().status == 200                     # renewed to now+1h
    w.offset = 80 * 60
    assert c.whoami().status == 200                     # would have expired at 60 min without renewal
    # local sessions do not slide
    v = w.as_user("vera")
    w.offset = 80 * 60 + 40 * 60
    assert v.whoami().status == 200
    w.offset = 80 * 60 + 61 * 60
    assert v.whoami().status == 401


def test_noc_viewer_cannot_acknowledge(world):
    c = world.client()
    c.noc(world.noc_token)
    r = c.post("/api/v1/incidents/inc_01M7R3X9G0NTM2HDJYD21Y49WH/ack")
    assert r.status == 403 and r.json()["error"]["code"] == "insufficient_role"


def test_noc_page_reads_fragment_and_posts_body(world):
    c = world.client()
    js = c.get("/noc.js")
    assert js.status == 200 and "location.hash" in js.body.decode() and "/auth/noc" in js.body.decode()
    assert "?token=" not in js.body.decode() and "?t=" not in js.body.decode()
    page = c.get("/noc")
    assert page.status == 200 and "noc.js" in page.body.decode()


def test_noc_token_never_reaches_logs(world, caplog, capsys):
    """Exchange good and bad NOC tokens and logins with DEBUG logging everywhere, then scan every log
    record and captured stream for the token (SR-14)."""
    caplog.set_level(logging.DEBUG)
    root = logging.getLogger()
    old = root.level
    root.setLevel(logging.DEBUG)
    try:
        c = world.client()
        assert c.noc(world.noc_token).status == 200
        bad = world.noc_token[:-1] + ("A" if world.noc_token[-1] != "A" else "B")
        world.client().post("/auth/noc", json_body={"token": bad})
        world.client().post(f"/auth/noc?token={world.noc_token}")
        world.client().post("/auth/login", json_body={"username": "alice", "password": "alice-pass-1"})
        world.client().post("/auth/login", json_body={"username": "alice", "password": "bad-password-xyz"})
        sso = world.sso_token()
        world.client().post("/auth/sso", form={"token": sso})
        world.client().post("/auth/sso", form={"token": sso})
    finally:
        root.setLevel(old)
    out = capsys.readouterr()
    haystack = "\n".join([r.getMessage() + " " + repr(r.args) + " " + str(r.exc_text) for r in caplog.records]
                         + [caplog.text, out.out, out.err])
    secrets_ = [world.noc_token, bad, "alice-pass-1", "bad-password-xyz", sso, sso.split(".")[2],
                world.noc_token[5:]]
    for s in secrets_:
        assert s not in haystack
    assert "expn_" not in haystack.replace("expn_[REDACTED]", "")
    assert any("noc session started" in r.getMessage() for r in caplog.records)   # events are logged, tokens not


def test_noc_tokens_file_stores_only_hashes(world):
    raw = (world.creds / "noc_tokens.json").read_text()
    assert world.noc_token not in raw
