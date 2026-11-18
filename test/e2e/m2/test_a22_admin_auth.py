"""A2.2 - the admin API refuses requests without a valid Access JWT, even if Access were bypassed.

ENFORCEMENT test (05-manager.md section 5 / 15 item 1): every request goes DIRECTLY to the Worker (no Cloudflare
Access in front), carrying only what an attacker who can reach the Worker could send. The Worker must verify the
JWT itself: RS256 signature against the JWKS of ACCESS_TEAM_DOMAIN, aud, iss, exp/nbf, then map the e-mail to
`admins`. The positive case proves the same code path accepts a genuine token, so the 401s are not a
misconfiguration artefact (a Worker that rejected everything would fail it).
"""

from __future__ import annotations

import base64
import json

import pytest

from conftest import AUD, OWNER

ME = "/api/admin/v1/me"


def _get(stack, token: str | None = None, headers: dict[str, str] | None = None):
    h = dict(headers or {})
    if token is not None:
        h["Cf-Access-Jwt-Assertion"] = token
    return stack.mgr.request("GET", ME, headers=h)


def _is_unauth(r) -> bool:
    return r.status == 401 and r.json()["error"]["code"] == "unauthenticated"


def test_valid_jwt_for_the_owner_is_200(stack):
    r = _get(stack, stack.token(OWNER))
    assert r.status == 200, r
    assert r.json() == {"email": OWNER, "role": "owner"}
    # the Worker really fetched the JWKS from the local issuer over HTTPS (the CA is trusted by the runtime only)
    assert "/cdn-cgi/access/certs" in stack.jwks.hits


def test_no_jwt_is_401(stack):
    assert _is_unauth(_get(stack))


def test_identity_headers_without_a_jwt_are_401(stack):
    """Cf-Access-Authenticated-User-Email is never trusted by itself (05 section 5 step 2)."""
    r = _get(stack, headers={"Cf-Access-Authenticated-User-Email": OWNER, "X-Forwarded-User": OWNER})
    assert _is_unauth(r)
    # ...and neither does it rescue an invalid token
    assert _is_unauth(_get(stack, "garbage", {"Cf-Access-Authenticated-User-Email": OWNER}))


def test_forged_jwt_signed_with_another_key_is_401(stack):
    """Same kid, same claims, but signed by a key that is not in the team's JWKS."""
    forged = stack.issuer.mint(OWNER, key=stack.issuer.forger)
    assert _is_unauth(_get(stack, forged))


def test_unknown_kid_is_401(stack):
    tok = stack.issuer.mint(OWNER)
    head, body, sig = tok.split(".")
    h = json.loads(base64.urlsafe_b64decode(head + "=="))
    h["kid"] = "no-such-kid"
    bad_head = base64.urlsafe_b64encode(json.dumps(h).encode()).rstrip(b"=").decode()
    assert _is_unauth(_get(stack, f"{bad_head}.{body}.{sig}"))


def test_tampered_claims_are_401(stack):
    """A genuine signature over different claims: swap the e-mail for another one after signing."""
    head, body, sig = stack.token("viewer@e2e.test").split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["email"] = OWNER
    nb = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    assert _is_unauth(_get(stack, f"{head}.{nb}.{sig}"))


def test_wrong_audience_is_401(stack):
    assert _is_unauth(_get(stack, stack.issuer.mint(OWNER, aud="some-other-application-aud")))
    assert _is_unauth(_get(stack, stack.issuer.mint(OWNER, aud=[])))


def test_wrong_issuer_is_401(stack):
    assert _is_unauth(_get(stack, stack.issuer.mint(OWNER, iss="https://evil.example.test")))


def test_expired_jwt_is_401(stack):
    assert _is_unauth(_get(stack, stack.issuer.mint(OWNER, exp_in=-3600)))


def test_not_yet_valid_jwt_is_401(stack):
    assert _is_unauth(_get(stack, stack.issuer.mint(OWNER, nbf_in=3600)))


@pytest.mark.parametrize("alg", ["none", "HS256"])
def test_algorithm_confusion_is_401(stack, alg):
    good = stack.issuer.mint(OWNER)
    _, body, _ = good.split(".")
    head = base64.urlsafe_b64encode(json.dumps({"alg": alg, "kid": stack.issuer.key.kid}).encode()).rstrip(b"=").decode()
    assert _is_unauth(_get(stack, f"{head}.{body}."))
    assert _is_unauth(_get(stack, f"{head}.{body}.{'A' * 43}"))


def test_unknown_but_validly_signed_admin_is_403(stack):
    """Authentication succeeded, authorisation did not: only EXP_OWNER_EMAIL is created on first sign-in."""
    r = _get(stack, stack.token("stranger@e2e.test"))
    assert r.status == 403 and r.json()["error"]["code"] == "unknown_admin", r


def test_every_admin_route_family_enforces_the_jwt(stack):
    """Not just /me: a mutation and a read on other route families are 401 with no JWT / a forged one."""
    forged = stack.issuer.mint(OWNER, key=stack.issuer.forger)
    for method, path in (
        ("GET", "/api/admin/v1/sites"),
        ("POST", "/api/admin/v1/sites"),
        ("GET", "/api/admin/v1/hosts"),
        ("POST", "/api/admin/v1/releases/upload"),
        ("GET", "/api/admin/v1/audit"),
    ):
        for hdrs in ({}, {"Cf-Access-Jwt-Assertion": forged}):
            r = stack.mgr.request(method, path, headers=dict(hdrs), body=b"{}" if method == "POST" else None)
            assert r.status == 401, (method, path, bool(hdrs), r)
    assert AUD  # the audience the genuine tokens carry is configured; wrong ones above are refused
