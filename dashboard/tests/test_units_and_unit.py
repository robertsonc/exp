"""systemd unit template and pure-function checks."""
from __future__ import annotations

import re
import time

import pytest
from exp_dashboard import config as dcfg
from exp_dashboard.auth import AuthError, JtiCache, LoginThrottle, Throttled, verify_sso_token

from conftest import ROOT, make_jwt

UNIT = (ROOT / "dashboard" / "systemd" / "exp-dashboard.service").read_text()


def directives(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line and not line.startswith(("#", "[")) and "=" in line:
            k, _, v = line.partition("=")
            out.setdefault(k.strip(), []).append(v.strip())
    return out


def test_unit_hardening_matches_spec():
    d = directives(UNIT)
    assert d["User"] == ["exp-dashboard"]
    assert d["AmbientCapabilities"] == ["CAP_NET_BIND_SERVICE"]
    assert d["CapabilityBoundingSet"] == ["CAP_NET_BIND_SERVICE"]
    assert d["ProtectSystem"] == ["strict"]
    assert d["NoNewPrivileges"] == ["yes"] and d["PrivateTmp"] == ["yes"]
    assert d["RestrictAddressFamilies"] == ["AF_INET AF_INET6 AF_UNIX"]
    assert "@STATE@" in d["ReadWritePaths"][0]
    assert d["ExecStart"] == ["@PREFIX@/bin/exp-dashboard run --config @CONFIG@"]
    assert d["StateDirectory"] == ["exp/dashboard"] and d["RuntimeDirectory"] == ["exp/dashboard"]
    assert d["MemoryDenyWriteExecute"] == ["yes"] and d["UMask"] == ["0077"]


def test_unit_loads_every_credential_and_uses_only_known_placeholders():
    d = directives(UNIT)
    creds = {c.split(":")[0]: c.split(":")[1] for c in d["LoadCredential"]}
    assert set(creds) == {"collector_tokens.json", "sso_secret", "local_users.json", "noc_tokens.json",
                          "tls.key", "tls.crt"}
    assert all(v == f"@CREDS@/{k}" for k, v in creds.items())
    assert set(re.findall(r"@[A-Z]+@", UNIT)) <= {"@VERSION@", "@PREFIX@", "@CONFIG@", "@CREDS@", "@STATE@",
                                                  "@RUN@"}
    assert "shell" not in UNIT.lower() and "/bin/sh" not in UNIT


def test_settings_defaults_and_origin(tmp_path):
    p = ROOT / "test/fixtures/configs/dashboard.json"
    s = dcfg.load_settings(p, state_dir=tmp_path / "s", creds_dir=tmp_path / "c", run_dir=tmp_path / "r")
    assert s.https == ("0.0.0.0", 443) and s.http_redirect == ("0.0.0.0", 80)
    assert s.origin == "https://10.32.98.30" and s.tls_cert == tmp_path / "s" / "tls" / "cert.pem"
    assert s.sessions_db == tmp_path / "s" / "sessions.db"
    prov = dcfg.load_settings(ROOT / "test/fixtures/configs/dashboard.tls-provided.json", state_dir=tmp_path / "s",
                              creds_dir=tmp_path / "c", run_dir=tmp_path / "r")
    assert prov.tls_mode == "provided" and prov.tls_cert == tmp_path / "c" / "tls.crt"
    assert dcfg.origin_of("https://h.example:8443/x") == "https://h.example:8443"


def test_throttle_unit():
    t = [1000.0]
    th = LoginThrottle(clock=lambda: t[0])
    for _ in range(5):
        th.check("Bob", "1.1.1.1")
        th.fail("Bob", "1.1.1.1")
    with pytest.raises(Throttled) as e:
        th.check("bob", "9.9.9.9")
    assert 800 < e.value.retry_after <= 900
    th.check("carol", "9.9.9.9")
    assert th.failures_last_hour() == 5
    t[0] += 3601
    assert th.failures_last_hour() == 0


def test_jti_cache_ttl_and_bound():
    t = [0.0]
    c = JtiCache(clock=lambda: t[0], limit=4)
    assert c.consume("a") and not c.consume("a")
    t[0] = 601
    assert c.consume("a")                                   # 10 minutes later it may be seen again
    for i in range(10):
        c.consume(f"x{i}")
    assert not c.consume("brand-new-while-full")            # fails closed under flood


def test_verify_sso_token_unit():
    secret = b"k" * 32
    now = time.time()
    kw = {"issuer": "exp-manager:default", "audience": "dash-main", "now": now}
    claims = verify_sso_token(make_jwt(secret), secret, **kw)
    assert claims.sub == "admin@example.com" and claims.role == "admin"
    for bad in (make_jwt(secret, role="root"), make_jwt(secret, sub=""), make_jwt(secret, sub="a\nb"),
                make_jwt(secret, exp="soon"), make_jwt(secret, exp=True), make_jwt(secret, aud=["dash-main"]),
                make_jwt(secret, jti=5), make_jwt(b"z" * 32)):
        with pytest.raises(AuthError):
            verify_sso_token(bad, secret, **kw)
