"""fake_manager: agent API conformance and enforcement."""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import http.client
import json
import subprocess
import sys
from pathlib import Path

import pytest
from fakes_support import FAKES, ROOT, check_openapi, check_response_headers, check_schema_file, request
from exp_common import ids as exp_ids
from exp_common import tlspin

import fake_manager
import fakes_common as fc

FIX = ROOT / "test" / "fixtures"
FACTS = json.loads((FIX / "status" / "probe-host.json").read_text())["facts"]
T0 = 1_795_000_000.0


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> float:
        return self.t


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def fake(clock):
    s = fake_manager.start(now_fn=clock, enrol_rate=(1000, 60.0))
    yield s
    s.stop()


def call(fake, method, path, body=None, secret=None, headers=None):
    h = dict(headers or {})
    if secret:
        h["Authorization"] = f"Bearer {secret}"
    return request(fake.port, method, "/api/agent/v1" + path, body, h)


def control(fake, method, path, body=None):
    return request(fake.port, method, "/_fake" + path, body)


def enrolled(fake, desired: str | None = "probe-host", **kw):
    """(host_id, agent_secret) of an enrolled host with a desired state."""
    made = fake.app.add_host(enrolled=True, **kw)
    if desired:
        fake.app.desired_from_fixture(made["host_id"], desired)
    return made["host_id"], made["agent_secret"]


def pending_with_token(fake, ttl=3600.0, token=None):
    made = fake.app.add_host()
    tok = fake.app.issue_enrol_token(made["host_id"], ttl, token)
    return made["host_id"], tok


def do_enrol(fake, tok, facts=FACTS):
    return call(fake, "POST", "/enrol", {"token": tok, "facts": facts})


def openssl_verify(pub_pem: str, message: bytes, sig_b64: str, tmp: Path) -> bool:
    (tmp / "pub.pem").write_text(pub_pem)
    (tmp / "m").write_bytes(message)
    (tmp / "s").write_bytes(base64.b64decode(sig_b64))
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(tmp / "pub.pem"), "-rawin",  # noqa: S603, S607
                        "-in", str(tmp / "m"), "-sigfile", str(tmp / "s")], capture_output=True, timeout=30)
    return r.returncode == 0


# ------------------------------------------------------------------------------------------ enrol

def test_enrol_happy_path_then_secret_works(fake):
    hid, tok = pending_with_token(fake)
    r = do_enrol(fake, tok)
    assert r.status == 201, r.body
    body = r.json()
    check_openapi("agent", "/enrol", "post", 201, body)
    check_response_headers("agent", "/enrol", "post", 201, r.headers)
    assert body["agent_id"] == hid
    assert exp_ids.is_token(body["agent_secret"], "expa")
    assert fake.app.hosts[hid].state == "enrolled"
    d = call(fake, "GET", "/desired", secret=body["agent_secret"])
    assert d.status == 200 and d.json()["host_id"] == hid
    check_schema_file("desired.schema.json", d.json())
    # only the hash is stored
    assert body["agent_secret"] not in json.dumps(fake.app.hosts[hid].__dict__, default=str)


def test_enrol_unknown_token_401_reused_410_expired_410(fake, clock):
    unknown = fc.fixture_token("expe", "nobody")
    r = do_enrol(fake, unknown)
    assert r.status == 401 and r.json()["error"]["code"] == "invalid_token"
    check_openapi("agent", "/enrol", "post", 401, r.json())
    hid, tok = pending_with_token(fake)
    assert do_enrol(fake, tok).status == 201
    again = do_enrol(fake, tok)
    assert again.status == 410 and again.json()["error"]["code"] == "token_used_or_expired"
    check_openapi("agent", "/enrol", "post", 410, again.json())
    hid2, tok2 = pending_with_token(fake, ttl=60)
    clock.t += 61
    exp = do_enrol(fake, tok2)
    assert exp.status == 410
    assert fake.app.hosts[hid2].state == "pending" and fake.app.hosts[hid2].secret_hash is None


def test_enrol_token_for_issued_but_expired_never_yields_secret(fake, clock):
    _, tok = pending_with_token(fake, ttl=-1)
    r = do_enrol(fake, tok)
    assert r.status == 410 and "agent_secret" not in r.body.decode()


def test_enrol_exactly_one_success_under_20_concurrent_attempts(fake):
    hid, tok = pending_with_token(fake)
    with concurrent.futures.ThreadPoolExecutor(20) as ex:
        results = list(ex.map(lambda _: do_enrol(fake, tok), range(20)))
    codes = sorted(r.status for r in results)
    assert codes.count(201) == 1 and codes.count(410) == 19, codes
    assert fake.app.enrol_successes == 1


def test_enrol_concurrent_with_default_rate_limit_still_single_success(clock):
    s = fake_manager.start(now_fn=clock)             # default 10 / min / IP
    try:
        hid, tok = pending_with_token(s)
        with concurrent.futures.ThreadPoolExecutor(20) as ex:
            results = list(ex.map(lambda _: do_enrol(s, tok), range(20)))
        codes = [r.status for r in results]
        assert codes.count(201) <= 1 and set(codes) <= {201, 410, 429}, codes
        assert codes.count(429) >= 10
    finally:
        s.stop()


def test_enrol_rate_limit_per_ip_429_with_retry_after(clock):
    s = fake_manager.start(now_fn=clock, enrol_rate=(10, 60.0))
    try:
        unknown = fc.fixture_token("expe", "nobody")
        for _ in range(10):
            assert do_enrol(s, unknown).status == 401
        r = do_enrol(s, unknown)
        assert r.status == 429 and r.json()["error"]["code"] == "rate_limited"
        check_openapi("agent", "/enrol", "post", 429, r.json())
        assert int(r.h("Retry-After")) >= 1
        clock.t += 61
        assert do_enrol(s, unknown).status == 401      # window slid
    finally:
        s.stop()


@pytest.mark.parametrize("payload", [
    b"not json", b"[]", b"{}", json.dumps({"token": "nope", "facts": FACTS}).encode(),
    json.dumps({"token": fc.fixture_token("expe", "x")}).encode(),
    json.dumps({"token": fc.fixture_token("expe", "x"), "facts": {"hostname": "h"}}).encode(),
    json.dumps({"token": fc.fixture_token("expe", "x"), "facts": {**FACTS, "arch": "mips"}}).encode(),
    json.dumps({"token": fc.fixture_token("expa", "x"), "facts": FACTS}).encode(),
])
def test_enrol_malformed_body_400(fake, payload):
    r = call(fake, "POST", "/enrol", payload, headers={"Content-Type": "application/json"})
    assert r.status == 400
    check_openapi("agent", "/enrol", "post", 400, r.json())


def test_enrol_invalid_facts_consume_nothing(fake):
    hid, tok = pending_with_token(fake)
    assert do_enrol(fake, tok, {"hostname": "x"}).status == 400
    assert do_enrol(fake, tok).status == 201          # token still good: a rejected request does not burn it


def test_enrol_oversize_body_400(fake):
    r = call(fake, "POST", "/enrol", b"x" * 70000, headers={"Content-Type": "application/json"})
    assert r.status == 400


# ----------------------------------------------------------------------------------------- desired

def test_desired_etag_and_304_hot_path(fake):
    hid, sec = enrolled(fake)
    r = call(fake, "GET", "/desired", secret=sec)
    assert r.status == 200
    check_openapi("agent", "/desired", "get", 200, r.json())
    check_response_headers("agent", "/desired", "get", 200, r.headers)
    etag = r.h("ETag")
    ver = r.json()["version"]
    assert etag == f'"{hid}:{ver}"'
    for inm in (etag, f"W/{etag}", f'"zzz", {etag}', "*"):
        n = call(fake, "GET", "/desired", secret=sec, headers={"If-None-Match": inm})
        assert n.status == 304 and n.body == b"" and n.h("ETag") == etag, inm
    miss = call(fake, "GET", "/desired", secret=sec, headers={"If-None-Match": f'"{hid}:{ver - 1}"'})
    assert miss.status == 200
    # a new desired version changes the etag
    et2 = control(fake, "PUT", f"/desired/{hid}", {"fixture": "probe-host"}).json()["etag"]
    assert et2 == f'"{hid}:{ver + 1}"'
    assert call(fake, "GET", "/desired", secret=sec, headers={"If-None-Match": etag}).status == 200
    assert call(fake, "GET", "/desired", secret=sec, headers={"If-None-Match": et2}).status == 304


def test_desired_refuses_missing_wrong_and_other_formats(fake):
    hid, sec = enrolled(fake)
    other = fc.fixture_token("expa", "someone-else")
    for headers in ({}, {"Authorization": "Bearer nope"}, {"Authorization": f"Bearer {other}"},
                    {"Authorization": f"Bearer {fc.fixture_token('expi', 'x')}"}, {"Authorization": sec}):
        r = request(fake.port, "GET", "/api/agent/v1/desired", headers=headers)
        assert r.status == 401, headers
        check_openapi("agent", "/desired", "get", 401, r.json())
        assert sec not in r.body.decode()


def test_each_host_gets_only_its_own_desired(fake):
    h1, s1 = enrolled(fake, name="a")
    h2, s2 = enrolled(fake, name="b")
    assert call(fake, "GET", "/desired", secret=s1).json()["host_id"] == h1
    assert call(fake, "GET", "/desired", secret=s2).json()["host_id"] == h2


def test_desired_fixtures_all_servable_and_valid(fake):
    for f in sorted((FIX / "desired").glob("*.json")):
        if f.stem == "unknown-component-type":
            continue
        hid, sec = enrolled(fake, desired=f.stem)
        r = call(fake, "GET", "/desired", secret=sec)
        assert r.status == 200, f.name
        check_schema_file("desired.schema.json", r.json())


def test_set_desired_rejects_invalid_and_regression(fake):
    hid, sec = enrolled(fake)
    ctl = control(fake, "PUT", f"/desired/{hid}", {"doc": {"schema": "exp.desired/1", "bogus": 1}})
    assert ctl.status == 400
    cur = fake.app.hosts[hid].desired
    fake.app.set_desired(hid, {k: v for k, v in cur.items() if k != "version"})     # -> version 2
    with pytest.raises(ValueError):
        fake.app.set_desired(hid, {**cur, "version": 1})


# ---------------------------------------------------------------------------- releases / artifacts

def test_manifest_exact_bytes_and_real_signature(fake, tmp_path):
    fake.app.add_release("0.1.0")
    hid, tok = pending_with_token(fake)
    pub = do_enrol(fake, tok).json()
    sec = pub["agent_secret"]
    m = call(fake, "GET", "/releases/0.1.0/manifest", secret=sec)
    s = call(fake, "GET", "/releases/0.1.0/manifest.sig", secret=sec)
    assert m.status == 200 and s.status == 200
    check_openapi("agent", "/releases/{version}/manifest", "get", 200, m.json())
    check_openapi("agent", "/releases/{version}/manifest.sig", "get", 200, s.body.decode(), media="text/plain")
    check_schema_file("manifest.schema.json", m.json())
    assert m.body == fake.app.releases["0.1.0"][0]                       # served bytes are the signed bytes
    assert openssl_verify(pub["release_pubkey_pem"], m.body, s.body.decode(), tmp_path)
    assert not openssl_verify(pub["release_pubkey_pem"], m.body + b" ", s.body.decode(), tmp_path)
    tampered = json.loads(m.body)
    tampered["version"] = "9.9.9"
    assert not openssl_verify(pub["release_pubkey_pem"], json.dumps(tampered).encode(), s.body.decode(), tmp_path)


def test_release_endpoints_need_auth_and_404(fake):
    fake.app.add_release("0.1.0")
    hid, sec = enrolled(fake)
    assert request(fake.port, "GET", "/api/agent/v1/releases/0.1.0/manifest").status == 401
    assert request(fake.port, "GET", "/api/agent/v1/releases/0.1.0/manifest.sig").status == 401
    r = call(fake, "GET", "/releases/9.9.9/manifest", secret=sec)
    assert r.status == 404
    check_openapi("agent", "/releases/{version}/manifest", "get", 404, r.json())
    assert call(fake, "GET", "/releases/..%2f..%2fetc/manifest", secret=sec).status == 404
    assert call(fake, "GET", "/releases/not-a-version/manifest.sig", secret=sec).status == 404


def test_artifact_403_unless_referenced_by_this_hosts_desired(fake):
    fake.app.add_release("0.1.0")
    h1, s1 = enrolled(fake, name="a")
    h2, s2 = enrolled(fake, name="b", desired=None)
    fake.app.set_desired(h2, {"schema": "exp.desired/1", "version": 1, "generated_at": "2026-11-18T20:00:00.000Z",
                              "components": [], "decommission": False,
                              "agent": {"version": "0.1.0", "artifact": fc.det_id("art_", "only-for-b")}})
    d1 = call(fake, "GET", "/desired", secret=s1).json()
    art = d1["components"][0]["artifact"]
    ok = call(fake, "GET", f"/artifacts/{art['id']}", secret=s1)
    assert ok.status == 200
    assert ok.h("Content-Length") == str(len(ok.body)) == str(art["size"])
    assert ok.h("ETag") == f'"{art["sha256"]}"' and hashlib.sha256(ok.body).hexdigest() == art["sha256"]
    check_response_headers("agent", "/artifacts/{artifact_id}", "get", 200, ok.headers)
    # host b is not entitled to host a's artifact, nor a's to b's
    forbidden = call(fake, "GET", f"/artifacts/{art['id']}", secret=s2)
    assert forbidden.status == 403 and forbidden.json()["error"]["code"] == "forbidden"
    check_openapi("agent", "/artifacts/{artifact_id}", "get", 403, forbidden.json())
    assert call(fake, "GET", f"/artifacts/{fc.det_id('art_', 'only-for-b')}", secret=s1).status == 403
    for bad in ("art_NOPE", "x", "..%2f..%2fdesired", "art_" + "0" * 26):
        assert call(fake, "GET", f"/artifacts/{bad}", secret=s1).status == 403, bad
    assert request(fake.port, "GET", f"/api/agent/v1/artifacts/{art['id']}").status == 401
    notmod = call(fake, "GET", f"/artifacts/{art['id']}", secret=s1, headers={"If-None-Match": ok.h("ETag")})
    assert notmod.status == 304


def test_artifact_in_desired_matches_release_manifest(fake):
    fake.app.add_release("0.1.0")
    hid, sec = enrolled(fake)
    man = call(fake, "GET", "/releases/0.1.0/manifest", secret=sec).json()
    art = call(fake, "GET", "/desired", secret=sec).json()["components"][0]["artifact"]
    entry = [a for a in man["artifacts"] if a["name"] == art["name"]][0]
    assert entry["sha256"] == art["sha256"] and entry["size"] == art["size"]


# ----------------------------------------------------------------------------------------- status

def test_status_accepts_valid_reports_and_stores(fake):
    hid, sec = enrolled(fake)
    for f in sorted((FIX / "status").glob("*.json")):
        r = call(fake, "POST", "/status", f.read_bytes(), secret=sec, headers={"Content-Type": "application/json"})
        assert r.status == 204 and r.body == b"", f.name
    stored = control(fake, "GET", f"/status/{hid}").json()["reports"]
    assert len(stored) == len(list((FIX / "status").glob("*.json")))
    assert stored[0]["schema"] == "exp.status/1"


def test_status_rejects_invalid_fixtures_and_garbage(fake):
    hid, sec = enrolled(fake)
    bad_files = sorted((FIX / "invalid" / "status").glob("*.json"))
    assert bad_files
    for f in bad_files:
        r = call(fake, "POST", "/status", f.read_bytes(), secret=sec)
        assert r.status == 400, f.name
        check_openapi("agent", "/status", "post", 400, r.json())
        assert r.json()["error"]["details"]["errors"]
    assert call(fake, "POST", "/status", b"not json", secret=sec).status == 400
    assert control(fake, "GET", f"/status/{hid}").json()["reports"] == []


def test_status_size_limit_413(fake):
    hid, sec = enrolled(fake)
    report = json.loads((FIX / "status" / "probe-host.json").read_text())
    report["events"] = [{"ts": "2026-11-18T20:00:00.000Z", "level": "info", "msg": "x" * 1000}] * 300   # > 256 KiB
    body = json.dumps(report).encode()
    assert len(body) > 256 * 1024
    r = call(fake, "POST", "/status", body, secret=sec)
    assert r.status == 413
    check_openapi("agent", "/status", "post", 413, r.json())
    ok = (FIX / "status" / "probe-host.json").read_bytes()
    assert call(fake, "POST", "/status", ok, secret=sec).status == 204
    assert request(fake.port, "POST", "/api/agent/v1/status", ok).status == 401


# ------------------------------------------------------------------------------- rotate / decommission

def test_rotate_requires_action_then_grace_period(fake, clock):
    hid, sec = enrolled(fake, desired="probe-host")
    r = call(fake, "POST", "/rotate", {}, secret=sec)
    assert r.status == 409
    assert r.json()["error"]["code"] == "rotation_not_requested"      # CR-wp4-rotate-409-code
    check_openapi("agent", "/rotate", "post", 409, r.json())
    control(fake, "PUT", f"/desired/{hid}", {"fixture": "rotate"})
    assert call(fake, "GET", "/desired", secret=sec).json()["actions"][0]["type"] == "rotate_agent_secret"
    bad = call(fake, "POST", "/rotate", {"x": 1}, secret=sec)
    assert bad.status == 400
    r = call(fake, "POST", "/rotate", {}, secret=sec)
    assert r.status == 200
    body = r.json()
    check_openapi("agent", "/rotate", "post", 200, body)
    check_response_headers("agent", "/rotate", "post", 200, r.headers)
    assert body["grace_s"] == 600 and body["agent_secret"] != sec
    new = body["agent_secret"]
    # both secrets work inside the grace window ...
    assert call(fake, "GET", "/desired", secret=sec).status == 200
    assert call(fake, "GET", "/desired", secret=new).status == 200
    clock.t += 599
    assert call(fake, "GET", "/desired", secret=sec).status == 200
    clock.t += 2
    assert call(fake, "GET", "/desired", secret=sec).status == 401     # ... the old one dies after grace_s
    assert call(fake, "GET", "/desired", secret=new).status == 200
    # the action was consumed, so a second rotation is refused until a new action is issued
    assert call(fake, "POST", "/rotate", {}, secret=new).status == 409
    assert request(fake.port, "POST", "/api/agent/v1/rotate", {}).status == 401


def test_decommissioned_requires_flag_then_revokes_credentials(fake):
    hid, sec = enrolled(fake)
    r = call(fake, "POST", "/decommissioned", {}, secret=sec)
    assert r.status == 409
    check_openapi("agent", "/decommissioned", "post", 409, r.json())
    control(fake, "PUT", f"/desired/{hid}", {"fixture": "decommission"})
    assert call(fake, "GET", "/desired", secret=sec).json()["decommission"] is True
    assert call(fake, "POST", "/decommissioned", {"junk": 1}, secret=sec).status == 400
    r = call(fake, "POST", "/decommissioned", {}, secret=sec)
    assert r.status == 204 and r.body == b""
    assert call(fake, "GET", "/desired", secret=sec).status == 401
    assert call(fake, "POST", "/status", (FIX / "status" / "probe-host.json").read_bytes(), secret=sec).status == 401
    assert fake.app.hosts[hid].state == "removed"


def test_previous_secret_revoked_by_decommission_too(fake):
    hid, sec = enrolled(fake)
    control(fake, "PUT", f"/desired/{hid}", {"fixture": "rotate"})
    new = call(fake, "POST", "/rotate", {}, secret=sec).json()["agent_secret"]
    control(fake, "PUT", f"/desired/{hid}", {"fixture": "decommission"})
    assert call(fake, "POST", "/decommissioned", {}, secret=new).status == 204
    assert call(fake, "GET", "/desired", secret=sec).status == 401
    assert call(fake, "GET", "/desired", secret=new).status == 401


# --------------------------------------------------------------------------- control / install.sh

def test_forced_5xx_and_unreachable_then_recovery(fake):
    hid, sec = enrolled(fake)
    assert control(fake, "POST", "/force", {"status": 503, "count": 2, "retry_after": 5}).status == 200
    for _ in range(2):
        r = call(fake, "GET", "/desired", secret=sec)
        assert r.status == 503 and r.h("Retry-After") == "5"
        check_openapi("agent", "/desired", "get", 503, r.json())
    assert call(fake, "GET", "/desired", secret=sec).status == 200
    control(fake, "POST", "/force", {"status": 500, "count": 1})
    r = call(fake, "GET", "/desired", secret=sec)
    assert r.status == 500 and r.json()["error"]["code"] == "internal_error"
    control(fake, "POST", "/force", {"unreachable": True, "count": 1})
    with pytest.raises((http.client.RemoteDisconnected, ConnectionError, http.client.BadStatusLine)):
        call(fake, "GET", "/desired", secret=sec)
    assert call(fake, "GET", "/desired", secret=sec).status == 200
    assert control(fake, "POST", "/force", {"status": 404}).status == 400


def test_control_issues_enrol_tokens_and_reports(fake):
    made = control(fake, "POST", "/hosts", {"name": "srv-09", "site": "hall-c"}).json()
    tok = control(fake, "POST", "/enrol-token", {"host_id": made["host_id"]}).json()
    assert exp_ids.is_token(tok["token"], "expe")
    assert do_enrol(fake, tok["token"]).status == 201
    hosts = control(fake, "GET", "/hosts").json()["items"]
    assert hosts[0]["state"] == "enrolled"
    assert control(fake, "POST", "/enrol-token", {"host_id": "h_nope"}).status == 400
    assert control(fake, "GET", "/nothing").status == 404


def test_control_disabled_is_refused():
    s = fake_manager.start(control=False)
    try:
        assert control(s, "GET", "/hosts").status == 403
    finally:
        s.stop()


def test_install_sh_placeholder_and_custom(tmp_path):
    s = fake_manager.start()
    try:
        r = request(s.port, "GET", "/install.sh")
        assert r.status == 200 and r.h("Content-Type").startswith("text/x-shellscript")
        check_openapi("agent", "/install.sh", "get", 200, r.body.decode(), media="text/x-shellscript")
        assert r.body.startswith(b"#!/bin/sh") and b"expe_" not in r.body
        assert request(s.port, "GET", "/healthz").body == b"ok"
    finally:
        s.stop()
    script = tmp_path / "install.sh"
    script.write_text("#!/bin/sh\necho custom\n")
    s = fake_manager.start(install_sh=script)
    try:
        assert request(s.port, "GET", "/install.sh").body == b"#!/bin/sh\necho custom\n"
    finally:
        s.stop()


def test_default_scenario_is_usable_end_to_end(tmp_path):
    s = fake_manager.start(scenario="default", state_dir=tmp_path)
    try:
        info = s.scenario_info
        d = call(s, "GET", "/desired", secret=info["agent_secret"])
        assert d.status == 200 and d.json()["components"][0]["type"] == "probe"
        e = do_enrol(s, info["enrol_token"])
        assert e.status == 201 and e.json()["agent_id"] == info["pending_host"]
        art = d.json()["components"][0]["artifact"]
        assert call(s, "GET", f"/artifacts/{art['id']}", secret=info["agent_secret"]).status == 200
        assert (tmp_path / "release-key" / "release-pub.pem").is_file()
    finally:
        s.stop()


def test_state_dir_scenario_files_are_loaded(tmp_path):
    (tmp_path / "hosts.json").write_text(json.dumps([{"name": "srv-07", "site": "hall-b", "enrolled": True,
                                                       "agent_secret": fc.fixture_token("expa", "srv-07"),
                                                       "desired": "all-in-one"}]))
    s = fake_manager.start(state_dir=tmp_path)
    try:
        r = call(s, "GET", "/desired", secret=fc.fixture_token("expa", "srv-07"))
        assert r.status == 200 and {c["type"] for c in r.json()["components"]} == {"collector", "dashboard", "probe"}
    finally:
        s.stop()


def test_tls_pinned(tmp_path):
    s = fake_manager.start(tls=True, state_dir=tmp_path)
    try:
        assert tlspin.request("GET", f"https://127.0.0.1:{s.port}/healthz", s.fingerprint, total_timeout=10).body == b"ok"
        with pytest.raises(tlspin.PinMismatch):
            tlspin.request("GET", f"https://127.0.0.1:{s.port}/healthz", "11:" * 31 + "11", total_timeout=10)
    finally:
        s.stop()


def test_cli_runs_as_script():
    proc = subprocess.Popen([sys.executable, str(FAKES / "fake_manager.py"), "--listen", "127.0.0.1:0",  # noqa: S603
                             "--scenario", "default"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        first = proc.stdout.readline().strip()
        port = int(first.rsplit(":", 1)[1])
        assert request(port, "GET", "/healthz").body == b"ok"
        lines = [proc.stdout.readline() for _ in range(5)]
        assert any("enrol_token: expe_" in x for x in lines)
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_method_and_path_errors(fake):
    hid, sec = enrolled(fake)
    assert call(fake, "POST", "/desired", {}, secret=sec).status == 405
    assert call(fake, "GET", "/enrol").status == 405
    assert call(fake, "GET", "/nope", secret=sec).status == 404
