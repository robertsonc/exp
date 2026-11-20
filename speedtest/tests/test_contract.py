"""Every route of shared/openapi/speedtest.yaml is implemented with the documented methods and the documented credential."""
from __future__ import annotations

import oas
import pytest
from exp_common import speedtest as st
from stbox import Box

SID = "st_01M7R3X9G0QWCYM3A3S1DE8MT4"
PATHS = [(p, [m.upper() for m in ops if m in ("get", "post", "put")], ops) for p, ops in oas.DOC["paths"].items()]


def concrete(path: str) -> str:
    return path.replace("{id}", SID).replace("{name}", "logo")


@pytest.mark.parametrize("path,methods,_ops", [x for x in PATHS if not x[0].startswith("/local/")], ids=lambda x: x if isinstance(x, str) else "")
def test_public_route_exists_with_exactly_the_documented_methods(box: Box, path, methods, _ops):
    r = box.request("PATCH", concrete(path))
    assert r.status == 405, f"{path} is not implemented (PATCH gave {r.status})"
    allow = {a.strip() for a in r.h("allow").split(",")}
    assert set(methods) <= allow, (path, methods, allow)
    assert allow <= set(methods) | {"HEAD", "OPTIONS"}, (path, allow)


@pytest.mark.parametrize("path,methods,_ops", [x for x in PATHS if x[0].startswith("/local/")], ids=lambda x: x if isinstance(x, str) else "")
def test_channel_route_exists_on_the_channel_listener(box: Box, path, methods, _ops):
    r = box.channel("PATCH", path)
    assert r.status == 405 and set(methods) == {a.strip() for a in r.h("allow").split(",")}


def test_documented_credentials_are_enforced_per_operation(box: Box):
    s = box.new_session()
    for path, methods, ops in PATHS:
        if path.startswith("/local/") or path in ("/st/px",):
            continue
        for m in methods:
            sec = ops[m.lower()].get("security", [])
            body = {"action": "acquire"} if "internet-slot" in path else ({"comment": "x"} if "comment" in path else None)
            if sec == [{"legToken": []}]:
                q = "?bytes=10" if path == "/st/down" else ""
                r = box.request(m, path + q, body, headers={})
                assert r.status == 401, (m, path, r.status)
            elif sec == [{"viewProof": []}]:
                r = box.request(m, concrete(path), body, headers={})
                assert r.status == 404, (m, path, r.status)
            elif sec == []:
                r = box.request(m, concrete(path) if "{" in path else path, body, headers={})
                assert r.status != 401 and r.status != 403, (m, path, r.status)
    assert s.sid


def test_error_codes_used_are_the_documented_vocabulary(box: Box):
    documented = set()
    for resp in oas.DOC["components"]["responses"].values():
        for ex in resp["content"]["application/json"].get("examples", {}).values():
            documented.add(ex["value"]["error"]["code"])
    s = box.new_session()
    seen = set()
    probes = [box.get("/st/ping"), box.get("/st/down?bytes=0", headers=s.leg), box.get(f"/st/api/v1/sessions/{SID}"),
              box.post("/st/api/v1/sessions", {}), box.post("/st/api/v1/sessions", {"consent": {"text_version": 1}, "view_verifier": "a" * 64}),
              box.get("/st/down?bytes=99999999", headers=s.leg), box.channel("GET", "/local/v1/where/wanted", src="127.0.0.2")]
    for r in probes:
        seen.add(r.json()["error"]["code"])
    assert seen <= documented | {"rate_limited", "budget_exceeded", "method_not_allowed", "not_implemented", "payload_too_large"}, seen - documented


def test_no_route_accepts_a_person_identity_field(box: Box):
    assert st.MAX_COMMENT_CHARS == 500
    for field in ("name", "email", "phone", "username", "user", "account"):
        r = box.post("/st/api/v1/sessions", {"consent": {"text_version": 3}, "view_verifier": "a" * 64, field: "x"})
        assert r.status == 400, field
