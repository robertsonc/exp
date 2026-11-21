"""A6.1: a phone runs a test from a zone QR link on the routed core layout; both legs; score + diagnosis in <= 20 s; 390-px
layout without horizontal scroll; CSP present; comment XSS inert (12-speedtest-analytics.md section 11)."""
from __future__ import annotations

import json

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e
XSS = "<img src=x onerror=alert(1)><script>alert(2)</script>\"'>${7*7}{{7*7}}"


def test_a61_phone_runs_test_from_zone_qr(core: M.Core, phone: M.Client, artifacts):
    r = phone.chromium({"name": "a61", "url": f"{core.page}/?z=hall-b", "report": XSS, "waitChecksMs": 90000, "copy": True,
                        "shotPre": "a61-01-start-390", "shotResults": "a61-02-results-390", "shotFinal": "a61-03-final-390"})
    first, final = r["first"], r["final"]
    # --- page quality on a 390-px phone: no horizontal scroll, CSP with hashes and no unsafe-inline, no violations
    assert r["status"] == 200
    assert "script-src 'sha256-" in r["cspHeader"] and "unsafe-inline" not in r["cspHeader"] and "unsafe-eval" not in r["cspHeader"]
    assert r["csp"] == [] and final["csp"] == [], (r["csp"], final["csp"])
    assert r["errors"] == [] and r["dialogs"] == [], (r["errors"], r["dialogs"])
    for snap in (r["pre"], first, final):
        assert snap["innerWidth"] == 390 and snap["scrollWidth"] <= snap["clientWidth"], snap["scrollWidth"]
    # --- every request went to the box, its DNS-leg names or the (fake) Cloudflare: nothing else
    for host in r["hosts"]:
        assert host in {M.CORE_IP, "speed.cloudflare.com"} or host.endswith("." + M.ZONE), f"unexpected host {host}"
    cf = core.cf_stats()
    assert cf["down"] > 0 and cf["up"] > 0 and cf["trace"] >= 1, cf
    # --- both legs, a score and a diagnosis within 20 s of the tap
    assert r["doneAt"] <= 20000, f"results after {r['doneAt']} ms"
    sub = r["submissions"][-1]
    assert sub["status"] == 202 and sub["req"]["schema"] == "exp.speedtest.submission/1"
    assert sub["req"]["zone_hint"] == "hall-b"
    assert first["score"] not in (None, "", "0", "—"), first["score"]
    assert first["verdict"] and first["why"], first
    assert sub["res"].get("diagnosis") is not None or first["why"]
    # --- what was stored: both legs measured, the path timed by the box, the DNS leg through the delegation
    tests = core.wait_test(1)
    tid = tests[0]["id"]
    assert tid == sub["res"]["id"]
    d = core.test_detail(tid)
    t = d["test"]
    legs = t["legs"]
    assert legs["local"]["status"] == "ok" and legs["internet"]["status"] == "ok", legs
    assert legs["internet"]["server"] == "cloudflare:FRA"
    assert legs["dns"]["source"] == "browser" and legs["dns"]["resolver_ip"] == M.GW_CORE, legs["dns"]       # via the delegation
    p = legs["path"]
    assert p["gateway_ms"]["samples"] > 0 and p["edge_ms"]["samples"] > 0 and p["edge1_ms"]["samples"] > 0, p
    assert p["edge1_addr"] == "10.255.2.2" and p["device_icmp_ms"] is not None, p
    assert t["zone_source"] in ("mist", "subnet", "qr") and t["zone"] == "hall-b"
    assert "ip" not in t["client"], "the default view carries no raw client address"
    assert d["diagnosis"]["user_text"]
    # --- identified by correlation (admin view): the fake Mist knows this phone by IP -> MAC
    full = core.test_detail(tid, identifiers=True)
    ident = [e for e in full["evidence"] if e["kind"] == "identity"]
    assert ident and ident[0]["status"] == "ok", [e["kind"] for e in full["evidence"]]
    assert phone.mac in json.dumps(ident[0]["data"]).lower()
    # --- comment XSS: stored verbatim, rendered as text only (no dialog, no violation, no markup)
    assert t["comment"] == XSS
    note = final["note"] or ""
    assert "<img src=x onerror=alert(1)>" in note, note
    assert "dialogs" in r and r["dialogs"] == []
