"""A6.11: transport and privacy end state (12-speedtest-analytics.md sections 4.3, 9, 11).

* over plain HTTP (the D15 default) the page loads, the internet leg still reaches HTTPS (fake) Cloudflare, clipboard and wake
  lock fall back cleanly, the DNS leg needs no certificate;
* then tls.mode = provided: HTTPS 443 (+ 80 -> 443 redirect) and all of it still works;
* no name / e-mail field exists anywhere (page inputs, stored documents);
* a purge by test, by MAC and by IP removes the rows (END STATE asserted by querying the collector's database)."""
from __future__ import annotations

import json
import re

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e
FORBIDDEN_KEYS = {"name", "email", "e-mail", "phone", "first_name", "last_name", "full_name", "given_name", "surname", "mail", "address"}
FORBIDDEN_WORDS = re.compile(r"e-?mail|your name|full name|first name|last name|phone number", re.I)     # an input's name/placeholder/label
ASKS_FOR_IDENTITY = re.compile(r"(enter|your|provide|type|add)\s+(full\s+|first\s+|last\s+)?(name|e-?mail|phone)", re.I)   # page text that asks


def identify(core: M.Core, phone: M.Client) -> None:
    core.fake("mist", "POST", "/_fake/reset")
    core.fake("mist", "POST", "/_fake/scenario", {"name": "healthy", "ip": phone.ip, "mac": phone.mac})
    core.fake("orch", "POST", "/_fake/scenario", {"name": "healthy", "client_ip": phone.ip})


def walk_keys(doc, path=""):
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield path + "/" + k, k
            yield from walk_keys(v, path + "/" + k)
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from walk_keys(v, f"{path}[{i}]")


def db_hits(core: M.Core, needle: str) -> dict[str, int]:
    """Rows of the collector database (every table, every column, as text) that contain `needle`."""
    script = (
        "import sqlite3,sys,json\n"
        "n=sys.argv[1].lower(); db=sqlite3.connect('file:/var/lib/exp/collector/records.db?mode=ro',uri=True); out={}\n"
        "for (t,) in db.execute(\"select name from sqlite_master where type='table'\"):\n"
        "    cols=[r[1] for r in db.execute(f'pragma table_info({t})')]\n"
        "    if not cols: continue\n"
        "    q=' or '.join(f'lower(cast({c} as text)) like ?' for c in cols)\n"
        "    k=db.execute(f'select count(*) from {t} where '+q,[f'%{n}%']*len(cols)).fetchone()[0]\n"
        "    if k: out[t]=k\n"
        "print(json.dumps(out))\n")
    return json.loads(core.col.ok(f"python3 -c {M.L._q(script)} {M.L._q(needle)}").strip().splitlines()[-1])


def make_cert(core: M.Core) -> str:
    key, crt = core.work / "box.key", core.work / "box.crt"
    M.sh(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "3", "-subj", "/CN=speed.exp.test",
          "-addext", f"subjectAltName=IP:{M.CORE_IP},DNS:{M.ZONE},DNS:*.{M.ZONE}", "-keyout", str(key), "-out", str(crt)], check=True)
    return crt.read_text(), key.read_text()


def test_a611_transport_and_privacy(core: M.Core, artifacts):
    seen_inputs: list[dict] = []
    stored: dict[str, str] = {}

    # ---------------------------------------------------------------- plain HTTP (default)
    p1 = core.new_client("tp1")
    identify(core, p1)
    r1, t1 = core.run_page(p1, name="a611-http", timeoutMs=120000, copy=True, report="the booth wifi drops", waitChecksMs=60000,
                           shotResults="a611-01-http-results-390")
    stored["http"] = t1
    snap = r1["final"]
    assert r1["status"] == 200 and r1["pre"]["secure"] is False and snap["secure"] is False
    assert snap["clipboard"] == "undefined" and snap["wakeLock"] == "undefined", (snap["clipboard"], snap["wakeLock"])
    assert r1["copyStat"], "copy falls back to select-the-code with a message"
    assert (r1["selection"] or "").strip(), "the share code is selected for the user to copy"
    assert "http://*." + M.ZONE in r1["cspHeader"] and "https://speed.cloudflare.com" in r1["cspHeader"]
    assert r1["csp"] == [] and r1["errors"] == [] and r1["dialogs"] == []
    assert any(h == "speed.cloudflare.com" for h in r1["hosts"]), "the internet leg reached (fake, HTTPS) Cloudflare from an HTTP page"
    d1 = core.test_detail(t1)["test"]
    assert d1["legs"]["internet"]["status"] == "ok" and d1["legs"]["local"]["status"] == "ok"
    assert d1["legs"]["dns"]["source"] == "browser" and d1["legs"]["dns"]["resolver_ip"], "the DNS leg needs no certificate"
    assert core.st_status()["listening"]["tls_mode"] == "none"
    for k in ("pre", "first", "final", "checked", "afterReport"):
        if r1.get(k):
            seen_inputs += r1[k]["inputs"]

    # ---------------------------------------------------------------- tls.mode = provided
    crt, key = make_cert(core)
    core.set_credential("speedtest", "tls.crt", crt, restart=False)
    core.set_credential("speedtest", "tls.key", key, restart=False)
    core.reconfigure("speedtest", lambda cfg: cfg["tls"].update({"mode": "provided"}))
    try:
        assert core.st_status()["listening"]["tls_mode"] == "provided"
        p2 = core.new_client("tp2")
        identify(core, p2)
        red = p2.run("curl", "-sI", "-m", "10", f"http://{M.CORE_IP}/")
        assert re.search(r"HTTP/1\.[01] 30[1278]", red.stdout) and f"https://{M.CORE_IP}" in red.stdout.lower().replace("location: ", "location: "), red.stdout
        pin = M.spki_pin(crt)
        r2, t2 = core.run_page(p2, name="a611-https", url=f"https://{M.CORE_IP}/?z=hall-b", spki=[pin], timeoutMs=120000, copy=True,
                               waitChecksMs=60000, shotResults="a611-02-https-results-390")
        stored["https"] = t2
        s2 = r2["final"]
        assert r2["pre"]["secure"] is True and s2["secure"] is True
        assert s2["clipboard"] == "object", "the clipboard API is back over HTTPS"
        assert r2["csp"] == [] and r2["errors"] == [] and r2["dialogs"] == [], (r2["csp"], r2["errors"])
        assert "speed.cloudflare.com" in r2["hosts"]
        d2 = core.test_detail(t2)["test"]
        assert d2["legs"]["internet"]["status"] == "ok" and d2["legs"]["local"]["status"] == "ok", d2["legs"]
        assert d2["legs"]["dns"]["source"] == "browser", d2["legs"]["dns"]
        for k in ("pre", "first", "final", "checked"):
            if r2.get(k):
                seen_inputs += r2[k]["inputs"]
    finally:
        core.reset_config("speedtest")
        core.set_credential("speedtest", "tls.crt", "", restart=False)
        core.set_credential("speedtest", "tls.key", "", restart=True)
    assert core.st_status()["listening"]["tls_mode"] == "none"

    # ---------------------------------------------------------------- a third test for the purge by IP
    p3 = core.new_client("tp3")
    identify(core, p3)
    r3, t3 = core.run_page(p3, name="a611-third", timeoutMs=120000)
    stored["third"] = t3
    for t in stored.values():
        core.wait_final(t)

    # ---------------------------------------------------------------- no name / email field anywhere
    names = {(i["name"] or i["id"] or "").lower() for i in seen_inputs}
    for i in seen_inputs:
        assert i["type"] not in ("email", "tel", "url") and (i["autocomplete"] or "") not in ("name", "email", "tel", "given-name", "family-name"), i
        for fld in (i["name"], i["id"], i["placeholder"], i["aria"]):
            assert not (fld and (fld.lower() in FORBIDDEN_KEYS or FORBIDDEN_WORDS.search(fld))), i
    assert not ASKS_FOR_IDENTITY.search(r1["first"]["bodyText"]), "the page asks for no name or e-mail"
    assert "no name or email" in (r1["consentText"] or "").lower(), "the consent says nothing like that is collected"
    for tid in stored.values():
        full = core.test_detail(tid, identifiers=True)
        for p, k in walk_keys({"test": full["test"], "diagnosis": full["diagnosis"]}):
            assert k.lower() not in FORBIDDEN_KEYS, f"{p}: a name/e-mail style field exists in the stored test"
        for ev in full["evidence"]:
            for p, k in walk_keys(ev["data"]):
                assert k.lower() not in FORBIDDEN_KEYS, f"{ev['kind']} {p}: name/e-mail style field in evidence"
    print("A6.11 page inputs seen:", sorted(names))

    # ---------------------------------------------------------------- purge by test / MAC / IP: end state by query
    audit_before = db_hits(core, "")        # '' matches every row of every table: sanity that the scan works at all
    assert audit_before.get("speedtests", 0) >= 3
    ident = {}
    for key_, client in (("http", p1), ("https", p2), ("third", p3)):
        ident[key_] = client
        assert db_hits(core, client.mac).get("evidence", 0) > 0, "the raw MAC is in the evidence before the purge (scrub is off)"
        assert db_hits(core, client.ip).get("speedtests", 0) > 0 or db_hits(core, client.ip).get("evidence", 0) > 0

    def gone(tid: str, client: M.Client) -> None:
        r = M.tlspin.request("GET", f"{core.collector_url}/api/v1/speedtests/{tid}", core.col_fp,
                             headers={"Authorization": f"Bearer {core.dash_token}", "X-Exp-User": M.L.USER})
        assert r.status == 404, (r.status, r.body[:200])
        assert tid not in {x["id"] for x in core.tests()}
        for needle in (client.mac, client.mac.replace(":", ""), client.ip):
            assert db_hits(core, needle) == {}, f"{needle} still present after the purge: {db_hits(core, needle)}"
        assert db_hits(core, tid).get("speedtests", 0) == 0 and db_hits(core, tid).get("evidence", 0) == 0 and db_hits(core, tid).get("diagnoses", 0) == 0

    # by test (dry run first: counts, deletes nothing)
    dry = core.collector_post("speedtests/purge", {"by": "test", "value": stored["http"], "dry_run": True})
    assert dry.status == 200 and dry.json()["matched_tests"] == 1 and dry.json()["deleted"] == {"tests": 0, "evidence": 0, "diagnoses": 0}, dry.body
    assert stored["http"] in {x["id"] for x in core.tests()}
    res = core.collector_post("speedtests/purge", {"by": "test", "value": stored["http"]})
    assert res.status == 200 and res.json()["deleted"]["tests"] == 1 and res.json()["deleted"]["evidence"] > 0, res.body
    gone(stored["http"], p1)
    # by MAC (the collector holds the device_key secret: it also reaches rows through the key)
    res = core.collector_post("speedtests/purge", {"by": "mac", "value": p2.mac.upper()})
    assert res.status == 200 and res.json()["device_key_matched"] is True and res.json()["deleted"]["tests"] == 1, res.body
    gone(stored["https"], p2)
    # by IP
    res = core.collector_post("speedtests/purge", {"by": "ip", "value": p3.ip})
    assert res.status == 200 and res.json()["deleted"]["tests"] == 1, res.body
    gone(stored["third"], p3)
    # the audit trail names the subject by hash only, never by identifier
    for client in (p1, p2, p3):
        assert db_hits(core, client.mac) == {} and db_hits(core, client.ip) == {}
    aud = json.loads(core.col.ok("sqlite3 -readonly /var/lib/exp/collector/records.db -json 'select * from speedtest_audit'") or "[]")
    assert len(aud) >= 3 and not any(p.ip in json.dumps(aud) or p.mac in json.dumps(aud) for p in (p1, p2, p3)), aud
    # the box keeps results without client.ip; a raw address or MAC never sits in its database either
    box = core.col.ok("strings /var/lib/exp/speedtest/speedtest.db* 2>/dev/null || python3 -c \"print(open('/var/lib/exp/speedtest/speedtest.db','rb').read().decode('latin1'))\"")
    for client in (p1, p2, p3):
        assert client.mac not in box.lower() and f'"ip": "{client.ip}"' not in box and f'"ip":"{client.ip}"' not in box
