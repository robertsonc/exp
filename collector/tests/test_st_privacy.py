"""12 section 9, SR-25: retention, the optional scrub, purge (API and CLI) -- end states, not intentions."""
from __future__ import annotations

import json
import sqlite3
import time

import pytest
from colhelpers import check_openapi, check_schema_file
from sthelpers import (
    device_key,
    evidence,
    make_stenv,
    result,
    wifi,
)

from exp_collector import cli
from exp_collector.speedtest.repo import KINDS
from exp_collector.store import MIGRATIONS, SCHEMA_VERSION, Store

MAC = "f0:18:98:aa:bb:01"
RAW = ("10.60.14.77", MAC, "f01898aabb01", "F0-18-98-AA-BB-01", "alices-iphone", "guest-portal-7731", "booth-pc-12")


def full_run(st, **kw):
    """A test with all eight evidence kinds naming the same client (IP, MAC, hostname, username everywhere)."""
    t = result(ip="10.60.14.77", **kw)
    ev = [evidence(k, t) for k in ("identity", "wired", "flows", "security", "dns", "wan", "baseline")]
    w = wifi(t)
    w["raw_refs"] = ["mist:stats/clients/f01898aabb01"]
    ev.append(w)
    sec = next(e for e in ev if e["kind"] == "security")
    sec["data"]["events"][0]["raw"] += " host=alices-iphone user=guest-portal-7731"
    st.run(t, ev)
    return t


class Clock:
    def __init__(self):
        self.off = 0.0

    def __call__(self):
        return time.time() + self.off


# --------------------------------------------------------------------------------------------- retention
def count(st, table="speedtests"):
    return st.db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608


def test_retention_deletes_tests_device_metadata_and_evidence_after_30_days(env):
    clk = Clock()
    st = make_stenv(env, clock=clk)
    old, new = full_run(st, ended_ago_s=29 * 86400), full_run(st)
    assert count(st) == 2 and count(st, "evidence") == 16 and count(st, "diagnoses") == 4
    clk.off = 2 * 86400
    res = st.app.speedtests.retention_once()
    assert res["tests"] == 1 and res["evidence"] == 8 and res["diagnoses"] == 2
    ids = {r[0] for r in st.db().execute("SELECT id FROM speedtests")}
    assert ids == {new["id"]}
    assert {r[0] for r in st.db().execute("SELECT DISTINCT test_id FROM evidence")} == {new["id"]}
    assert {r[0] for r in st.db().execute("SELECT DISTINCT test_id FROM diagnoses")} == {new["id"]}
    assert old["id"] not in st.db_dump() and st.get(f"/{old['id']}").status == 404
    assert st.app.speedtests.retention_once()["tests"] == 0                          # idempotent
    clk.off = 32 * 86400
    st.app.speedtests.retention_once()
    assert count(st) == count(st, "evidence") == count(st, "diagnoses") == 0


def test_retention_window_is_configurable(env):
    clk = Clock()
    st = make_stenv(env, speedtests={"retention_days": 7}, clock=clk)
    full_run(st)
    clk.off = 6 * 86400
    assert st.app.speedtests.retention_once()["tests"] == 0
    clk.off = 8 * 86400
    assert st.app.speedtests.retention_once()["tests"] == 1


def test_retention_runs_in_the_background_job(env):
    clk = Clock()
    st = make_stenv(env, clock=clk)
    full_run(st)
    clk.off = 31 * 86400
    st.app.speedtests.run_jobs_once()
    assert count(st) == 0


def test_retention_keeps_raw_identifiers_by_default(st):
    full_run(st)
    row = st.db().execute("SELECT client_ip, mac, hostname, username, scrubbed FROM speedtests").fetchone()
    assert tuple(row) == ("10.60.14.77", MAC, "alices-iphone", "guest-portal-7731", 0)   # no scrub unless configured


# --------------------------------------------------------------------------------------- finalize sweep
def test_a_test_nobody_completed_is_finalized_by_the_collector(env):
    clk = Clock()
    st = make_stenv(env, clock=clk)
    bare, with_ev = result(), result()
    st.ingest(bare)
    st.ingest(with_ev)
    st.put_ev(wifi(with_ev, rssi=-80, snr=14, util=30, clients=20))
    assert st.app.speedtests.finalize_due() == 0                                      # inside the window
    clk.off = 400
    assert st.app.speedtests.finalize_due() == 2
    a, b = st.get(f"/{bare['id']}").json(), st.get(f"/{with_ev['id']}").json()
    assert a["evidence_state"]["state"] == "unavailable" and a["diagnosis"]["stage"] == "final"
    assert b["evidence_state"]["state"] == "final" and b["diagnosis"]["cause"][0]["id"] == "wifi_signal"
    assert st.feed().json()["items"] == []
    assert st.complete(bare["id"], []).status == 409
    assert st.app.speedtests.finalize_due() == 0


# ---------------------------------------------------------------------------------------------- the scrub
def test_scrub_after_diagnosis_removes_every_raw_identifier_and_keeps_the_device_key(env):
    st = make_stenv(env, speedtests={"scrub_after_diagnosis": True})
    t = full_run(st)
    dump = st.db_dump()
    for raw in RAW:
        assert raw.lower() not in dump.lower(), raw
    row = st.db().execute("SELECT * FROM speedtests").fetchone()
    assert row["client_ip"] is None and row["mac"] is None and row["hostname"] is None and row["username"] is None
    assert row["scrubbed"] == 1 and row["device_key"] == "231b3838d0007bf24d5b048d8a17a19495b0fb11b94a792fa99b1deb58b9e082"
    assert row["zone"] == "hallb-row12" and row["ap_name"] == "hallb-ap-12" and row["ssid"] == "Summit-Guest"
    adm = st.get(f"/{t['id']}?identifiers=true", user="ada")                          # even admins get nothing back
    assert adm.status == 200 and "client" in adm.json()["test"] and "ip" not in adm.json()["test"]["client"]
    for ev in adm.json()["evidence"]:
        check_schema_file("evidence.schema.json", ev)                                 # still contract-valid
    ident = next(e for e in adm.json()["evidence"] if e["kind"] == "identity")["data"]
    assert ident["scrubbed"] is True and ident["device_key"] and "mac" not in ident and "username" not in ident
    assert adm.json()["diagnosis"]["stage"] == "final"
    flows = next(e for e in adm.json()["evidence"] if e["kind"] == "flows")["data"]["flows"]
    assert all(f["ip1"] != "10.60.14.77" for f in flows)
    assert st.get("?identifiers=true&q=10.60.14.77", user="ada").json()["items"] == []
    assert st.status(t["id"]).json()["state"] == "final"


def test_scrub_leaves_nothing_on_disk_after_a_checkpoint(env):
    st = make_stenv(env, speedtests={"scrub_after_diagnosis": True})
    full_run(st)
    c = sqlite3.connect(st.app.paths.db_path)
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    c.close()
    blob = b""
    for suffix in ("", "-wal"):
        try:
            blob += open(str(st.app.paths.db_path) + suffix, "rb").read()
        except OSError:
            pass
    for raw in RAW:
        assert raw.encode() not in blob and raw.lower().encode() not in blob, raw


def test_scrub_applies_to_tests_that_became_final_before_it_was_enabled(env):
    st = make_stenv(env)
    full_run(st)
    assert "alices-iphone" in st.db_dump()
    svc = st.app.speedtests
    svc.settings = type(svc.settings)(**{**svc.settings.__dict__, "scrub_after_diagnosis": True})
    assert svc.retention_once()["scrubbed"] == 1
    assert "alices-iphone" not in st.db_dump() and MAC not in st.db_dump()
    assert svc.retention_once()["scrubbed"] == 0


def test_non_admin_view_is_the_same_transform_without_touching_the_rows(st):
    t = full_run(st)
    safe = st.get(f"/{t['id']}").body.decode()
    for raw in RAW:
        assert raw.lower() not in safe.lower(), raw
    assert "alices-iphone" in st.db_dump()                                           # the rows are untouched
    adm = st.get(f"/{t['id']}?identifiers=true", user="ada").body.decode()
    assert "alices-iphone" in adm and MAC in adm and "10.60.14.77" in adm


def test_no_person_identity_field_exists_anywhere(st):
    t = full_run(st)
    forbidden = {"name", "email", "phone", "full_name", "first_name", "last_name", "account", "user_name"}
    seen = set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                seen.add(k)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    for body in (st.get(f"/{t['id']}?identifiers=true", user="ada").json(), st.status(t["id"]).json(),
                 st.get("?identifiers=true", user="ada").json()):
        walk(body)
    assert not (seen & forbidden), seen & forbidden
    for table in ("speedtests", "evidence", "diagnoses", "speedtest_audit"):
        cols = {r[1] for r in st.db().execute(f"PRAGMA table_info({table})")}  # noqa: S608
        assert not (cols & forbidden), (table, cols)


# ------------------------------------------------------------------------------------------------ purge
def tables_for(st, test_id):
    c = st.db()
    return (c.execute("SELECT COUNT(*) FROM speedtests WHERE id=?", (test_id,)).fetchone()[0],
            c.execute("SELECT COUNT(*) FROM evidence WHERE test_id=?", (test_id,)).fetchone()[0],
            c.execute("SELECT COUNT(*) FROM diagnoses WHERE test_id=?", (test_id,)).fetchone()[0])


def two_devices(st):
    a = full_run(st)
    b = result(ip="10.60.15.9")
    ident = evidence("identity", b, ip="10.60.15.9", mac="f0:18:98:aa:bb:02", device_key=f"{7:064x}",
                     hostname="bobs-laptop", username=None)
    ident["data"].pop("username")
    st.run(b, [wifi(b), ident])
    return a, b


@pytest.mark.parametrize("by,value", [("test", None), ("ip", "10.60.14.77"), ("mac", MAC),
                                      ("mac", "F0-18-98-AA-BB-01"), ("device_key", None)])
def test_purge_end_state_rows_are_gone(st, by, value):
    a, b = two_devices(st)
    if by == "test":
        value = a["id"]
    if by == "device_key":
        value = "231b3838d0007bf24d5b048d8a17a19495b0fb11b94a792fa99b1deb58b9e082"
    dry = st.purge(by, value, dry_run=True)
    assert dry.status == 200 and dry.json()["matched_tests"] == 1 and dry.json()["deleted"]["tests"] == 0
    assert tables_for(st, a["id"]) == (1, 8, 2)                                      # a dry run deletes nothing
    r = st.purge(by, value)
    assert r.status == 200
    check_openapi("collector", "/speedtests/purge", "post", 200, r.json())
    body = r.json()
    assert body["matched_tests"] == 1 and body["deleted"] == {"tests": 1, "evidence": 8, "diagnoses": 2}
    assert body["audited_by"] == "ada" and body["dry_run"] is False
    assert tables_for(st, a["id"]) == (0, 0, 0)
    assert tables_for(st, b["id"]) == (1, 2, 2)                                      # the other device is untouched
    assert st.get(f"/{a['id']}").status == 404 and st.status(a["id"]).status == 404
    assert all(i["id"] != a["id"] for i in st.get("").json()["items"])
    dump = st.db_dump()
    for raw in ("alices-iphone", "guest-portal-7731", "10.60.14.77"):
        assert raw not in dump
    assert st.purge(by, value).json()["matched_tests"] == 0                          # nothing left to match


def test_purge_by_mac_reaches_scrubbed_rows_through_the_device_key(env):
    st = make_stenv(env, speedtests={"scrub_after_diagnosis": True})
    a, b = two_devices(st)
    assert st.db().execute("SELECT mac FROM speedtests WHERE id=?", (a["id"],)).fetchone()[0] is None
    # the fixture's device_key was computed under another secret: store what the runner would have computed here
    dk = device_key(env, MAC)
    st.db().close()
    c = sqlite3.connect(st.app.paths.db_path)
    c.execute("UPDATE speedtests SET device_key=? WHERE id=?", (dk, a["id"]))
    c.commit()
    c.close()
    r = st.purge("mac", MAC)
    assert r.json()["matched_tests"] == 1 and r.json()["device_key_matched"] is True
    assert tables_for(st, a["id"]) == (0, 0, 0) and tables_for(st, b["id"])[0] == 1


def test_purge_by_mac_without_the_secret_matches_raw_macs_only(env):
    st = make_stenv(env, device_secret=False)
    a, _b = two_devices(st)
    r = st.purge("mac", MAC)
    assert r.json()["device_key_matched"] is False and r.json()["matched_tests"] == 1     # raw MAC still stored
    assert tables_for(st, a["id"]) == (0, 0, 0)


def test_purge_by_mac_without_the_secret_cannot_reach_scrubbed_rows(env):
    st = make_stenv(env, device_secret=False, speedtests={"scrub_after_diagnosis": True})
    a, _b = two_devices(st)
    r = st.purge("mac", MAC)
    assert r.json() == {"dry_run": False, "matched_tests": 0, "deleted": {"tests": 0, "evidence": 0, "diagnoses": 0},
                        "device_key_matched": False, "audited_by": "ada"}
    assert tables_for(st, a["id"])[0] == 1                                          # reported, not silently ignored


def test_purge_is_audited_without_the_identifier_and_needs_a_user(st):
    full_run(st)
    r = st.purge("ip", "10.60.14.77", user=None)
    assert r.status == 403 and r.json()["error"]["code"] == "forbidden"
    assert st.app.speedtests.repo.count() == 1
    st.purge("ip", "10.60.14.77", user="grace")
    rows = st.app.speedtests.repo.audit_rows()
    assert rows[0]["actor"] == "grace" and rows[0]["action"] == "purge" and rows[0]["matched"] == 1
    assert rows[0]["subject"].startswith("ip:") and "10.60.14.77" not in json.dumps(rows)


def test_purge_does_not_log_the_identifier(st, log_capture):
    full_run(st)
    st.purge("mac", MAC)
    st.purge("ip", "10.60.14.77")
    out = log_capture()
    assert "purge" in out
    for raw in (MAC, "10.60.14.77", "f01898aabb01"):
        assert raw not in out


def test_purge_validation_and_injection(st):
    full_run(st)
    for body in ({}, {"by": "name", "value": "x"}, {"by": "ip", "value": "not-an-ip"}, {"by": "mac", "value": "zz"},
                 {"by": "test", "value": "nope"}, {"by": "device_key", "value": "ABC"}, {"by": "ip", "value": ""},
                 {"by": "ip", "value": "1" * 129}, {"by": "ip", "value": "10.0.0.1", "extra": 1},
                 {"by": "ip", "value": "10.0.0.1", "dry_run": "yes"}, {"by": "test", "value": "' OR 1=1 --"}):
        r = st.req("POST", "/purge", st.tokens["expd"], body, {"X-Exp-User": "ada"})
        assert r.status == 400, body
    assert st.req("POST", "/purge", st.tokens["expd"], raw=b"{", headers={"X-Exp-User": "ada"}).status == 400
    assert st.app.speedtests.repo.count() == 1


def test_purge_by_ip_matches_the_normalised_address(st):
    t = result(ip="2001:db8::5")
    st.run(t, [])
    assert st.purge("ip", "2001:0db8:0:0:0:0:0:5").json()["matched_tests"] == 1


# --------------------------------------------------------------------------------------------------- CLI
def cli_args(st, *extra):
    cfg = st.env.tmp / "collector.json"
    cfg.write_text(json.dumps(st.env.cfg_doc))
    return ["speedtest", "purge", "--config", str(cfg), "--state-dir", str(st.env.state), "--run-dir",
            str(st.env.run), "--creds-dir", str(st.env.creds), *extra]


def test_cli_purge_by_each_selector_ends_with_the_rows_gone(st, capsys):
    a, b = two_devices(st)
    assert cli.main(cli_args(st, "--device-key", "0" * 64, "--user", "ops")) == 0
    assert json.loads(capsys.readouterr().out)["matched_tests"] == 0
    assert cli.main(cli_args(st, "--ip", "10.60.14.77", "--dry-run", "--user", "ops")) == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry["matched_tests"] == 1 and dry["dry_run"] is True and tables_for(st, a["id"]) == (1, 8, 2)
    assert cli.main(cli_args(st, "--mac", MAC, "--user", "ops")) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["deleted"] == {"tests": 1, "evidence": 8, "diagnoses": 2} and res["audited_by"] == "cli:ops"
    assert tables_for(st, a["id"]) == (0, 0, 0) and tables_for(st, b["id"])[0] == 1
    assert cli.main(cli_args(st, "--test", b["id"])) == 0
    assert tables_for(st, b["id"]) == (0, 0, 0)
    assert st.app.speedtests.repo.audit_rows()[0]["actor"].startswith("cli:")


def test_cli_purge_argument_errors(st, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(cli_args(st))                                                       # a selector is required
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        cli.main(cli_args(st, "--ip", "1.2.3.4", "--mac", MAC))                      # exactly one
    assert e.value.code == 2
    assert cli.main(cli_args(st, "--ip", "not-an-ip")) == 2
    capsys.readouterr()


def test_cli_purge_works_when_the_analytics_are_disabled(env, capsys):
    st = make_stenv(env)
    a = full_run(st)
    env.cfg_doc["speedtests"]["enabled"] = False
    assert cli.main(cli_args(st, "--test", a["id"])) == 0
    assert tables_for(st, a["id"]) == (0, 0, 0)
    capsys.readouterr()


# -------------------------------------------------------------------------------------------- migration
def test_database_migrates_from_schema_1_keeping_the_records(tmp_path):
    p = tmp_path / "v1.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    for stmt in MIGRATIONS[1]:
        c.execute(stmt)
    c.execute("INSERT INTO meta VALUES('schema_version','1')")
    c.execute("INSERT INTO records VALUES('p','r1',1,'s','ping','ok','{}')")
    c.commit()
    c.close()
    s = Store(p).open()
    try:
        assert s.schema_version() == SCHEMA_VERSION == 2 and s.count_records() == 1
        with s.reader() as conn:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            idx = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"speedtests", "evidence", "diagnoses", "speedtest_audit"} <= tables
        assert {"speedtests_zone", "speedtests_ap", "speedtests_ssid", "speedtests_cause", "speedtests_device",
                "speedtests_ip", "speedtests_mac", "speedtests_pending"} <= idx
    finally:
        s.close()
    assert KINDS == ("wifi", "wired", "flows", "wan", "security", "baseline", "dns", "identity")


def test_secure_delete_is_on_for_the_writer(st):
    seen = []
    st.app.store.write(lambda conn: seen.append(conn.execute("PRAGMA secure_delete").fetchone()[0]))
    assert seen == [1]
