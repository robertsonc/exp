"""A6.6: anonymous mode. With privacy.scrub_after_diagnosis enabled (collector, runner, speedtest), after the FINAL diagnosis no raw
identifier (client IP, MAC in either spelling, DHCP hostname, 802.1X-style username) remains in ANY table of the collector database,
the runner's database or the syslog ring, or the box's own database; the join key (device_key) and the zone are kept. There is no
identified mode and no name / e-mail field anywhere (asserted on the stored documents and on every column of the speedtest tables).
(12-speedtest-analytics.md sections 9, 11; the default is scrub OFF, asserted as the counter-proof in A6.11.)"""
from __future__ import annotations

import secrets
import time

import pytest
from exp_common import speedtest as st

import m6lib as M

pytestmark = pytest.mark.e2e
FORBIDDEN = {"name", "email", "e-mail", "mail", "phone", "first_name", "last_name", "full_name", "given_name", "surname", "address"}
RING, RUNNER_DB, BOX_DB = "/var/lib/exp/runner/syslog.db", "/var/lib/exp/runner/runner.db", "/var/lib/exp/speedtest/speedtest.db"
COLLECTOR_TABLES = ("speedtests", "evidence", "diagnoses", "speedtest_audit")


def walk_keys(doc, path=""):
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield path + "/" + k, k
            yield from walk_keys(v, path + "/" + k)
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from walk_keys(v, f"{path}[{i}]")


def spellings(mac: str) -> list[str]:
    bare = mac.replace(":", "")
    return [mac, mac.upper(), bare, bare.upper(), mac.replace(":", "-"), mac.replace(":", "-").upper(), ".".join(bare[i:i + 4] for i in range(0, 12, 4))]


def test_a66_scrub_after_final_diagnosis(core: M.Core):
    core.clean_slate()

    def enable(shape: str):
        def f(cfg: dict) -> None:
            if shape == "collector":
                cfg["speedtests"]["scrub_after_diagnosis"] = True
            elif shape == "runner":
                cfg["correlation"]["privacy"]["scrub_after_diagnosis"] = True
            else:
                cfg["privacy"]["scrub_after_diagnosis"] = True
        return f

    for shape in ("collector", "runner", "speedtest"):
        core.reconfigure(shape, enable(shape))
    try:
        ph = core.new_client("scrub")
        core.identify(ph)
        now = time.time()
        dhcp_name = "scrub-" + secrets.token_hex(3)         # unique per run: the ring may still hold lines of an earlier run
        # lines that name the client: a DHCP ack (IP + MAC + hostname), a DHCP discover (MAC + hostname only, no IP), a firewall deny (IP)
        core.syslog(
            M.ss.rfc3164_message(M.ss.dhcp_isc("DHCPACK", ph.ip, ph.mac, hostname=dhcp_name), ts=now - 30, host="dhcp-core", tag="dhcpd"),
            M.ss.rfc3164_message(M.ss.dhcp_isc("DHCPDISCOVER", ph.ip, ph.mac, hostname=dhcp_name), ts=now - 31, host="dhcp-core", tag="dhcpd"),
            *[M.ss.rfc3164_message(M.ss.ec_firewall(src=ph.ip, dst="10.0.0.10", sport=52000 + i, dport=22, action="DENY"), ts=now - i,
                                   host="ec-core", tag="zbf") for i in range(2)])
        r, tid = core.run_page(ph, name="a66", timeoutMs=120000)
        core.final(tid)
        key = st.device_key(core.expk, ph.mac)

        # --- the scrub runs after the final diagnosis: poll until the stores are clean, then assert the end state
        needles = [ph.ip, *spellings(ph.mac), "client-host", dhcp_name]

        def dirty() -> dict:
            out = {}
            for n in needles:
                for db in ("/var/lib/exp/collector/records.db", RING, RUNNER_DB, BOX_DB):
                    h = core.db_hits(n, db)
                    if h:
                        out[f"{n} @ {db.rsplit('/', 1)[-1]}"] = h
            return out

        deadline = time.time() + 90
        left = dirty()
        while left and time.time() < deadline:
            time.sleep(3)
            left = dirty()
        assert left == {}, f"raw identifiers remain after the final diagnosis: {left}"
        assert core.db_hits(tid).get("speedtests") == 1, "the scrub is not a wipe: the test row is still there"

        # --- what is kept: the join key and the zone; the stored documents (even the admin view) carry no identifier
        after = core.test_detail(tid, identifiers=True)
        assert after["device_key"] == key and after["test"]["zone"] == "hall-b", (after.get("device_key"), after["test"].get("zone"))
        ident = core.ev(after, "identity")["data"]
        assert ident["device_key"] == key and ident.get("scrubbed") is True and not {"mac", "ip", "hostname", "username"} & set(ident), ident
        blob = str(after)
        for n in needles:
            assert n not in blob, f"{n} still in the admin view"
        assert "client_ip" not in after["test"].get("client", {}) and "ip" not in after["test"].get("client", {}), after["test"].get("client")
        # the diagnosis was made BEFORE the scrub from the full evidence and is kept
        assert after["diagnosis"]["stage"] == "final" and after["diagnosis"]["user_text"]
        # --- no name / e-mail field anywhere: stored documents and every column of the speedtest tables
        for p, k in walk_keys({"test": after["test"], "diagnosis": after["diagnosis"], "evidence": [e["data"] for e in after["evidence"]]}):
            assert k.lower() not in FORBIDDEN, f"{p}: name/e-mail style field in a stored document"
        cols = core.columns()
        for t in COLLECTOR_TABLES:
            assert t in cols, (t, sorted(cols))
            assert not {c.lower() for c in cols[t]} & FORBIDDEN, (t, cols[t])
        for db in (RING, RUNNER_DB, BOX_DB):
            for t, cs in core.columns(db).items():
                if t.startswith("sqlite_"):          # SQLite's own bookkeeping (sqlite_sequence has a `name` column)
                    continue
                assert not {c.lower() for c in cs} & FORBIDDEN, (db, t, cs)
    finally:
        for shape in ("collector", "runner", "speedtest"):
            core.reset_config(shape)
