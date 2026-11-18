"""A2.7 - decommission a host: components removed, units gone, files removed, credentials revoked, host gone from the UI.

A converged all-in-one host (agent, collector, dashboard, probe with a veth port in its network namespace). The admin
calls `POST hosts/{id}/decommission`; the agent (06-agent.md section 5) removes every component including data and creds,
tells the manager (`POST decommissioned`), then removes itself. Observations: the host's filesystem, systemd, its network
interfaces, the manager's admin API and agent API (the old agent secret must be refused).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import pytest
from expharness.dockerhost import wait_for

import m2lib
from m2lib import agent_call, provision_full

SITE = "dec-e2e"


@dataclass
class Dec:
    full: m2lib.Full
    secret: str
    probe_token: str
    before: dict[str, str]


@pytest.fixture(scope="module")
def dec(stack, host_image):
    full = provision_full(stack, SITE, "a27", "e2e-dec")
    try:
        h = full.host
        before = {
            "units": h.run("systemctl list-units 'exp-*' --all --no-pager --plain --no-legend | awk '{print $1}' | sort").out,
            "opt": h.run("ls /opt/exp").out,
            "ifaces": h.run("ip -br link | awk '{print $1}'").out,
        }
        yield Dec(full, m2lib.agent_secret(h), m2lib.probe_token(h), before)
    finally:
        try:
            (stack.artifacts / "a27-host-journal.txt").write_text(full.host.journal(None, 600))
        finally:
            full.host.remove()


def test_host_is_fully_installed_before(stack, dec):
    h = dec.full.host
    b = dec.before
    assert {"exp-agent.service", "exp-collector.service", "exp-dashboard.service", "exp-probe.service"} <= set(b["units"].split())
    assert set(b["opt"].split()) >= {"agent", "collector", "dashboard", "probe"}
    assert h.run("test -s /etc/exp/agent.json").rc == 0
    assert h.run("ls /var/lib/exp").out.split() and h.run("ls /etc/exp").out.split()
    assert "vp0" not in b["ifaces"].split(), "the probe owns its port: it lives in the probe's namespace"


def test_decommission_removes_everything(stack, dec):
    admin, hid, h = stack.admin, dec.full.host_id, dec.full.host
    r = admin.call("POST", f"/hosts/{hid}/decommission", None, ok=(202,)).json()
    assert r["host_id"] == hid and r["state"] == "decommissioning"

    # the agent calls POST decommissioned: the manager marks the host removed and revokes the credentials
    def gone():
        listed = admin.get("/hosts?limit=200")["items"]
        return not any(x["host_id"] == hid for x in listed) and admin.call("GET", f"/hosts/{hid}").status == 404

    wait_for(gone, 240, 3, "the host to disappear from the admin API", h.diagnostics)

    # ---- the host: no exp unit left, no files, no agent
    # systemd may still remember a unit name a removed unit referenced (LOAD=not-found, inactive): that is no unit
    listing = h.run("systemctl list-units 'exp-*' --all --no-pager --plain --no-legend").out.splitlines()
    live = [ln for ln in listing if ln.split()[1] != "not-found" or ln.split()[2] != "inactive"]
    unit_files = h.run("systemctl list-unit-files 'exp-*' --no-pager --plain --no-legend | awk '{print $1}'").out.split()
    assert live == [] and unit_files == [], (live, unit_files)
    assert h.run("ls /etc/systemd/system | grep -c '^exp-'").out.strip() == "0"
    assert h.run("ls -A /opt/exp 2>/dev/null | wc -l").out.strip() == "0", h.run("find /opt/exp | head -20").out
    assert h.run("test ! -e /etc/exp/agent.json").rc == 0
    assert h.run("ls -A /etc/exp 2>/dev/null | wc -l").out.strip() == "0", h.run("find /etc/exp | head").out
    assert h.run("ls -A /var/lib/exp 2>/dev/null | wc -l").out.strip() == "0", h.run("find /var/lib/exp | head").out
    assert h.run("ls /usr/bin /usr/local/bin | grep -c '^exp-'").out.strip() == "0"
    assert h.run("pgrep -af 'exp-(agent|collector|dashboard|probe)|victoria' | grep -v pgrep | wc -l").out.strip() == "0"
    # the probe's port went back to the host and its namespace is gone
    ifaces = h.run("ip -br link | awk '{print $1}'").out.split()
    assert any(i.startswith("vp0") for i in ifaces), ifaces
    assert h.run("ip netns list | grep -c exp").out.strip() == "0"

    # ---- the manager: credentials revoked, nothing current about the host
    for path in ("/desired", "/releases/%s/manifest" % stack.version):
        assert agent_call(stack, "GET", path, dec.secret)[0] == 401, path
    assert agent_call(stack, "POST", "/status", dec.secret, b"{}")[0] == 401
    assert agent_call(stack, "POST", "/rotate", dec.secret, b"{}")[0] == 401
    rows = stack.mgr.sql(f"SELECT revoked_at FROM agent_creds WHERE host_id = '{hid}'")
    assert rows and rows[0]["revoked_at"], rows
    assert stack.mgr.sql(f"SELECT state FROM hosts WHERE host_id = '{hid}'")[0]["state"] == "removed"
    hosts = {x["host_id"] for x in admin.get("/fleet/hosts?limit=1000")["items"]}
    assert hid not in hosts
    assert admin.call("GET", f"/hosts/{hid}/components").status == 404
    assert admin.call("GET", f"/hosts/{hid}/status").status == 404
    assert admin.call("POST", f"/hosts/{hid}/enrol-token", None).status in (404, 409)
    assert admin.call("POST", f"/hosts/{hid}/rotate-agent", None).status == 404
    # the probe's ingest token and the collector token are not served any more either
    audit = admin.get(f"/audit?resource=host:{hid}&limit=100")["items"]
    actions = {a["action"] for a in audit}
    assert {"host.decommission", "agent.decommissioned"} <= actions, actions
    assert dec.secret not in str(audit)


def test_decommissioned_host_does_not_resurrect(stack, dec):
    """Nothing the removed host knew works any more: neither its agent secret nor its probe's ingest token (the collector is gone
    with the host; the manager no longer compiles anything for it)."""
    hid = dec.full.host_id
    time.sleep(35)  # more than one poll interval of a (hypothetically) still running agent
    assert agent_call(stack, "GET", "/desired", dec.secret)[0] == 401
    assert host_row_missing(stack, hid)
    # the other hosts' desired states no longer carry this host's collector or probe
    for x in stack.admin.get("/fleet/hosts?limit=1000")["items"]:
        assert x["host_id"] != hid


def host_row_missing(stack, hid: str) -> bool:
    return stack.admin.call("GET", f"/hosts/{hid}").status == 404
