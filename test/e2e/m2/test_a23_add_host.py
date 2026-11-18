"""A2.3 - add host -> one-liner -> the host enrols and reports facts; the assigned shapes converge in < 2 min;
probe data reaches the collector; the dashboard opens via the manager's SSO handoff.

The flow is the product's own: admin API (site, host with shapes collector + dashboard + probe, one component per
shape exactly as the add-host wizard creates them), the returned one-liner is executed VERBATIM in a fresh
Ubuntu 24.04 systemd container, the probe's test port is a veth wired to a small DHCP/DNS LAN (netns + dnsmasq),
and every observation is made through the manager's admin API or the components' own HTTPS APIs.
"""

from __future__ import annotations

import html
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import pytest
from expharness import dockerhost
from expharness.dockerhost import LAN_GW, LAN_NAMES, build_lan, jget, pinned_request, wait_for

from conftest import start_host

CONVERGE_S = 120  # SPEC A2.3: assigned shapes converge < 2 min (measured from the one-liner finishing)
SITE = "hall-e2e"


@dataclass
class Scenario:
    host: dockerhost.Host
    host_id: str
    command: str
    token: str
    ids: dict[str, str]
    cids: dict[str, str]
    t_cmd_done: float = 0.0
    t_converged: float = 0.0
    install: Any = None
    ports_put: Any = None
    mgmt_refused: Any = None
    facts: dict[str, Any] = field(default_factory=dict)

    def status(self, stack) -> dict[str, Any] | None:
        r = stack.admin.call("GET", f"/hosts/{self.host_id}/status")
        return r.json()["report"] if r.status == 200 else None

    def comp(self, stack, typ: str) -> dict[str, Any] | None:
        rep = self.status(stack)
        if not rep:
            return None
        return next((c for c in rep["components"] if c["type"] == typ), None)


def probe_intent() -> dict[str, Any]:
    """The wizard's default probe intent, pointed at the test LAN instead of the internet (no external targets)."""
    names = list(LAN_NAMES)
    return {
        "mode": "netns",
        "heartbeat": {
            "interval_s": 10,
            "gateway": True,
            "dhcp": True,
            "dns": True,
            "ping": [LAN_GW],
            "dns_names": names,
        },
        "tests": {
            "dhcp": {"interval_s": 300},
            "dns": {"interval_s": 300, "names": names},
            "app": None,
            "throughput": None,
            "path": None,
            "wifi": None,
        },
    }


@pytest.fixture(scope="module")
def sc(stack, host_image):
    admin = stack.admin
    admin.post("/sites", {"site": SITE, "name": "Hall E2E", "timezone": "UTC"}, ok=(201,))
    admin.call("PATCH", f"/sites/{SITE}/release", {"version": stack.version}, ok=(200,))
    created = admin.post(
        "/hosts",
        {"name": "e2e-host-1", "site": SITE, "shapes": ["collector", "dashboard", "probe"]},
        ok=(201,),
    )
    host_id, enrol = created["host"]["host_id"], created["enrol"]
    ids = {"collector": "col-e2e", "dashboard": "dash-e2e", "probe": "probe-e2e"}
    from test_a23_support import default_intent  # noqa: PLC0415

    cids = {}
    for typ in ("collector", "dashboard", "probe"):
        cfg = probe_intent() if typ == "probe" else default_intent(typ, "e2e-host-1")
        r = admin.post(f"/hosts/{host_id}/components", {"type": typ, "id": ids[typ], "config": cfg}, ok=(201,))
        cids[typ] = r["component_id"]
    host = start_host(stack, "a23")
    s = Scenario(host, host_id, enrol["command"], enrol["token"], ids, cids)
    try:
        build_lan(host)
        t0 = time.monotonic()
        s.install = host.run(enrol["command"], timeout=600)  # the one-liner, verbatim
        s.t_cmd_done = time.monotonic()
        (stack.artifacts / "a23-install.txt").write_text(f"rc={s.install.rc} in {s.t_cmd_done - t0:.0f}s\n{s.install.text}\n")
        assert s.install.rc == 0, s.install
        yield s
    finally:
        try:
            (stack.artifacts / "a23-host-diagnostics.txt").write_text(host.diagnostics())
            (stack.artifacts / "a23-host-journal.txt").write_text(host.journal(None, 400))
        finally:
            host.remove()


def healthy_all(sc, stack):
    rep = sc.status(stack)
    if not rep:
        return None
    by = {c["type"]: c for c in rep["components"]}
    return rep if all(t in by and by[t]["health"] == "ok" for t in ("collector", "dashboard", "probe")) else None


def comp_facts(stack, sc, typ):
    items = stack.admin.get(f"/hosts/{sc.host_id}/components")["items"]
    return next(c for c in items if c["type"] == typ).get("facts") or {}


@pytest.fixture(scope="module")
def conv(stack, sc):
    """Everything the admin does after the one-liner: wait for the host's facts, try (and fail) to give the probe
    the management interface, assign the veth test port, then wait for all three shapes to report healthy."""
    admin = stack.admin

    def facts():
        h = admin.get(f"/hosts/{sc.host_id}")
        return h if h["facts"] and h["facts"].get("interfaces") else None

    sc.facts = wait_for(facts, 90, 2, "the host's facts with interfaces", sc.host.agent_log)
    sc.mgmt_refused = admin.call(
        "PUT",
        f"/components/{sc.cids['probe']}/ports",
        {"ports": [{"id": "c01", "iface": "eth0", "role": "client"}]},
    )
    sc.ports_put = admin.call(
        "PUT",
        f"/components/{sc.cids['probe']}/ports",
        {"ports": [{"id": "c01", "iface": "vp0", "role": "client"}]},
    )
    try:
        rep = wait_for(
            lambda: healthy_all(sc, stack),
            CONVERGE_S + 240,
            3,
            "collector, dashboard and probe healthy",
            sc.host.diagnostics,
        )
    finally:
        sc.t_converged = time.monotonic()
    sc.report = rep
    return sc


def test_host_enrols_and_reports_facts(stack, sc, conv):
    h = conv.facts
    assert h["state"] == "enrolled"
    f = h["facts"]
    assert f["os"] == {"id": "ubuntu", "version": "24.04"}
    assert f["arch"] == "amd64" and f["hostname"] == "e2e-a23" and f["machine_id"]
    assert h["mgmt_ip"] == sc.host.ip
    assert h["agent_version"] == stack.version
    names = {i["name"]: i for i in f["interfaces"]}
    assert names["eth0"]["in_use_by"] == "mgmt" and names["eth0"]["default_route"] is True
    assert "vp0" in names
    assert sorted(h["shapes"]) == ["collector", "dashboard", "probe"]
    # the enrol token is spent and the secret never reached the install output or the agent journal
    assert "expa_" not in sc.install.text
    # (sudo itself logs the argv of the documented one-liner, `sudo bash -s -- expe_...`: that line is the operator's
    # own command, single use and valid for an hour; everything the agent and the components log is scanned)
    journal = "\n".join(ln for ln in sc.host.journal(None, 3000).splitlines() if "COMMAND=" not in ln)
    assert not dockerhost.TOKEN_RE.findall(journal), "token-shaped string in the journal"


def test_management_interface_is_refused_for_probe_ports(conv):
    r = conv.mgmt_refused
    assert r.status == 422 and r.json()["error"]["code"] == "mgmt_interface_refused", r
    assert conv.ports_put.status == 200 and conv.ports_put.json()["ports"][0]["iface"] == "vp0"


def test_all_shapes_converge_healthy_within_two_minutes(stack, conv):
    took = conv.t_converged - conv.t_cmd_done
    (stack.artifacts / "a23-timing.txt").write_text(
        f"one-liner finished -> all shapes healthy: {took:.0f}s (limit {CONVERGE_S}s)\n"
    )
    assert took < CONVERGE_S, f"shapes took {took:.0f}s to converge after the command (limit {CONVERGE_S}s)"
    by = {c["type"]: c for c in conv.report["components"]}
    for t in ("collector", "dashboard", "probe"):
        assert by[t]["health"] == "ok", by[t]
    h = stack.admin.get(f"/hosts/{conv.host_id}")
    assert h["applied_version"] == h["desired_version"]


def test_probe_data_reaches_the_collector(stack, sc, conv):
    cf = comp_facts(stack, sc, "collector")
    ip, port = cf["listen"].rsplit(":", 1)
    fp = cf["tls_fingerprint_sha256"]
    tok = json.loads(sc.host.run("cat $(find /etc/exp/dashboard -name collector_tokens.json | head -1)").out)
    token = tok[sc.ids["collector"]]
    auth = {"Authorization": f"Bearer {token}"}
    sc.collector = (ip, int(port), fp, auth)

    def probe_row():
        items = jget(ip, int(port), "/api/v1/probes", fp, auth)["items"]
        row = next((p for p in items if p["probe"] == sc.ids["probe"]), None)
        return row if row and row["last_seen"] and row["newest_s"] is not None and row["newest_s"] < 120 else None

    row = wait_for(probe_row, 150, 5, "the collector listing the probe as reporting", sc.host.diagnostics)
    assert row["site"] == SITE
    now = time.time()
    frm, to = (time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t)) for t in (now - 3600, now + 300))
    recs = jget(ip, int(port), f"/api/v1/records?probe={sc.ids['probe']}&from={frm}&to={to}&limit=50", fp, auth)
    assert recs["items"], "no measurement records for the probe in the collector"
    tests = {r.get("test") for r in recs["items"]}
    assert tests & {"gateway", "dhcp_hb", "dns_hb"}, tests
    # the manager's fleet view carries the probe's own health, from the agent's status reports
    assert any(c["type"] == "probe" and c["health"] == "ok" for c in sc.status(stack)["components"])


def test_dashboard_opens_via_sso_handoff(stack, sc, conv):
    df = comp_facts(stack, sc, "dashboard")
    base = df["url"]
    ip = re.sub(r"^https://|/$", "", base).split(":")[0]
    fp = df["tls_fingerprint_sha256"]
    r = stack.admin.call("POST", f"/dashboards/{sc.ids['dashboard']}/sso", None)
    assert r.status == 200, r
    assert "text/html" in r.headers["content-type"] and r.headers.get("cache-control") == "no-store"
    form = r.text
    action = html.unescape(re.search(r'<form id="sso" method="post" action="([^"]+)"', form).group(1))
    token = html.unescape(re.search(r'name="token" value="([^"]+)"', form).group(1))
    assert action == f"{base.rstrip('/')}/auth/sso"
    # a token on its own is not a session; follow the auto-submit form as the browser would
    st, hdrs, _ = pinned_request(ip, 443, "GET", "/api/v1/states", fp)
    assert st == 401, "the dashboard API must refuse requests without a session"
    st, hdrs, body = pinned_request(
        ip,
        443,
        "POST",
        "/auth/sso",
        fp,
        {"Content-Type": "application/x-www-form-urlencoded"},
        urllib.parse.urlencode({"token": token}).encode(),
    )
    assert st in (302, 303), (st, body[:200])
    cookies = [c.split(";", 1)[0] for c in hdrs.get("set-cookie", [])]
    assert cookies, hdrs
    st, _h, body = pinned_request(ip, 443, "GET", "/api/v1/states", fp, {"Cookie": "; ".join(cookies)})
    assert st == 200, (st, body[:300])
    assert "items" in json.loads(body)
    # the handoff token is single use (jti): replaying it opens no second session
    st2, h2, _ = pinned_request(
        ip,
        443,
        "POST",
        "/auth/sso",
        fp,
        {"Content-Type": "application/x-www-form-urlencoded"},
        urllib.parse.urlencode({"token": token}).encode(),
    )
    assert st2 in (400, 401, 403) and not h2.get("set-cookie"), (st2, h2)
