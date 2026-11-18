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
from dataclasses import dataclass, field
from typing import Any

import pytest
from conftest import MANAGER_NAME, start_host
from expharness import dockerhost
from expharness.dockerhost import LAN_GW, LAN_NAMES, build_lan, jget, pinned_get, wait_for

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
        "heartbeat": {"interval_s": 10, "gateway": True, "dhcp": True, "dns": True, "ping": [LAN_GW], "dns_names": names},
        "tests": {"dhcp": {"interval_s": 300}, "dns": {"interval_s": 300, "names": names}, "app": None,
                  "throughput": None, "path": None, "wifi": None},
    }


@pytest.fixture(scope="module")
def sc(stack, host_image):
    admin = stack.admin
    admin.post("/sites", {"site": SITE, "name": "Hall E2E", "timezone": "UTC"}, ok=(201,))
    admin.call("PATCH", f"/sites/{SITE}/release", {"version": stack.version}, ok=(200,))
    created = admin.post("/hosts", {"name": "e2e-host-1", "site": SITE, "shapes": ["collector", "dashboard", "probe"]}, ok=(201,))
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


def test_00_explore(stack, sc):
    def facts():
        h = stack.admin.get(f"/hosts/{sc.host_id}")
        return h if h["facts"] and h["facts"].get("interfaces") else None

    h = wait_for(facts, 90, 3, "interfaces in facts", sc.host.agent_log)
    print(json.dumps(h, indent=1)[:2500])
    r = stack.admin.call("PUT", f"/components/{sc.cids['probe']}/ports", {"ports": [{"id": "c01", "iface": "eth0", "role": "client"}]})
    print("MGMT", r)
    r = stack.admin.call("PUT", f"/components/{sc.cids['probe']}/ports", {"ports": [{"id": "c01", "iface": "vp0", "role": "client"}]})
    print("PORTS", r)
    t0 = time.monotonic()
    for _ in range(40):
        rep = sc.status(stack)
        print(int(time.monotonic() - t0), [(c["type"], c["health"]) for c in (rep or {}).get("components", [])])
        time.sleep(5)
    print(sc.host.diagnostics())
