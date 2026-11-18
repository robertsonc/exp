"""The M1 measurement tests on real namespaces, a real DHCP/DNS server (dnsmasq) and real curl
(02-probe.md section 11 items 3, 4, 5). Run through probe/tests/harness/run.sh (privileged container).

Lab: a bridge `hv-lab` in the container's root namespace with a PINNED MAC, 10.99.0.1 (gateway, DHCP
server) and 10.99.0.2 (the resolver DHCP hands out), dnsmasq on it; three veth "ports" c01..c03 moved into
namespaces exp-c0N with a real udhcpc lease each; a `rogue` namespace on the same bridge (10.99.0.3) that
can run a second DHCP server / a DNS interceptor; a `wan` namespace behind the root namespace's forwarding
holding the "internet" target 10.88.0.1. Cutting egress = a policy rule that prohibits forwarding for
traffic arriving from the bridge; the control path (pinned to hv-wan) is unaffected."""
from __future__ import annotations

import json
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest
from harness_support import BIN, _real_environment, make_cfg, net, paths, run, wait_for  # noqa: F401  (fixtures by name)
from httpstub import HttpStub
from netfakes import validate_measurements

from exp_probe import netns
from exp_probe.checks import register_all
from exp_probe.checks.app import app
from exp_probe.checks.dhcp import dhcp, dhcp_hb
from exp_probe.checks.dns import dns_hb
from exp_probe.checks.gateway import gateway
from exp_probe.checks.trace import trace
from exp_probe.config import parse_config
from exp_probe.runner import CommandRunner
from exp_probe.scheduler import REGISTRY, Rotation, Scheduler, TestContext, WorkerPool

pytestmark = [pytest.mark.harness,
              pytest.mark.skipif(not shutil.which("dnsmasq") or not shutil.which("busybox") or not shutil.which("curl"),
                                 reason="needs dnsmasq, busybox and curl")]
R = CommandRunner()
GW, DNS_IP, ROGUE_IP, TARGET = "10.99.0.1", "10.99.0.2", "10.99.0.3", "10.88.0.1"
NAMES = ["google.com", "apple.com", "microsoft.com"]


def hb_config(ports, **extra):
    heartbeat = {"interval_s": 10, "ping": [GW, TARGET], "dns_names": NAMES, "alternate_resolver": GW,
                 "trace": {"target": TARGET, "pace_ms": 20, "max_hops": 8, "timeout_s": 2, "control_path": True}}
    heartbeat.update(extra.pop("heartbeat", {}))
    return parse_config({"schema": "exp.probe.config/1", "probe_id": "probe-h1", "site": "lab", "collector": None,
                         "mode": "netns", "mgmt_iface": "hv-wan",
                         "ports": [{"id": pid, "iface": iface, "role": "client"} for pid, iface in ports],
                         "heartbeat": heartbeat, **extra})


class Lab:
    def __init__(self, net, paths, run, tmp_path):
        self.net, self.paths, self.run, self.tmp = net, paths, run, tmp_path
        self.procs: list[subprocess.Popen] = []
        self.holders: list[subprocess.Popen] = []
        self.cfg = None
        self.cfgfile = tmp_path / "config.json"

    def sh(self, *argv, check=True):
        return self.run(*argv, check=check)

    def popen(self, argv, **kw):
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
        self.procs.append(p)
        return p

    def dnsmasq(self, *args, ns=None):
        base = ["dnsmasq", "--no-daemon", "--user=root", "--bind-interfaces", "--except-interface=lo", "--no-hosts",
                "--no-resolv", f"--dhcp-leasefile={self.tmp / ('leases-' + str(len(self.procs)))}"]
        argv = (["ip", "netns", "exec", ns] if ns else []) + base + list(args)
        return self.popen(argv)

    def build(self):
        s = self.sh
        # bridge with a pinned MAC, gateway + resolver addresses
        s("ip", "link", "add", "hv-lab", "type", "bridge")
        s("ip", "link", "set", "hv-lab", "address", "02:00:5e:10:00:01")
        s("ip", "addr", "add", f"{GW}/24", "dev", "hv-lab")
        s("ip", "addr", "add", f"{DNS_IP}/24", "dev", "hv-lab")
        s("ip", "link", "set", "hv-lab", "up")
        self.ports = []
        for pid in ("c01", "c02", "c03"):
            iface = self.net.veth(pid)
            s("ip", "link", "set", f"{iface}p", "master", "hv-lab")
            self.ports.append((pid, iface))
        # rogue namespace on the same bridge
        s("ip", "netns", "add", "rogue")
        s("ip", "link", "add", "hv-rg", "type", "veth", "peer", "name", "hv-rgp")
        s("ip", "link", "set", "hv-rg", "netns", "rogue")
        s("ip", "link", "set", "hv-rgp", "master", "hv-lab")
        s("ip", "link", "set", "hv-rgp", "up")
        s("ip", "-n", "rogue", "addr", "add", f"{ROGUE_IP}/24", "dev", "hv-rg")
        s("ip", "-n", "rogue", "link", "set", "hv-rg", "up")
        s("ip", "-n", "rogue", "link", "set", "lo", "up")
        # wan namespace: the "internet" target, reached by forwarding through the root namespace
        s("ip", "netns", "add", "wan")
        s("ip", "link", "add", "hv-wan", "type", "veth", "peer", "name", "wv")
        s("ip", "link", "set", "wv", "netns", "wan")
        s("ip", "addr", "add", "10.77.0.1/30", "dev", "hv-wan")
        s("ip", "link", "set", "hv-wan", "up")
        s("ip", "-n", "wan", "addr", "add", "10.77.0.2/30", "dev", "wv")
        s("ip", "-n", "wan", "addr", "add", f"{TARGET}/32", "dev", "lo")
        s("ip", "-n", "wan", "link", "set", "wv", "up")
        s("ip", "-n", "wan", "link", "set", "lo", "up")
        s("ip", "-n", "wan", "route", "add", "default", "via", "10.77.0.1")
        s("ip", "route", "add", f"{TARGET}/32", "via", "10.77.0.2")
        s("sysctl", "-w", "net.ipv4.ip_forward=1")
        s("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
        # DHCP + DNS server on the bridge
        self.dnsmasq("--interface=hv-lab", "--dhcp-range=10.99.0.50,10.99.0.80,5m", f"--dhcp-option=3,{GW}",
                     f"--dhcp-option=6,{DNS_IP}", "--local=/invalid/", *[f"--address=/{n}/10.99.0.9" for n in NAMES])
        self.cfg = hb_config(self.ports)
        self.cfgfile.write_text(json.dumps(self.cfg.raw))
        netns.up(self.cfg, R, self.paths)
        common = ["--config", str(self.cfgfile), "--state-dir", str(self.paths.state_dir), "--run-dir", str(self.paths.run_dir)]
        for pid, _ in self.ports:
            self.holders.append(subprocess.Popen(["python3", str(BIN), "lease", pid, *common],
                                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for pid, _ in self.ports:
            doc = wait_for(lambda pid=pid: self._bound(pid), timeout=40)
            assert doc, f"{pid} got no lease within 40 s"

    def _bound(self, pid):
        try:
            doc = json.loads(self.paths.lease_file(pid).read_text())
        except (OSError, ValueError):
            return None
        return doc if doc.get("state") == "bound" else None

    def scheduler(self, emitted, cfg=None):
        register_all()
        return Scheduler(cfg or self.cfg, self.paths, R, emitted.extend, WorkerPool(8), registry=REGISTRY,
                         rotation=Rotation(None))

    def ctx(self, test_port, cfg=None, path="", explicit=True):
        cfg = cfg or self.cfg
        return TestContext(cfg, self.paths, R, time.time, cfg.port(test_port), path, time.time(), explicit)

    def teardown(self):
        for p in self.holders:
            p.send_signal(signal.SIGTERM)
        for p in self.holders:
            try:
                p.wait(15)
            except subprocess.TimeoutExpired:
                p.kill()
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        if self.cfg is not None:
            try:
                netns.down(self.cfg, R, self.paths)
            except (OSError, netns.TeardownIncomplete):
                pass
        for argv in (["ip", "rule", "del", "priority", "100"], ["ip", "netns", "del", "rogue"], ["ip", "netns", "del", "wan"],
                     ["ip", "link", "del", "hv-wan"], ["ip", "link", "del", "hv-rgp"], ["ip", "link", "del", "hv-lab"],
                     ["ip", "route", "del", f"{TARGET}/32"]):
            self.sh(*argv, check=False)


@pytest.fixture
def lab(net, paths, run, tmp_path):
    lb = Lab(net, paths, run, tmp_path)
    try:
        lb.build()
        yield lb
    finally:
        lb.teardown()


def by(ms, test, **labels):
    return [m for m in ms if m.test == test and all(m.labels.get(k) == v for k, v in labels.items())]


# ---------------------------------------------------------------------------------- item 3: cadence

def test_three_ports_produce_schema_valid_heartbeats_every_10s_and_each_cycle_ends_before_7s(lab):
    import threading

    from exp_common.schema import iso_to_ms
    stamped: list = []
    sched = lab.scheduler([])
    sched.emit = lambda ms: stamped.extend((time.time(), m) for m in ms)
    stop = threading.Event()
    t = threading.Thread(target=sched.run, args=(stop,), daemon=True)
    t.start()
    try:
        end = time.time() + 50
        while time.time() < end and len({int(s // 10) for s, m in stamped if m.test == "gateway"}) < 4:
            time.sleep(0.5)
    finally:
        stop.set()
        t.join(10)
        sched.pool.shutdown(True, 15)
    emitted = [m for _, m in stamped]
    validate_measurements(emitted)
    cycles: dict[int, list[float]] = {}                       # cycle boundary -> arrival times of its records
    gw_cycles: dict[int, int] = {}
    for arrived, m in stamped:
        c = int(iso_to_ms(m.ts) // 10000) * 10
        cycles.setdefault(c, []).append(arrived)
        if m.test == "gateway":
            gw_cycles[c] = gw_cycles.get(c, 0) + 1
    full = sorted(c for c, n in gw_cycles.items() if n == 3)                  # one gateway record per port
    assert len(full) >= 3, f"fewer than 3 complete heartbeat cycles: {gw_cycles}"
    assert all(b - a == 10 for a, b in zip(full, full[1:], strict=False)), full             # every 10 s, aligned
    for c in full:
        assert max(cycles[c]) - c < 7.0, f"cycle {c} took {max(cycles[c]) - c:.1f} s"
    gateways = [m for m in emitted if m.test == "gateway"]
    assert {m.labels["port"] for m in gateways} == {"c01", "c02", "c03"}
    assert {"gateway", "dhcp_hb", "dns_hb", "ping", "trace"} <= {m.test for m in emitted}
    bad = [(m.test, m.labels, m.outcome, m.error) for m in emitted if m.outcome != "ok"]
    assert not bad, bad
    for test in ("dhcp_hb", "dns_hb", "ping", "trace"):
        assert {m.labels["port"] for m in emitted if m.test == test} == {"c01", "c02", "c03"}, test      # rotation


# ----------------------------------------------------------------------------- item 4: negative controls

def test_blocking_dns_fails_dns_hb_but_not_dhcp_hb(lab):
    # DNS to the lease resolver goes to a MAC nobody has: silently dropped, no ICMP, no error
    lab.sh("ip", "-n", "exp-c01", "neigh", "replace", DNS_IP, "lladdr", "02:de:ad:00:00:01", "dev", "hv-c01", "nud", "permanent")
    ms = [*dns_hb(lab.ctx("c01")), *dhcp_hb(lab.ctx("c01"))]
    validate_measurements(ms)
    dhcp_rec = by(ms, "dns_hb", resolver_kind="dhcp")[0]
    alt = by(ms, "dns_hb", resolver_kind="alternate")[0]
    assert dhcp_rec.outcome == "fail" and "no answer" in dhcp_rec.error and "rtt_ms" not in dhcp_rec.metrics
    assert alt.outcome == "ok"                                    # the edge is fine: only the DHCP resolver is dead
    hb = by(ms, "dhcp_hb")[0]
    assert hb.outcome == "ok" and hb.metrics["offers"] == 1 and hb.labels["server"] == GW


@pytest.mark.parametrize("ping_check", [False, True], ids=["rogue-no-ping-check", "rogue-ping-check"])
def test_rogue_dhcp_server_is_flagged(lab, ping_check):
    lab.dnsmasq("--interface=hv-rg", "--port=0", "--dhcp-range=10.99.0.200,10.99.0.210,5m",
                f"--dhcp-option=3,{ROGUE_IP}", *(() if ping_check else ("--no-ping",)), ns="rogue")
    time.sleep(1.5)
    ctx = lab.ctx("c01")
    ctx.cfg.tests["dhcp"] = {"interval_s": 300, "offer_collect_s": 5.0}          # a ping-checking server answers late
    (m,) = dhcp_hb(ctx)
    validate_measurements([m])
    assert m.detail["rogue_suspect"] is True and m.outcome == "degraded", (m.detail, m.error)
    assert set(m.detail["servers"]) == {GW, ROGUE_IP} and m.metrics["offers"] == 2
    ms = [o["ms"] for o in m.detail["offer_list"]]
    if ping_check:
        assert max(ms) > 1000                                    # the ping-checking rogue really was late
    # SR-18: DISCOVER only -- the rogue server never saw a REQUEST, so it recorded no lease
    assert (lab.tmp / "leases-1").read_text().strip() == ""


def test_dns_interception_is_detected(lab):
    lab.dnsmasq("--interface=hv-rg", f"--listen-address={ROGUE_IP}", "--address=/invalid/10.99.0.99",
                "--address=/google.com/10.99.0.9", "--address=/apple.com/10.99.0.9", "--address=/microsoft.com/10.99.0.9", ns="rogue")
    time.sleep(1.5)
    cfg = hb_config(lab.ports, heartbeat={"alternate_resolver": ROGUE_IP})
    ms = dns_hb(TestContext(cfg, lab.paths, R, time.time, cfg.port("c01"), "", time.time(), True))
    validate_measurements(ms)
    alt = by(ms, "dns_hb", resolver_kind="alternate")[0]
    assert alt.outcome == "degraded" and alt.detail["nxdomain_canary"]["intercepted"] is True
    honest = by(ms, "dns_hb", resolver_kind="dhcp")[0]
    assert honest.outcome == "ok"


def test_captive_portal_is_detected_by_app_and_a_clean_204_is_not(lab):
    web = HttpStub(GW)
    try:
        cfg = hb_config(lab.ports, tests={"app": {"interval_s": 300, "targets": [
            {"app": "clean", "url": web.url("/cp-ok/generate_204")}, {"app": "portal", "url": web.url("/cp-200/generate_204")},
            {"app": "redirect", "url": web.url("/cp-302/generate_204")}, {"app": "ok", "url": web.url("/ok"), "apdex_t_ms": 1000}]}})
        ms = app(TestContext(cfg, lab.paths, R, time.time, cfg.port("c01"), "", time.time(), True))
    finally:
        web.close()
    validate_measurements(ms)
    got = {m.labels["app"]: m for m in ms}
    assert got["clean"].outcome == "ok" and got["ok"].outcome == "ok"
    for k in ("portal", "redirect"):
        assert got[k].outcome == "fail" and got[k].detail["captive_portal"] is True
    assert got["ok"].detail["ip"] == GW and got["ok"].metrics["status_code"] == 200


def test_dora_reconfirms_without_disturbing_the_held_lease(lab):
    before = lab._bound("c01")
    holder_pids = subprocess.run(["ip", "netns", "pids", "exp-c01"], capture_output=True, text=True).stdout.split()
    ctx = lab.ctx("c01")
    ctx.cfg.tests["dhcp"] = {"interval_s": 300, "offer_collect_s": 1.0}
    (m,) = dhcp(ctx)
    validate_measurements([m])
    assert m.outcome == "ok", (m.error, m.detail)
    assert m.detail["ip"] == before["ip"] == m.detail["held_ip"] and m.labels["server"] == GW
    assert m.metrics["lease_s"] == 300 and m.metrics["total_ms"] > 0
    after = lab._bound("c01")
    assert after["ip"] == before["ip"] and after["event"] == before["event"]          # the holder saw nothing
    assert subprocess.run(["ip", "netns", "pids", "exp-c01"], capture_output=True, text=True).stdout.split() == holder_pids
    addr = json.loads(lab.run("ip", "-n", "exp-c01", "-j", "-4", "addr", "show", "dev", "hv-c01").stdout)
    assert [a["local"] for a in addr[0]["addr_info"]] == [before["ip"]]               # still exactly one address


# --------------------------------------------------------------------------------- item 5: trace

def test_trace_names_the_last_hop_when_egress_is_cut_and_the_control_path_still_reaches(lab):
    ok = trace(lab.ctx("c01", path="test"))[0]
    assert ok.outcome == "ok" and ok.metrics["reached"] == 1 and ok.detail["hops"][0][1] == GW, ok.detail
    lab.sh("ip", "rule", "add", "iif", "hv-lab", "prohibit", "priority", "100")        # egress cut past the gateway
    cut = trace(lab.ctx("c01", path="test"))[0]
    ctl = trace(lab.ctx("c01", path="control"))[0]
    validate_measurements([cut, ctl])
    assert cut.outcome == "fail" and cut.metrics["reached"] == 0 and cut.detail["last_ip"] == GW
    assert f"path stops after {GW} (hop 1)" in cut.error
    assert ctl.outcome == "ok" and ctl.metrics["reached"] == 1 and ctl.labels["path"] == "control"
    assert gateway(lab.ctx("c01"))[0].outcome == "ok"                                    # the LAN is fine: only past-the-gateway is cut
