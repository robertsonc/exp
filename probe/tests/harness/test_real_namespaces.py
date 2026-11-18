"""Preflight on real veths and the netns round trip (02-probe.md section 11, items 1-2), plus a real
lease through busybox udhcpc and dnsmasq."""
from __future__ import annotations

import json
import shutil
import signal
import subprocess
from pathlib import Path

import pytest
from harness_support import BIN, _real_environment, cli, make_cfg, net, paths, run, wait_for  # noqa: F401  (fixtures are used by name)

from exp_probe import netns, preflight
from exp_probe.runner import CommandRunner

pytestmark = pytest.mark.harness
R = CommandRunner()


def two_ports(net):
    return [("c01", net.veth("c01")), ("c02", net.veth("c02"))]


# ------------------------------------------------------------------------------------- preflight

def test_clean_veths_are_approved_and_nothing_changes(net, paths):
    cfg = make_cfg(two_ports(net))
    before = net.snapshot()
    res = preflight.check(cfg, R, paths)
    assert res.ok, res.reasons_text()
    assert net.snapshot() == before


def test_port_with_an_address_is_refused_and_nothing_changes(net, paths, run):
    ports = two_ports(net)
    run("ip", "addr", "add", "192.0.2.10/24", "dev", ports[0][1])
    before = net.snapshot()
    res = preflight.check(make_cfg(ports), R, paths)
    assert [c.port_id for c in res.refused] == ["c01"] and "192.0.2.10/24" in res.refused[0].reasons[0]
    assert net.snapshot() == before and res.exit_code() == 1


def test_bridged_port_is_refused(net, paths, run):
    ports = two_ports(net)
    run("ip", "link", "add", "hv-br0", "type", "bridge")
    run("ip", "link", "set", ports[1][1], "master", "hv-br0")
    before = net.snapshot()
    res = preflight.check(make_cfg(ports), R, paths)
    assert [c.port_id for c in res.refused] == ["c02"] and "enslaved to hv-br0" in res.refused[0].reasons[0]
    assert net.snapshot() == before


def test_bonded_port_is_refused(net, paths, run):
    ports = two_ports(net)
    if not run("ip", "link", "add", "hv-bond0", "type", "bond", check=False).ok:
        pytest.skip("the kernel has no bonding driver")
    run("ip", "link", "set", ports[0][1], "down")
    run("ip", "link", "set", ports[0][1], "master", "hv-bond0")
    before = net.snapshot()
    res = preflight.check(make_cfg(ports), R, paths)
    assert "c01" in [c.port_id for c in res.refused] and "enslaved to hv-bond0" in res.refused[0].reasons[0]
    assert net.snapshot() == before


def test_default_route_holder_is_refused(net, paths, run):
    ports = two_ports(net)
    run("ip", "link", "add", "hv-def", "type", "veth", "peer", "name", "hv-defp")
    run("ip", "link", "set", "hv-def", "up")
    run("ip", "link", "set", "hv-defp", "up")
    run("ip", "route", "add", "default", "dev", "hv-def", "metric", "9999")
    cfg = make_cfg([ports[0], ("c03", "hv-def")])
    before = net.snapshot()
    res = preflight.check(cfg, R, paths)
    assert [c.port_id for c in res.refused] == ["c03"] and "default route" in res.refused[0].reasons[0]
    assert net.snapshot() == before


def test_mgmt_interface_and_missing_port_are_refused(net, paths):
    ports = two_ports(net)
    cfg = make_cfg([ports[0], ("c09", "hv-nope")], mgmt="eth9")
    res = preflight.check(cfg, R, paths)
    assert [c.port_id for c in res.refused] == ["c09"] and "does not exist" in res.refused[0].reasons[0]
    cfg2 = make_cfg(ports, mgmt="eth9")
    cfg2.mgmt_iface = ports[0][1]                                   # defence in depth, independent of the config check
    assert "management interface" in preflight.check(cfg2, R, paths).refused[0].reasons[0]


def test_cli_preflight_exit_codes(net, paths, run, tmp_path):
    ports = two_ports(net)
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(make_cfg(ports).raw))
    common = ["--config", str(cfgfile), "--state-dir", str(paths.state_dir), "--run-dir", str(paths.run_dir)]
    assert cli("preflight", *common).returncode == 0
    run("ip", "addr", "add", "192.0.2.10/24", "dev", ports[0][1])
    r = cli("preflight", *common)
    assert r.returncode == 1 and "REFUSED c01" in r.stderr


# ------------------------------------------------------------------------------------ round trip

def test_netns_round_trip_returns_every_port_and_keeps_the_veths(net, paths, run):
    ports = two_ports(net)
    cfg = make_cfg(ports)
    for _ in range(2):                                              # twice: it is repeatable
        netns.up(cfg, R, paths)
        assert {"exp-c01", "exp-c02"} <= net.ns_names()
        for pid, iface in ports:
            assert not net.host_has(iface)                          # moved out of the host namespace ...
            link = json.loads(run("ip", "-n", f"exp-{pid}", "-j", "link", "show", "dev", iface).stdout)[0]
            assert "UP" in link["flags"]                            # ... into its own, and up
            assert net.host_has(f"{iface}p")                        # the peer stays on the host
        netns.up(cfg, R, paths)                                     # idempotent
        netns.down(cfg, R, paths)
        for _pid, iface in ports:
            assert net.host_has(iface), f"{iface} was destroyed with its namespace"
            assert "UP" not in json.loads(run("ip", "-j", "link", "show", "dev", iface).stdout)[0]["flags"]
        assert not {"exp-c01", "exp-c02"} & net.ns_names()
        assert not Path("/etc/netns/exp-c01").exists()


def test_refused_up_leaves_the_host_untouched(net, paths, run):
    ports = two_ports(net)
    run("ip", "addr", "add", "192.0.2.10/24", "dev", ports[1][1])
    before = net.snapshot()
    with pytest.raises(netns.PreflightRefused):
        netns.up(make_cfg(ports), R, paths)
    assert net.snapshot() == before and not any(n.startswith("exp-") for n in net.ns_names())


def test_cli_netns_up_down(net, paths, tmp_path):
    ports = two_ports(net)
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(make_cfg(ports).raw))
    common = ["--config", str(cfgfile), "--state-dir", str(paths.state_dir), "--run-dir", str(paths.run_dir)]
    r = cli("netns", "up", "--wait-s", "0", *common)
    assert r.returncode == 0, r.stderr
    assert "c01: hv-c01 up in exp-c01" in r.stdout and "exp-c01" in net.ns_names()
    r = cli("netns", "down", *common)
    assert r.returncode == 0, r.stderr
    assert all(net.host_has(i) for _, i in ports) and not any(n.startswith("exp-") for n in net.ns_names())


def test_stale_namespace_is_cleaned_and_its_port_returned(net, paths, run):
    ports = two_ports(net)
    old = net.veth("old")
    run("ip", "netns", "add", "exp-old")
    run("ip", "link", "set", "dev", old, "netns", "exp-old")
    assert not net.host_has(old)
    netns.down(make_cfg(ports), R, paths)
    assert net.host_has(old) and "exp-old" not in net.ns_names()


# ------------------------------------------------------------------------------------------ lease

@pytest.mark.skipif(not shutil.which("dnsmasq") or not shutil.which("busybox"), reason="needs dnsmasq and busybox")
def test_real_lease_via_udhcpc_and_hook(net, paths, run, tmp_path):
    port = net.veth("c01", peer_addr="10.77.0.1/24")
    cfg = make_cfg([("c01", port)])
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(cfg.raw))
    leasefile = tmp_path / "dnsmasq.leases"
    dns = subprocess.Popen(["dnsmasq", "--no-daemon", "--port=0", "--user=root", "--bind-interfaces",
                            "--interface=hv-c01p", "--except-interface=lo", "--dhcp-range=10.77.0.50,10.77.0.60,2m",
                            "--dhcp-option=3,10.77.0.1", "--dhcp-option=6,10.77.0.1,10.77.0.2",
                            f"--dhcp-leasefile={leasefile}", "--no-hosts", "--no-resolv"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    holder = None
    try:
        netns.up(cfg, R, paths)
        common = ["--config", str(cfgfile), "--state-dir", str(paths.state_dir), "--run-dir", str(paths.run_dir)]
        holder = subprocess.Popen(["python3", str(BIN), "lease", "c01", *common],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        lease_json = paths.lease_file("c01")

        def bound():
            try:
                doc = json.loads(lease_json.read_text())
            except (OSError, ValueError):
                return None
            return doc if doc.get("state") == "bound" else None
        doc = wait_for(bound, timeout=30)
        assert doc, "no lease within 30 s"
        assert doc["ip"].startswith("10.77.0.") and doc["prefix"] == 24 and doc["router"] == ["10.77.0.1"]
        assert doc["dns"] == ["10.77.0.1", "10.77.0.2"] and doc["serverid"] == "10.77.0.1"
        assert doc["hostname_sent"] == "exp-probe-h1-c01"
        # the address and route really are in the namespace, not on the host
        addr = json.loads(run("ip", "-n", "exp-c01", "-j", "-4", "addr", "show", "dev", port).stdout)
        assert doc["ip"] in [a["local"] for a in addr[0]["addr_info"]]
        assert "10.77.0.1" in run("ip", "-n", "exp-c01", "route", "show", "default").stdout
        resolv = Path("/etc/netns/exp-c01/resolv.conf").read_text()
        assert "nameserver 10.77.0.1" in resolv and "nameserver 10.77.0.2" in resolv
        # what udhcpc sent
        pids = run("ip", "netns", "pids", "exp-c01").stdout.split()
        cmdlines = [Path(f"/proc/{p}/cmdline").read_bytes().split(b"\0") for p in pids]
        assert any(b"udhcpc" in c and b"-R" in c and b"-f" in c for c in cmdlines)
        assert wait_for(lambda: leasefile.exists() and "exp-probe-h1-c01" in leasefile.read_text(), 5)
    finally:
        if holder is not None:
            holder.send_signal(signal.SIGTERM)
            try:
                holder.wait(15)
            except subprocess.TimeoutExpired:
                holder.kill()
        dns.terminate()
        dns.wait(10)
        netns.down(cfg, R, paths)
        assert net.host_has(port)
