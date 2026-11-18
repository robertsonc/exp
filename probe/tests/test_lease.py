"""Lease holder: udhcpc argv, the hook's end state (lease.json, resolv.conf, address commands)."""
from __future__ import annotations

import json
import os
import stat

from conftest import make_config
from exp_common.schema import iso_to_ms
from fakes import FakeIp

from exp_probe import lease, netns


def cfg1(**kw):
    return make_config(ports=[{"id": "c01", "iface": "t0", "role": "client", **kw}])


def test_udhcpc_argv(paths):
    cfg = cfg1(dhcp={"hostname": "exp-hallb-c01", "vendor_class": "exp-probe", "client_id": "mac"})
    argv = lease.udhcpc_argv(cfg, cfg.ports[0], paths)
    assert argv[:6] == ["ip", "netns", "exec", "exp-c01", "busybox", "udhcpc"]
    assert "-f" in argv and "-R" in argv                          # foreground, release on stop
    assert argv[argv.index("-i") + 1] == "t0"
    assert argv[argv.index("-V") + 1] == "exp-probe"
    assert "hostname:exp-hallb-c01" in argv
    assert argv[argv.index("-s") + 1].endswith("hooks/udhcpc-hook")
    assert argv[argv.index("-p") + 1] == str(paths.run_dir / "c01" / "udhcpc.pid")
    assert "0x3d:00" not in " ".join(argv)                         # client_id mac: busybox default
    assert all(isinstance(a, str) for a in argv)


def test_client_id_hostname_variant(paths):
    cfg = cfg1(dhcp={"hostname": "abc", "client_id": "hostname"})
    argv = lease.udhcpc_argv(cfg, cfg.ports[0], paths)
    assert argv[-2:] == ["-x", "0x3d:00" + b"abc".hex()]


def test_default_identity_is_derived_not_personal(paths):
    cfg = cfg1()
    argv = lease.udhcpc_argv(cfg, cfg.ports[0], paths)
    assert "hostname:exp-probe-t1-c01" in argv


def test_hook_script_is_executable_and_execs_the_cli():
    st = os.stat(lease.HOOK_PATH)
    assert st.st_mode & stat.S_IXUSR
    assert "udhcpc-hook" in lease.HOOK_PATH.read_text()


BOUND = {"interface": "t0", "ip": "10.1.0.31", "mask": "24", "router": "10.1.0.1", "dns": "10.1.0.2 1.1.1.1",
         "lease": "3600", "serverid": "10.1.0.1", "domain": "event.lan", "broadcast": "10.1.0.255", "mtu": "1500",
         "opt114": "68747470733a2f2f706f7274616c2e6578616d706c652f"}


def test_bound_event_end_state(paths):
    ip = FakeIp()
    cfg = cfg1()
    assert lease.hook(cfg, "bound", BOUND, ip, paths) == 0
    doc = json.loads(paths.lease_file("c01").read_text())
    assert doc["state"] == "bound" and doc["ip"] == "10.1.0.31" and doc["prefix"] == 24
    assert doc["router"] == ["10.1.0.1"] and doc["dns"] == ["10.1.0.2", "1.1.1.1"]
    assert doc["lease_s"] == 3600 and doc["serverid"] == "10.1.0.1" and doc["mtu"] == 1500
    assert doc["captive_portal_uri"] == "https://portal.example/" and doc["hostname_sent"] == "exp-probe-t1-c01"
    assert doc["schema"] == "exp.probe.lease/1" and iso_to_ms(doc["ts"])
    assert stat.S_IMODE(os.stat(paths.lease_file("c01")).st_mode) == 0o644
    resolv = paths.resolv_path("c01").read_text()
    assert "nameserver 10.1.0.2" in resolv and "nameserver 1.1.1.1" in resolv and "search event.lan" in resolv
    assert ["ip", "addr", "replace", "10.1.0.31/24", "dev", "t0", "broadcast", "10.1.0.255",
            "valid_lft", "3600", "preferred_lft", "3600"] in ip.calls
    assert ["ip", "route", "replace", "default", "via", "10.1.0.1", "dev", "t0"] in ip.calls
    assert ["ip", "link", "set", "dev", "t0", "mtu", "1500"] in ip.calls
    assert lease.has_lease(lease.read_lease(paths, "c01"))
    # no stray temp files next to lease.json (atomic write)
    assert sorted(p.name for p in paths.port_run_dir("c01").iterdir()) == ["lease.json"]


def test_deconfig_resets_state(paths):
    ip = FakeIp()
    cfg = cfg1()
    lease.hook(cfg, "bound", BOUND, ip, paths)
    lease.hook(cfg, "deconfig", {"interface": "t0"}, ip, paths)
    assert lease.read_lease(paths, "c01")["state"] == "none" and not lease.has_lease(lease.read_lease(paths, "c01"))
    assert paths.resolv_path("c01").read_text() == netns.PLACEHOLDER_RESOLV
    assert ["ip", "-4", "addr", "flush", "dev", "t0", "scope", "global"] in ip.calls


def test_leasefail_records_transition_not_every_retry(paths):
    ip = FakeIp()
    cfg = cfg1()
    for _ in range(3):
        lease.hook(cfg, "leasefail", {"interface": "t0"}, ip, paths)
    doc = lease.read_lease(paths, "c01")
    assert doc["state"] == "leasefail" and doc["retries_since"] == 2 and doc["first_failed"]


def test_hostile_lease_values_are_ignored(paths):
    ip = FakeIp()
    cfg = cfg1()
    env = {**BOUND, "ip": "10.1.0.31; reboot", "router": "$(id) 10.1.0.1 evil", "dns": "not-an-ip 9.9.9.9",
           "domain": "x\nnameserver 6.6.6.6", "search": "bad;domain"}
    lease.hook(cfg, "bound", env, ip, paths)
    assert lease.read_lease(paths, "c01") is None or lease.read_lease(paths, "c01")["state"] != "bound"   # bad ip: no bind
    env["ip"] = "10.1.0.31"
    lease.hook(cfg, "bound", env, ip, paths)
    doc = lease.read_lease(paths, "c01")
    assert doc["router"] == ["10.1.0.1"] and doc["dns"] == ["9.9.9.9"]
    resolv = paths.resolv_path("c01").read_text()
    assert "6.6.6.6" not in resolv and "search" not in resolv        # injected lines / unsafe search are dropped
    assert not any(any(ch in arg for ch in ";$()") for call in ip.calls for arg in call)


def test_unknown_interface_is_ignored(paths):
    assert lease.hook(cfg1(), "bound", {**BOUND, "interface": "zz9"}, FakeIp(), paths) == 0
    assert lease.read_lease(paths, "c01") is None


def test_run_lease_execs_udhcpc_with_hook_environment(paths, tmp_path):
    ip = FakeIp()
    ip.ns["exp-c01"] = {}
    got = {}
    cfg = cfg1()
    lease.run_lease(cfg, "c01", ip, paths, "/etc/exp/probe/config.json", "/opt/exp/probe/1/bin/exp-probe",
                    exec_fn=lambda f, a, e: got.update(file=f, argv=a, env=e))
    assert got["file"] == "ip" and got["argv"][:5] == ["ip", "netns", "exec", "exp-c01", "busybox"]
    assert got["env"]["EXP_PROBE_BIN"] == "/opt/exp/probe/1/bin/exp-probe"
    assert got["env"]["EXP_PROBE_CONFIG"] == "/etc/exp/probe/config.json"
    assert lease.read_lease(paths, "c01")["state"] == "none"


def test_run_lease_refusals(paths, capsys):
    ip = FakeIp()
    called = []
    kw = {"exec_fn": lambda *a: called.append(a)}
    assert lease.run_lease(cfg1(), "c01", ip, paths, "c", "e", **kw) == 3          # namespace missing
    ip.ns["exp-s01"] = {}
    target = make_config(ports=[{"id": "s01", "iface": "t2", "role": "target", "address": "10.1.0.250/24",
                                 "gateway": "10.1.0.1"}])
    assert lease.run_lease(target, "s01", ip, paths, "c", "e", **kw) == 2           # not a client port
    host = make_config(ports=[{"id": "c01", "iface": "t0", "role": "client"}], mode="host")
    assert lease.run_lease(host, "c01", ip, paths, "c", "e", **kw) == 0
    assert called == []
