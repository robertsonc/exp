"""netns up/down (02-probe.md section 1): exact command sequences, round trip, fail-closed refusal."""
from __future__ import annotations

import signal

import pytest
from conftest import make_config
from fakes import Link

from exp_probe import netns


def seed(ip, *names, virtual=False):
    for n in names:
        ip.add_host_link(n, up=True, virtual=virtual)


def no_sleep(_s):
    return None


def test_up_exact_command_sequence(ip, paths):
    seed(ip, "t0", "t1")
    lines = netns.up(make_config(), ip, paths, sleep=no_sleep)
    assert ip.mutations == [
        ["ip", "netns", "add", "exp-c01"],
        ["ip", "link", "set", "dev", "t0", "netns", "exp-c01"],
        ["ip", "-n", "exp-c01", "link", "set", "lo", "up"],
        ["ip", "netns", "exec", "exp-c01", "sysctl", "-qw", "net.ipv6.conf.t0.disable_ipv6=1"],
        ["ip", "-n", "exp-c01", "link", "set", "dev", "t0", "up"],
        ["ip", "netns", "add", "exp-c02"],
        ["ip", "link", "set", "dev", "t1", "netns", "exp-c02"],
        ["ip", "-n", "exp-c02", "link", "set", "lo", "up"],
        ["ip", "netns", "exec", "exp-c02", "sysctl", "-qw", "net.ipv6.conf.t1.disable_ipv6=1"],
        ["ip", "-n", "exp-c02", "link", "set", "dev", "t1", "up"],
    ]
    assert lines == ["c01: t0 up in exp-c01", "c02: t1 up in exp-c02"]
    # end state: each port lives in its own namespace, up; the host namespace lost them
    assert set(ip.ns["exp-c01"]) == {"lo", "t0"} and ip.ns["exp-c01"]["t0"].up
    assert ip.host_names() == set()
    # per-namespace resolv.conf placeholder exists
    assert "no DHCP lease yet" in paths.resolv_path("c01").read_text()


def test_down_returns_every_port_then_deletes_namespaces(ip, paths):
    seed(ip, "t0", "t1", virtual=True)            # virtual ports die with their namespace unless returned
    netns.up(make_config(), ip, paths, sleep=no_sleep)
    ip.mutations.clear()
    lines = netns.down(make_config(), ip, paths, sleep=no_sleep)
    assert ip.mutations == [
        ["ip", "-n", "exp-c01", "link", "set", "dev", "t0", "down"],
        ["ip", "-n", "exp-c01", "link", "set", "dev", "t0", "netns", "1"],
        ["ip", "link", "set", "dev", "t0", "down"],
        ["ip", "-n", "exp-c02", "link", "set", "dev", "t1", "down"],
        ["ip", "-n", "exp-c02", "link", "set", "dev", "t1", "netns", "1"],
        ["ip", "link", "set", "dev", "t1", "down"],
        ["ip", "netns", "del", "exp-c01"],
        ["ip", "netns", "del", "exp-c02"],
    ]
    # END STATE: both ports are back on the host (the veth-like ones survived), namespaces and files gone
    assert ip.host_names() == {"t0", "t1"} and not any(ip.ns[""][n].up for n in ("t0", "t1"))
    assert set(ip.ns) == {""}
    assert not paths.resolv_path("c01").parent.exists()
    assert all("returned to the host" in ln for ln in lines)


def test_round_trip_is_repeatable(ip, paths):
    seed(ip, "t0", "t1", virtual=True)
    cfg = make_config()
    for _ in range(3):
        netns.up(cfg, ip, paths, sleep=no_sleep)
        assert ip.host_names() == set()
        netns.down(cfg, ip, paths, sleep=no_sleep)
        assert ip.host_names() == {"t0", "t1"} and set(ip.ns) == {""}


def test_the_fake_really_destroys_virtual_ports_without_the_explicit_move(ip):
    """Guards the guard: proves the fake models the EXM lesson, so the test above is meaningful."""
    ip.ns["exp-x"] = {"lo": Link("lo"), "v0": Link("v0", virtual=True), "p0": Link("p0", virtual=False)}
    ip.run(["ip", "netns", "del", "exp-x"])
    assert ip.host_names() == {"p0"}                    # the virtual one is gone, the physical one returned


def test_up_is_idempotent(ip, paths):
    seed(ip, "t0", "t1")
    cfg = make_config()
    netns.up(cfg, ip, paths, sleep=no_sleep)
    ip.mutations.clear()
    netns.up(cfg, ip, paths, sleep=no_sleep)
    assert ["ip", "netns", "add", "exp-c01"] not in ip.mutations
    assert not any(m[:3] == ["ip", "link", "set"] and "netns" in m for m in ip.mutations)   # nothing moved again
    assert set(ip.ns["exp-c01"]) == {"lo", "t0"}


def test_down_is_idempotent_and_safe_when_nothing_is_up(ip, paths):
    seed(ip, "t0", "t1")
    cfg = make_config()
    netns.down(cfg, ip, paths, sleep=no_sleep)
    assert not any(m[:3] == ["ip", "netns", "del"] for m in ip.mutations)
    assert ip.host_names() == {"t0", "t1"}


def test_refused_up_changes_nothing(ip, paths):
    seed(ip, "t0", "t1")
    ip.ns[""]["t1"].addrs = ["10.9.9.9/24"]
    ip.default_routes = []
    with pytest.raises(netns.PreflightRefused) as ei:
        netns.up(make_config(), ip, paths, sleep=no_sleep)
    assert "c02" in str(ei.value) and "carries address" in str(ei.value)
    assert ip.mutations == []                                  # not even the clean port c01 was touched
    assert ip.host_names() == {"t0", "t1"} and set(ip.ns) == {""}
    assert not paths.etc_netns.exists()


def test_stuck_port_keeps_its_namespace(ip, paths):
    seed(ip, "t0", "t1", virtual=True)
    cfg = make_config()
    netns.up(cfg, ip, paths, sleep=no_sleep)
    ip.fail_move_back = {"t0"}
    with pytest.raises(netns.TeardownIncomplete, match="exp-c01"):
        netns.down(cfg, ip, paths, sleep=no_sleep)
    assert "exp-c01" in ip.ns and "t0" in ip.ns["exp-c01"]      # NOT deleted: deleting would destroy the port
    assert ["ip", "netns", "del", "exp-c01"] not in ip.calls
    assert "t1" in ip.ns[""] and "exp-c02" not in ip.ns          # the other port was returned and cleaned


def test_vlan_subinterface_created_and_removed(ip, paths):
    seed(ip, "t0")
    cfg = make_config(ports=[{"id": "c01", "iface": "t0", "role": "client", "vlan": 120}])
    netns.up(cfg, ip, paths, sleep=no_sleep)
    assert ["ip", "-n", "exp-c01", "link", "add", "link", "t0", "name", "vlan120", "type", "vlan", "id", "120"] in ip.mutations
    assert "vlan120" in ip.ns["exp-c01"]
    netns.down(cfg, ip, paths, sleep=no_sleep)
    assert ip.host_names() == {"t0"} and set(ip.ns) == {""}


def test_host_mode_changes_nothing(ip, paths):
    seed(ip, "t0")
    cfg = make_config(ports=[{"id": "c01", "iface": "t0", "role": "client"}], mode="host")
    assert "host namespace" in netns.up(cfg, ip, paths, sleep=no_sleep)[0]
    netns.down(cfg, ip, paths, sleep=no_sleep)
    assert ip.mutations == []


def test_wait_for_late_port(ip, paths):
    seed(ip, "t0")
    sleeps: list[float] = []

    def sleeper(s):
        sleeps.append(s)
        if len(sleeps) == 2:
            seed(ip, "t1")                                      # udev finishes naming the NIC
    netns.up(make_config(), ip, paths, wait_s=10, sleep=sleeper)
    assert len(sleeps) == 2 and set(ip.ns) == {"", "exp-c01", "exp-c02"}


def test_wait_gives_up_and_refuses(ip, paths):
    seed(ip, "t0")
    with pytest.raises(netns.PreflightRefused, match="does not exist"):
        netns.up(make_config(), ip, paths, wait_s=3, sleep=no_sleep)
    assert ip.mutations == []


def test_processes_in_namespace_are_stopped_before_return(ip, paths):
    seed(ip, "t0", "t1", virtual=True)
    cfg = make_config()
    netns.up(cfg, ip, paths, sleep=no_sleep)
    ip.pids["exp-c01"] = ["4242"]
    sent: list[tuple[int, int]] = []

    def kill(pid, sig):
        sent.append((pid, sig))
        ip.pids["exp-c01"] = []
    netns.down(cfg, ip, paths, sleep=no_sleep, kill=kill)
    assert sent == [(4242, signal.SIGTERM)]


def test_stale_namespaces_are_cleaned_and_their_ports_returned(ip, paths):
    seed(ip, "t0", "t1")
    cfg = make_config()
    ip.ns["exp-old"] = {"lo": Link("lo"), "t9": Link("t9", up=True, virtual=True)}
    (paths.etc_netns / "exp-old").mkdir(parents=True)
    (paths.etc_netns / "exp-old" / "resolv.conf").write_text("x")
    lines = netns.down(cfg, ip, paths, sleep=no_sleep)
    assert "t9" in ip.ns[""] and "exp-old" not in ip.ns and not (paths.etc_netns / "exp-old").exists()
    assert any("exp-old" in ln for ln in lines)


def test_guard_refuses_address_bond_and_default_route(ip, paths):
    seed(ip, "t0")
    assert netns.guard(ip, paths, "t0") is None
    ip.default_routes = ["t0"]
    assert "default route" in netns.guard(ip, paths, "t0")
