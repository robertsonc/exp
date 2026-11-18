"""Preflight (02-probe.md section 3): every refusal, and proof that a refusal changes nothing."""
from __future__ import annotations

import json

import pytest
from conftest import make_config
from fakes import FakeIp

from exp_probe import cli, preflight
from exp_probe.preflight import IN_NAMESPACE, OK, REFUSED


def host(ip: FakeIp, *names: str, **kw) -> None:
    for n in names:
        ip.add_host_link(n, up=True, **kw)


def verdicts(res):
    return {c.port_id: c.verdict for c in res.checks}


def test_clean_ports_are_approved(ip, paths):
    host(ip, "t0", "t1", "mgmt0")
    ip.default_routes = ["mgmt0"]
    ip.ns[""]["mgmt0"].addrs = ["10.9.0.5/24"]
    res = preflight.check(make_config(), ip, paths)
    assert res.ok and res.exit_code() == 0 and verdicts(res) == {"c01": OK, "c02": OK}
    assert ip.mutations == []


def test_port_with_global_address_refused_and_nothing_changed(ip, paths):
    host(ip, "t0", "t1")
    ip.ns[""]["t0"].addrs = ["10.1.2.3/24"]
    before = {n: (lk.up, list(lk.addrs)) for n, lk in ip.ns[""].items()}
    res = preflight.check(make_config(), ip, paths)
    assert not res.ok and res.exit_code() == 1
    assert verdicts(res) == {"c01": REFUSED, "c02": OK}
    assert "carries address 10.1.2.3/24" in res.refused[0].reasons[0]
    assert ip.mutations == []                                    # nothing changed
    assert before == {n: (lk.up, list(lk.addrs)) for n, lk in ip.ns[""].items()}


@pytest.mark.parametrize("kind,master_kind", [("bond", "bond0"), ("bridge", "br0"), ("team", "team0")])
def test_enslaved_port_refused(ip, paths, kind, master_kind):
    host(ip, "t0", "t1")
    ip.ns[""]["t0"].master = master_kind
    res = preflight.check(make_config(), ip, paths)
    assert verdicts(res)["c01"] == REFUSED
    assert f"enslaved to {master_kind}" in res.refused[0].reasons[0]
    assert ip.mutations == []


def test_bond_device_itself_refused(ip, paths):
    host(ip, "t1")
    ip.add_host_link("t0", up=True, kind="bond")
    res = preflight.check(make_config(), ip, paths)
    assert "is a bond device" in " ".join(res.refused[0].reasons)
    assert ip.mutations == []


def test_vlan_children_on_host_refused(ip, paths):
    host(ip, "t0", "t1")
    ip.add_host_link("t0.100", up=True, kind="vlan", parent="t0")
    res = preflight.check(make_config(), ip, paths)
    assert "stacked on it" in " ".join(res.refused[0].reasons)


def test_veth_peer_link_field_is_not_a_child(ip, paths):
    host(ip, "t0", "t1")
    ip.add_host_link("t0peer", up=True, kind="veth", parent="t0")     # veth lists its peer as "link"
    assert preflight.check(make_config(), ip, paths).ok


def test_default_route_holder_refused(ip, paths):
    host(ip, "t0", "t1")
    ip.default_routes = ["t1"]
    res = preflight.check(make_config(), ip, paths)
    assert verdicts(res) == {"c01": OK, "c02": REFUSED}
    assert "default route" in res.refused[0].reasons[0]
    assert ip.mutations == []


def test_ipv6_default_route_holder_refused(ip, paths):
    host(ip, "t0", "t1")
    ip.extra[("ip", "-6", "-j", "route", "show", "default")] = ip._r(
        ["ip"], 0, json.dumps([{"dst": "default", "dev": "t0"}]))
    assert verdicts(preflight.check(make_config(), ip, paths))["c01"] == REFUSED


def test_mgmt_iface_refused(ip, paths):
    host(ip, "t0", "mgmt0")
    # config validation already refuses this; the host-level check must still refuse independently
    # (defence in depth: a config edited behind the validator's back, or a NIC renamed by udev)
    cfg = make_config(ports=[{"id": "c01", "iface": "t0", "role": "client"}], mgmt="mgmt0")
    cfg.mgmt_iface = "t0"
    res = preflight.check(cfg, ip, paths)
    assert res.refused and "management interface" in res.refused[0].reasons[0]
    assert ip.mutations == []


def test_nonexistent_port_refused(ip, paths):
    host(ip, "t0")
    res = preflight.check(make_config(), ip, paths)
    assert verdicts(res) == {"c01": OK, "c02": REFUSED}
    assert "does not exist" in res.refused[0].reasons[0]


def test_port_already_in_its_namespace_is_fine(ip, paths):
    host(ip, "t1")
    ip.ns["exp-c01"] = {"lo": ip.ns[""].get("lo") or __import__("fakes").Link("lo"),
                        "t0": __import__("fakes").Link("t0", up=True, virtual=True)}
    res = preflight.check(make_config(), ip, paths)
    assert res.ok and verdicts(res) == {"c01": IN_NAMESPACE, "c02": OK}


def test_wifi_iface_with_client_role_refused(ip, paths):
    host(ip, "t0", "t1")
    (paths.sys_class_net / "t0" / "wireless").mkdir(parents=True)
    res = preflight.check(make_config(), ip, paths)
    assert verdicts(res)["c01"] == REFUSED and "Wi-Fi" in res.refused[0].reasons[0]
    ok = preflight.check(make_config(ports=[{"id": "c01", "iface": "t0", "role": "wifi"},
                                            {"id": "c02", "iface": "t1", "role": "client"}]), ip, paths)
    assert ok.ok
    assert ip.mutations == []


def test_no_carrier_on_every_port_gives_nic_hint(ip, paths):
    host(ip, "t0", "t1", carrier=False)
    res = preflight.check(make_config(), ip, paths)
    assert res.ok and any("NIC" in h and "not the cables" in h for h in res.hints)
    ip.ns[""]["t0"].carrier = True
    assert preflight.check(make_config(), ip, paths).hints == []


def test_unreadable_host_fails_closed(ip, paths):
    host(ip, "t0", "t1")
    ip.fail_all = True
    res = preflight.check(make_config(), ip, paths)
    assert not res.ok and res.exit_code() == 2 and res.errors and res.checks == []


def test_guard_helper(ip, paths):
    host(ip, "t0")
    assert preflight.guard(ip, paths, "t0") is None
    ip.ns[""]["t0"].addrs = ["192.0.2.9/24"]
    assert "carries address" in preflight.guard(ip, paths, "t0")


def test_cli_preflight_exit_codes_and_reasons(ip, paths, tmp_path, capsys):
    host(ip, "t0", "t1")
    ip.ns[""]["t0"].addrs = ["10.1.2.3/24"]
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(make_config().raw))
    argv = ["preflight", "--config", str(cfgfile), "--state-dir", str(paths.state_dir), "--run-dir", str(paths.run_dir)]
    assert cli.main(argv, runner=ip) == 1
    assert "REFUSED c01 (t0): carries address" in capsys.readouterr().err
    ip.ns[""]["t0"].addrs = []
    assert cli.main(argv, runner=ip) == 0
    ip.fail_all = True
    assert cli.main(argv, runner=ip) == 2
