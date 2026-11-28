"""Wi-Fi ports: radio (phy) moves, preflight refusals, the wpa_supplicant config and supervisor (02-probe.md 5.11)."""
from __future__ import annotations

import stat

import pytest
from conftest import make_config
from exp_common.config import ConfigError
from fakes import FakeIp

from exp_probe import netns, preflight
from exp_probe import wifi as wf
from exp_probe.config import Port
from exp_probe.runner import CmdResult

PORTS = [{"id": "c01", "iface": "t0", "role": "client"},
         {"id": "w01", "iface": "wlp3s0", "role": "wifi", "ssid": "EVENT-FREE"}]


class WifiIp(FakeIp):
    """FakeIp plus the `iw phy ... set netns` moves of whole radios (and refusing `ip link set netns` for them)."""

    def __init__(self) -> None:
        super().__init__()
        self.phys: dict[str, str] = {}             # iface -> phy

    def run(self, argv, timeout=10, **kw):
        a = list(argv)
        ns = ""
        core = a
        if a[:3] == ["ip", "netns", "exec"]:
            ns, core = a[3], a[4:]
        if core[:1] == ["cat"] and core[1].endswith("/phy80211/name"):
            self.calls.append(a)
            iface = core[1].split("/")[4]
            if iface in self.phys and self.where(iface) == ns:
                return CmdResult(tuple(a), 0, self.phys[iface] + "\n")
            return CmdResult(tuple(a), 1, "", "No such file or directory")
        if core[:2] == ["iw", "phy"] and core[3:5] == ["set", "netns"]:
            self.calls.append(a)
            self.mutations.append(a)
            phy = core[2]
            dest = core[6] if core[5] == "name" else ("" if core[5] == "1" else core[5])
            moved = False
            for iface, p in self.phys.items():
                cur = self.where(iface)
                if p == phy and cur == ns and dest in self.ns:
                    self.ns[dest][iface] = self.ns[cur].pop(iface)
                    moved = True
            return CmdResult(tuple(a), 0 if moved else 1, "", "" if moved else "command failed: No such device")
        if a[:2] == ["ip", "-n"] and "netns" in a[4:] and a[-3:-1] != ["set", "dev"]:
            name = a[a.index("dev") + 1] if "dev" in a else ""
            if name in self.phys:
                self.calls.append(a)
                return CmdResult(tuple(a), 2, "", "RTNETLINK answers: Invalid argument")
        if a[:4] == ["ip", "link", "set", "dev"] and len(a) > 5 and a[5] == "netns" and a[4] in self.phys:
            self.calls.append(a)
            return CmdResult(tuple(a), 2, "", "RTNETLINK answers: Invalid argument")
        return super().run(a, timeout, **kw)


def sysnet(paths, iface: str, phy: str | None = "phy0", rfkill: str | None = None) -> None:
    d = paths.sys_class_net / iface
    d.mkdir(parents=True, exist_ok=True)
    if phy:
        (d / "wireless").mkdir(exist_ok=True)
        (d / "phy80211").mkdir(exist_ok=True)
        (d / "phy80211" / "name").write_text(phy + "\n")
        if rfkill:
            k = d / "phy80211" / "rfkill3"
            k.mkdir()
            (k / "hard").write_text("1\n" if rfkill == "hard" else "0\n")
            (k / "soft").write_text("1\n" if rfkill == "soft" else "0\n")


@pytest.fixture
def wip(paths):
    ip = WifiIp()
    ip.add_host_link("lo")
    ip.add_host_link("t0")
    ip.add_host_link("wlp3s0")
    ip.phys["wlp3s0"] = "phy0"
    sysnet(paths, "t0", phy=None)
    sysnet(paths, "wlp3s0")
    return ip


# --------------------------------------------------------------------------------------- netns

def test_up_moves_the_radio_and_down_brings_it_back(wip, paths):
    cfg = make_config(ports=PORTS)
    netns.up(cfg, wip, paths)
    assert wip.where("wlp3s0") == "exp-w01" and wip.where("t0") == "exp-c01"
    assert ["iw", "phy", "phy0", "set", "netns", "name", "exp-w01"] in wip.mutations
    assert not [m for m in wip.mutations if m[:4] == ["ip", "link", "set", "dev"] and m[4] == "wlp3s0" and "netns" in m]
    netns.up(cfg, wip, paths)                                       # idempotent: nothing moves twice
    assert sum(m[:2] == ["iw", "phy"] for m in wip.mutations) == 1
    netns.down(cfg, wip, paths, sleep=lambda s: None, kill=lambda p, s: None)
    assert wip.where("wlp3s0") == "" and wip.where("t0") == ""
    assert ["ip", "netns", "exec", "exp-w01", "iw", "phy", "phy0", "set", "netns", "1"] in wip.mutations
    assert "exp-w01" not in wip.ns


def test_a_stale_wifi_namespace_returns_its_radio(wip, paths):
    netns.up(make_config(ports=PORTS), wip, paths)
    gone = netns.remove_stale(make_config(ports=PORTS[:1]), wip, paths, sleep=lambda s: None, kill=lambda p, s: None)
    assert gone == ["exp-w01"] and wip.where("wlp3s0") == ""


# ------------------------------------------------------------------------------------ preflight

def reasons(cfg, ip, paths):
    res = preflight.check(cfg, ip, paths)
    return {c.port_id: c.reasons for c in res.checks}, res


def test_a_lone_unblocked_radio_is_ok(wip, paths):
    r, res = reasons(make_config(ports=PORTS), wip, paths)
    assert res.ok and r["w01"] == [] and wip.mutations == []


def test_a_shared_radio_is_refused_and_names_mgmt(wip, paths):
    wip.add_host_link("mgmt0")
    sysnet(paths, "mgmt0", phy="phy0")
    r, res = reasons(make_config(ports=PORTS), wip, paths)
    assert not res.ok and "also carries mgmt0 (the management interface)" in r["w01"][0]


@pytest.mark.parametrize("kind,text", [("soft", "rfkill unblock"), ("hard", "hard-blocked")])
def test_a_blocked_radio_is_refused(wip, paths, kind, text):
    sysnet(paths, "wlp3s0", rfkill=kind)
    r, res = reasons(make_config(ports=PORTS), wip, paths)
    assert not res.ok and any(text in x for x in r["w01"])


def test_networkmanager_or_another_supplicant_is_refused(wip, paths):
    wip.extra[("nmcli", "-t", "-f", "DEVICE,STATE", "device")] = CmdResult((), 0, "t0:unmanaged\nwlp3s0:connected\n")
    p = paths.proc / "811"
    p.mkdir(parents=True)
    (p / "cmdline").write_bytes(b"/sbin/wpa_supplicant\0-c\0/run/netplan/wpa-wlp3s0.conf\0-iwlp3s0\0")
    ours = paths.proc / "900"
    ours.mkdir()
    (ours / "cmdline").write_bytes(b"wpa_supplicant\0-i\0wlp3s0\0-c\0/run/exp/probe/w01/wpa_supplicant.conf\0")
    r, res = reasons(make_config(ports=PORTS), wip, paths)
    assert not res.ok
    assert any("NetworkManager manages wlp3s0" in x for x in r["w01"])
    assert any("another wpa_supplicant (pid 811)" in x for x in r["w01"])
    assert not any("900" in x for x in r["w01"])


def test_role_wifi_on_a_wired_port_is_refused(wip, paths):
    cfg = make_config(ports=[{"id": "w01", "iface": "t0", "role": "wifi", "ssid": "X"}])
    r, res = reasons(cfg, wip, paths)
    assert not res.ok and "is not a Wi-Fi interface" in r["w01"][0]


# ----------------------------------------------------------------------------- supplicant config

def port(**kw):
    return make_config(ports=[{"id": "w01", "iface": "wlp3s0", "role": "wifi", "ssid": "EVENT-FREE", **kw}]).port("w01")


def test_auto_offers_owe_then_open_with_a_hex_ssid_and_no_credential(paths):
    text = wf.wpa_conf(make_config(ports=PORTS), port(), paths)
    assert f"ssid={b'EVENT-FREE'.hex()}" in text and '"EVENT-FREE"' not in text
    assert text.index("key_mgmt=OWE") < text.index("key_mgmt=NONE")
    assert "ieee80211w=2" in text and "mac_addr=0" in text and "preassoc_mac_addr=0" in text
    assert "psk" not in text and "password" not in text and "freq_list" not in text
    assert f"ctrl_interface=DIR={paths.run_dir}/w01/wpa GROUP=root" in text


def test_security_band_and_country_options(paths):
    cfg = make_config(ports=PORTS)
    assert "key_mgmt=NONE" not in wf.wpa_conf(cfg, port(security="owe"), paths)
    assert "key_mgmt=OWE" not in wf.wpa_conf(cfg, port(security="open"), paths)
    t5 = wf.wpa_conf(cfg, port(band="5", country="NL"), paths)
    with pytest.raises(ConfigError):
        port(country="nl")                                   # the schema takes upper-case ISO codes only
    assert "country=NL" in t5
    fl = [ln for ln in t5.splitlines() if "freq_list" in ln][0].split("=")[1].split()
    assert fl[0] == "5180" and "5825" in fl and "2412" not in fl
    t6 = wf.wpa_conf(cfg, port(band="6"), paths)
    assert "5955" in t6 and "7115" in t6


def test_an_ssid_cannot_inject_config(paths):
    evil = 'x"\n}\nnetwork={\nssid="y'
    text = wf.wpa_conf(make_config(ports=PORTS), Port(id="w01", iface="wlp3s0", role="wifi", raw={"ssid": evil}), paths)
    assert text.count("network={") == 2 and evil not in text and evil.encode().hex() in text


def test_channel_mapping():
    assert wf.freq_to_channel(2412) == (1, "2.4") and wf.freq_to_channel(2484) == (14, "2.4")
    assert wf.freq_to_channel(5180) == (36, "5") and wf.freq_to_channel(5825) == (165, "5")
    assert wf.freq_to_channel(5955) == (1, "6") and wf.freq_to_channel(None) == (None, None)


def test_supervisor_writes_a_0600_config_and_execs_in_the_namespace(wip, paths):
    cfg = make_config(ports=PORTS)
    netns.up(cfg, wip, paths)
    got = {}
    assert wf.run_wifi(cfg, "w01", wip, paths, exec_fn=lambda f, a, e: got.update(f=f, a=a)) == 0
    p = wf.conf_path(paths, "w01")
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(wf.ctrl_dir(paths, "w01").stat().st_mode) == 0o700
    assert got["a"] == ["ip", "netns", "exec", "exp-w01", "wpa_supplicant", "-i", "wlp3s0", "-D", "nl80211", "-c", str(p)]


def test_supervisor_refuses_other_roles_and_a_missing_namespace(wip, paths, capsys):
    cfg = make_config(ports=PORTS)
    assert wf.run_wifi(cfg, "c01", wip, paths, exec_fn=lambda *a: None) == 2
    assert wf.run_wifi(cfg, "w01", wip, paths, exec_fn=lambda *a: None) == 3
    assert "exp-probe-netns.service" in capsys.readouterr().err
