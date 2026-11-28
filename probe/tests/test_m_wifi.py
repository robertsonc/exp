"""`wifi_hb` / `wifi_join` (02-probe.md 5.11) against a fake wpa_supplicant control socket and fake tools."""
from __future__ import annotations

import json
import signal
import socket
import threading

import pytest
from measure_support import make_ctx
from netfakes import FakeEnv, FakeIcmp, ScriptRunner, answer_all, link_rules, silent, validate_measurements

from exp_probe import wifi as wf
from exp_probe.checks import wifi as wc
from exp_probe.lease import write_lease

SSID = "EVENT-FREE"
PORTS = [{"id": "c01", "iface": "t0", "role": "client"},
         {"id": "w01", "iface": "wlp3s0", "role": "wifi", "ssid": SSID, "band": "5"}]
STATUS_OK = {"bssid": "AA:BB:CC:00:11:22", "freq": "5180", "ssid": SSID, "id": "0", "mode": "station",
             "key_mgmt": "OWE", "wpa_state": "COMPLETED", "address": "02:00:00:00:01:00"}
SIGNAL = {"RSSI": "-52", "LINKSPEED": "433", "NOISE": "-92", "FREQUENCY": "5180"}
CURL_204 = json.dumps({"exitcode": 0, "response_code": 204, "time_total": 0.03, "time_namelookup": 0.001,
                       "time_connect": 0.01, "time_starttransfer": 0.03, "size_download": 0, "num_redirects": 0,
                       "scheme": "http"})
CURL_PORTAL = json.dumps({"exitcode": 0, "response_code": 200, "time_total": 0.2, "time_namelookup": 0.001,
                          "time_connect": 0.01, "time_starttransfer": 0.2, "size_download": 5120, "num_redirects": 1,
                          "url_effective": "https://portal.venue.example/login", "scheme": "https"})


class FakeCtrl:
    def __init__(self, status: dict[str, str] | None = None, sig: dict[str, str] | None = None) -> None:
        self.status = dict(STATUS_OK if status is None else status)
        self.sig = dict(SIGNAL if sig is None else sig)
        self.sent: list[str] = []
        self.down = False

    def request(self, cmd: str) -> str:
        self.sent.append(cmd)
        if self.down:
            raise wf.CtrlUnavailable("wpa_supplicant control socket /run/x is missing")
        if cmd == "STATUS":
            return "".join(f"{k}={v}\n" for k, v in self.status.items())
        if cmd == "SIGNAL_POLL":
            return "".join(f"{k}={v}\n" for k, v in self.sig.items())
        return "OK\n"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    wc.reset_state()
    t = {"now": 1000.0}
    monkeypatch.setattr(wc, "MONO", lambda: t["now"])
    monkeypatch.setattr(wc, "SLEEP", lambda s: t.__setitem__("now", t["now"] + s))
    yield t
    wc.reset_state()


def runner(curl: str = CURL_204, curl_rc: int = 0) -> ScriptRunner:
    r = ScriptRunner()
    for i in ("t0", "wlp3s0"):
        link_rules(r, i)
    r.on("curl", out=curl, rc=curl_rc)
    r.on("iw", "dev", "wlp3s0", "survey", "dump", out=(
        "Survey data from wlp3s0\n\tfrequency:\t\t\t5160 MHz\n\tnoise:\t\t\t\t-97 dBm\n"
        "Survey data from wlp3s0\n\tfrequency:\t\t\t5180 MHz [in use]\n\tnoise:\t\t\t\t-95 dBm\n"))
    return r


def hb(tmp_path, monkeypatch, ctrl: FakeCtrl, *, r: ScriptRunner | None = None, icmp=None, leased=("c01", "w01"),
       lease_doc=None, **kw):
    monkeypatch.setattr(wc, "CTRL_FACTORY", lambda paths, port: ctrl)
    ctx = make_ctx(tmp_path, ports=PORTS, port_id="w01", runner=r or runner(), leased=leased, lease_doc=lease_doc,
                   env=FakeEnv(icmp=icmp if icmp is not None else FakeIcmp(answer_all(0.0024))), **kw)
    out = wc.wifi_hb(ctx)
    validate_measurements(out)
    return out, ctx


def test_ok_beat_has_the_catalog_shape(tmp_path, monkeypatch):
    (m,), ctx = hb(tmp_path, monkeypatch, FakeCtrl())
    assert m.test == "wifi_hb" and m.outcome == "ok", m.error
    assert m.labels == {"port": "w01", "ssid": SSID, "band": "5"}
    assert m.metrics == {"link_up": 1, "rssi_dbm": -52, "noise_dbm": -92, "snr_db": 40, "tx_rate_mbps": 433,
                         "channel": 36, "gw_rtt_ms": 2.4}
    assert m.detail["on_target"] is True and m.detail["security"] == "owe" and m.detail["portal"] is False
    assert m.detail["bssid"] == "aa:bb:cc:00:11:22" and m.detail["band_seen"] == "5"
    curl = [c for c in ctx.runner.calls if "curl" in c]
    assert len(curl) == 1 and curl[0][:4] == ["ip", "netns", "exec", "exp-w01"]       # inside the namespace


def test_portal_check_is_cached_and_rerun_on_a_new_lease(tmp_path, monkeypatch, _clean):
    ctrl = FakeCtrl()
    r = runner()
    _, ctx = hb(tmp_path, monkeypatch, ctrl, r=r)
    curls = lambda: sum("curl" in c for c in r.calls)  # noqa: E731
    _clean["now"] += 10
    wc.wifi_hb(ctx)
    ctrl.status["bssid"] = "aa:bb:cc:00:11:33"            # a roam inside the same network keeps the verdict
    wc.wifi_hb(ctx)
    assert curls() == 1
    _clean["now"] += wc.PORTAL_EVERY_S
    wc.wifi_hb(ctx)
    assert curls() == 2
    doc = json.loads(ctx.paths.lease_file("w01").read_text())
    doc["ts"] = "2099-01-01T00:00:00.000Z"                # a new lease: check again at once
    ctx.paths.lease_file("w01").write_text(json.dumps(doc))
    wc.wifi_hb(ctx)
    assert curls() == 3


def test_captive_portal_is_degraded_and_reported_never_clicked(tmp_path, monkeypatch):
    (m,), ctx = hb(tmp_path, monkeypatch, FakeCtrl(), r=runner(CURL_PORTAL),
                   lease_doc={"state": "bound", "ip": "10.9.0.31", "prefix": 22, "router": ["10.9.0.1"], "dns": ["10.9.0.1"],
                              "captive_portal_uri": "https://portal.venue.example/api"})
    assert m.outcome == "degraded" and m.detail["portal"] is True
    assert "captive portal" in m.error and "204" in m.detail["portal_reason"]
    assert m.detail["dhcp_captive_portal_uri"] == "https://portal.venue.example/api"
    assert [c for c in ctx.runner.calls if "curl" in c][0][-1].endswith("/generate_204")   # only the check URL


def test_unknown_portal_when_the_check_cannot_run(tmp_path, monkeypatch):
    (m,), _ = hb(tmp_path, monkeypatch, FakeCtrl(), r=runner("", curl_rc=6))
    assert m.outcome == "ok" and m.detail["portal"] is None and "connectivity check failed" in m.detail["portal_reason"]


def test_not_associated_fails_and_asks_to_rejoin_at_most_every_60s(tmp_path, monkeypatch, _clean):
    ctrl = FakeCtrl({"wpa_state": "SCANNING", "address": "02:00:00:00:01:00"})
    (m,), _ = hb(tmp_path, monkeypatch, ctrl)
    assert m.outcome == "fail" and m.labels["ssid"] == "none" and m.metrics == {"link_up": 0}
    assert m.detail["rejoin"] is True and "SCANNING" in m.error
    _clean["now"] += 10
    (m2,), _ = hb(tmp_path, monkeypatch, ctrl)
    assert m2.detail["rejoin"] is False
    _clean["now"] += 50
    (m3,), _ = hb(tmp_path, monkeypatch, ctrl)
    assert m3.detail["rejoin"] is True
    assert ctrl.sent.count("REASSOCIATE") == 2


def test_wrong_ssid_is_fail_with_on_target_false(tmp_path, monkeypatch):
    (m,), _ = hb(tmp_path, monkeypatch, FakeCtrl({**STATUS_OK, "ssid": "Guest"}))
    assert m.outcome == "fail" and m.labels["ssid"] == "Guest" and m.detail["on_target"] is False
    assert m.detail["target_ssid"] == SSID and "not the target" in m.error


def test_associated_without_a_lease_fails(tmp_path, monkeypatch):
    (m,), _ = hb(tmp_path, monkeypatch, FakeCtrl(), leased=("c01",))
    assert m.outcome == "fail" and "no DHCP lease" in m.error and m.metrics["link_up"] == 1


def test_silent_gateway_fails(tmp_path, monkeypatch):
    (m,), _ = hb(tmp_path, monkeypatch, FakeCtrl(), icmp=FakeIcmp(silent))
    assert m.outcome == "fail" and m.error == "no reply from gateway 10.1.0.1 over Wi-Fi"


def test_weak_signal_is_degraded_and_noise_falls_back_to_the_survey(tmp_path, monkeypatch):
    (m,), _ = hb(tmp_path, monkeypatch, FakeCtrl(sig={"RSSI": "-81", "LINKSPEED": "6", "NOISE": "9999"}))
    assert m.outcome == "degraded" and "weak signal -81 dBm" in m.error
    assert m.metrics["noise_dbm"] == -95 and m.metrics["snr_db"] == 14 and "SNR 14 dB" in m.error


def test_supplicant_down_is_error(tmp_path, monkeypatch):
    ctrl = FakeCtrl()
    ctrl.down = True
    (m,), _ = hb(tmp_path, monkeypatch, ctrl)
    assert m.outcome == "error" and "wpa_supplicant not running" in m.error and "exp-probe-wifi@w01" in m.error


def test_ssid_escapes_are_decoded():
    assert wf.decode_ssid(r"caf\xc3\xa9 \"x\" \\") == 'café "x" \\'


def test_heartbeats_stand_aside_while_a_join_runs(tmp_path, monkeypatch):
    from exp_probe.checks.gateway import gateway
    assert wf.begin_join("w01")
    try:
        out, ctx = hb(tmp_path, monkeypatch, FakeCtrl())
        assert out == [] and gateway(ctx) == []
    finally:
        wf.end_join("w01")


# ------------------------------------------------------------------------------------------ join

class JoinCtrl(FakeCtrl):
    """DISCONNECT -> DISCONNECTED; RECONNECT -> AUTHENTICATING, ASSOCIATED after `assoc` s, COMPLETED after
    `done` s (time read from the patched monotonic clock)."""

    def __init__(self, clock: dict[str, float], assoc: float = 0.2, done: float = 0.3, ssid: str = SSID,
                 never: bool = False) -> None:
        super().__init__()
        self.clock, self.assoc, self.done, self.never = clock, assoc, done, never
        self.t0: float | None = None
        self.status["ssid"] = ssid

    def request(self, cmd: str) -> str:
        if cmd == "RECONNECT":
            self.t0 = self.clock["now"]
        if cmd == "STATUS":
            if self.t0 is None:
                self.status["wpa_state"] = "DISCONNECTED"
            else:
                dt = self.clock["now"] - self.t0
                self.status["wpa_state"] = ("SCANNING" if self.never or dt < self.assoc
                                            else "ASSOCIATED" if dt < self.done else "COMPLETED")
        return super().request(cmd)


def join(tmp_path, monkeypatch, ctrl, clock, *, renew=True):
    monkeypatch.setattr(wc, "CTRL_FACTORY", lambda paths, port: ctrl)
    ctx = make_ctx(tmp_path, ports=PORTS, port_id="w01", runner=runner(), leased=("c01", "w01"))
    ctx.paths.pid_file("w01").write_text("4242\n")
    sent: list[tuple[int, int]] = []

    def kill(pid, sig):
        sent.append((pid, sig))
        if renew:
            clock["now"] += 0.15
            write_lease(ctx.paths, ctx.cfg.port("w01"), {"state": "bound", "event": "renew", "ip": "10.1.0.31",
                                                         "prefix": 24, "router": ["10.1.0.1"], "dns": ["10.1.0.2"]})
    monkeypatch.setattr(wc, "KILL", kill)
    # leases written within one second share a timestamp: make the renewed one distinguishable
    doc = json.loads(ctx.paths.lease_file("w01").read_text())
    doc["ts"] = "2026-01-01T00:00:00.000Z"
    ctx.paths.lease_file("w01").write_text(json.dumps(doc))
    out = wc.wifi_join(ctx)
    validate_measurements(out)
    return out, sent


def test_join_measures_assoc_auth_and_dhcp(tmp_path, monkeypatch, _clean):
    ctrl = JoinCtrl(_clean)
    (m,), sent = join(tmp_path, monkeypatch, ctrl, _clean)
    assert m.test == "wifi_join" and m.outcome == "ok", m.error
    assert m.labels == {"port": "w01", "ssid": SSID}
    assert 180 <= m.metrics["assoc_ms"] <= 260 and 50 <= m.metrics["auth_ms"] <= 150
    assert m.metrics["total_ms"] == pytest.approx(m.metrics["assoc_ms"] + m.metrics["auth_ms"] + m.metrics["dhcp_ms"], abs=0.5)
    assert ctrl.sent[0] == "DISCONNECT" and "RECONNECT" in ctrl.sent
    assert sent == [(4242, signal.SIGUSR1)]
    assert m.detail["security"] == "owe" and m.detail["reason"] == "scheduled"
    assert not wf.joining("w01")


def test_join_that_never_associates_fails(tmp_path, monkeypatch, _clean):
    (m,), sent = join(tmp_path, monkeypatch, JoinCtrl(_clean, never=True), _clean)
    assert m.outcome == "fail" and "no association" in m.error and sent == []
    assert not wf.joining("w01")


def test_join_to_another_ssid_fails(tmp_path, monkeypatch, _clean):
    (m,), _ = join(tmp_path, monkeypatch, JoinCtrl(_clean, ssid="Guest"), _clean)
    assert m.outcome == "fail" and m.labels["ssid"] == "Guest" and "not the target" in m.error


def test_join_without_a_renewed_lease_fails(tmp_path, monkeypatch, _clean):
    (m,), _ = join(tmp_path, monkeypatch, JoinCtrl(_clean), _clean, renew=False)
    assert m.outcome == "fail" and "no DHCP lease" in m.error and "dhcp_ms" not in m.metrics


def test_slow_join_is_degraded(tmp_path, monkeypatch, _clean):
    (m,), _ = join(tmp_path, monkeypatch, JoinCtrl(_clean, assoc=4.0, done=5.5), _clean)
    assert m.outcome == "degraded" and "join took" in m.error


# ------------------------------------------------------------------------------- control socket

def test_ctrl_talks_to_a_datagram_socket_and_skips_events(tmp_path):
    from conftest import make_config

    from exp_probe.config import Paths
    paths = Paths(run_dir=tmp_path / "r")
    port = make_config(ports=PORTS).port("w01")
    d = wf.ctrl_dir(paths, "w01")
    d.mkdir(parents=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(str(d / "wlp3s0"))

    def serve():
        data, addr = srv.recvfrom(4096)
        srv.sendto(b"<3>CTRL-EVENT-SCAN-STARTED ", addr)
        srv.sendto(b"wpa_state=COMPLETED\nssid=" + SSID.encode() + b"\n" if data == b"STATUS" else b"FAIL\n", addr)
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        out = wf.parse_kv(wf.Ctrl(paths, port).request("STATUS"))
    finally:
        th.join(2)
        srv.close()
    assert out == {"wpa_state": "COMPLETED", "ssid": SSID}
    assert not [p for p in paths.port_run_dir("w01").iterdir() if p.name.startswith(".ctrl-")]    # client socket gone


def test_ctrl_missing_socket_is_unavailable(tmp_path):
    from conftest import make_config

    from exp_probe.config import Paths
    with pytest.raises(wf.CtrlUnavailable):
        wf.Ctrl(Paths(run_dir=tmp_path), make_config(ports=PORTS).port("w01")).request("STATUS")
