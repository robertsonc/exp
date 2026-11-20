"""orchestrator fake: pyedgeconnect-shaped auth, flows, interface state, time series, health, alarms and scenarios."""
from __future__ import annotations

import http.client
import json
import urllib.parse

import pytest
from fakes_support import R, request

import fake_ca
from orchestrator import server as orch

T0 = 1_795_000_000.0
IP = "10.60.14.77"


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> float:
        return self.t


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def fake(clock):
    f = orch.start(now_fn=clock)
    yield f
    f.stop()


def call(fake, method, path, body=None, headers=None, key=True, **q) -> R:
    hdr = {"X-Auth-Token": fake.api_key} if key is True else dict(key or {})
    hdr.update(headers or {})
    qs = urllib.parse.urlencode(q)
    return request(fake.port, method, orch.PREFIX + path + ("?" + qs if qs else ""), body, hdr)


def session_headers(fake) -> dict[str, str]:
    user, pw = fake.user
    r = call(fake, "POST", "/authentication/login", {"user": user, "password": pw, "token": "", "loginType": 0}, key=None)
    assert r.status == 200
    cookies = {}
    conn = http.client.HTTPConnection("127.0.0.1", fake.port, timeout=10)
    conn.request("POST", orch.PREFIX + "/authentication/login", json.dumps({"user": user, "password": pw, "token": "", "loginType": 0}),
                 {"Content-Type": "application/json"})
    resp = conn.getresponse()
    resp.read()
    for k, v in resp.getheaders():
        if k.lower() == "set-cookie":
            name, _, rest = v.partition("=")
            cookies[name] = rest.split(";")[0]
    conn.close()
    return {"Cookie": f"{orch.SESSION_COOKIE}={cookies[orch.SESSION_COOKIE]}", "X-XSRF-TOKEN": cookies[orch.CSRF_COOKIE], "_csrf": cookies[orch.CSRF_COOKIE]}


# ------------------------------------------------------------------------------------------------------ auth
def test_api_key_and_rejections(fake):
    assert call(fake, "GET", "/gmsserver/briefInfo", key=None).status == 401
    assert call(fake, "GET", "/gmsserver/briefInfo", key={"X-Auth-Token": "wrong"}).status == 401
    assert call(fake, "GET", "/gmsserver/briefInfo", key={"Authorization": f"Bearer {fake.api_key}"}).status == 401   # not the documented header
    r = call(fake, "GET", "/gmsserver/briefInfo")
    assert r.status == 200 and r.json()["release"] == "9.3.4" and set(r.json()) >= {"uptime", "release", "time", "timeZone", "inContainerMode"}


def test_login_session_flow(fake, clock):
    h = session_headers(fake)
    xsrf = h.pop("_csrf")
    ok = call(fake, "GET", "/appliance", key=h)
    assert ok.status == 200 and len(ok.json()) == 2
    # cookie without the matching X-XSRF-TOKEN header, or with a wrong one: 401
    assert call(fake, "GET", "/appliance", key={"Cookie": h["Cookie"]}).status == 401
    assert call(fake, "GET", "/appliance", key={"Cookie": h["Cookie"], "X-XSRF-TOKEN": xsrf + "x"}).status == 401
    # expiry: the runner must log in again
    clock.t += fake.app.session_ttl_s + 1
    assert call(fake, "GET", "/appliance", key=h).status == 401


def test_logout_and_bad_logins(fake):
    h = session_headers(fake)
    h.pop("_csrf")
    assert call(fake, "GET", "/authentication/logout", key=h).status == 200
    assert call(fake, "GET", "/appliance", key=h).status == 401
    user, pw = fake.user
    for body in ({"user": user, "password": "no", "token": "", "loginType": 0}, {"user": "x", "password": pw, "token": "", "loginType": 0},
                 {"user": user, "password": pw, "token": "", "loginType": 9}, {"user": user, "password": pw, "loginType": 0}, {"user": 1}):
        assert call(fake, "POST", "/authentication/login", body, key=None).status == 401, body
    fake.app.login_fail = True
    assert call(fake, "POST", "/authentication/login", {"user": user, "password": pw, "token": "", "loginType": 0}, key=None).status == 401


def test_credentials_are_runtime_derived(fake):
    key, user, pw = orch.default_credentials()
    src = open(orch.__file__).read()
    assert key not in src and pw not in src and fake.api_key == key


# -------------------------------------------------------------------------------------------------- appliances
def test_appliances(fake):
    lst = call(fake, "GET", "/appliance").json()
    assert {a["nePk"] for a in lst} == {"1.NE", "2.NE"}
    a = call(fake, "GET", "/appliance", nePk="1.NE").json()
    assert a["hostName"] == "ec-core" and a["state"] == 1 and a["id"] == a["nePk"] == "1.NE" and a["IP"] == a["ip"]
    assert call(fake, "GET", "/appliance", nePk="9.NE").status == 404


# ------------------------------------------------------------------------------------------------------- flows
def test_flows_by_client_ip_and_row_indices(fake):
    fake.state.load_scenario("healthy", at=T0, client_ip=IP)
    j = call(fake, "GET", "/flow", nePk="1.NE", ip1=IP, ipEitherFlag="True", portEitherFlag="True", filter="all", edgeHa="False", builtIn="False",
             bytes="total").json()
    assert j["total_flows"] == 3 and j["matched_flows"] == 2 == j["returned_flows"] and j["ret_code"] == 0
    assert set(j) >= {"now", "stale_flows", "active", "inactive", "flows"} and j["active"]["total_flows"] == 3
    row = [r for r in j["flows"] if r[3] == "speedtest_http"][0]
    assert len(row) == 63
    assert (row[9], row[8], row[10], row[16], row[17], row[26]) == (IP, 4, 51000, "203.0.113.50", 443, "tcp")
    assert row[4] == int.from_bytes(bytes(map(int, IP.split("."))), "big")           # [4] IP1_1, 32-bit integer for IPv4
    assert (row[20], row[21], row[22], row[23]) == (1_000, 190_000_000, 0, 60_000_000)
    assert (row[31], row[38], row[39], row[48], row[59], row[60]) == (3, int(T0 - 120), 0, 0, 0, "DefaultOverlay")
    assert call(fake, "GET", "/flow", nePk="1.NE", ip1="10.99.0.1").json()["returned_flows"] == 0


def test_flows_filters_and_old_path_form(fake):
    fake.state.load_scenario("healthy", at=T0, client_ip=IP)
    assert call(fake, "GET", "/flow/1.NE/q", ip1=IP, application="dns").json()["returned_flows"] == 1
    j = call(fake, "GET", "/flow", nePk="1.NE", ip1=IP, port2="53").json()
    assert [r[3] for r in j["flows"]] == ["dns"]
    assert call(fake, "GET", "/flow", nePk="1.NE", ip1="10.60.14.0", mask1="24").json()["returned_flows"] == 2
    assert call(fake, "GET", "/flow", nePk="1.NE", ip1=IP, ip2="10.0.0.53").json()["returned_flows"] == 1
    # directionality per the docstring: True = ip1 is the source; False = either direction
    assert call(fake, "GET", "/flow", nePk="1.NE", ip1="203.0.113.50", ipEitherFlag="True").json()["returned_flows"] == 0
    assert call(fake, "GET", "/flow", nePk="1.NE", ip1="203.0.113.50", ipEitherFlag="False").json()["returned_flows"] == 2
    assert call(fake, "GET", "/flow", nePk="1.NE", ip1="not-an-ip").status == 400
    assert call(fake, "GET", "/flow", nePk="7.NE").status == 404


def test_flows_time_windows_epoch_ms(fake):
    fake.state.load_scenario("healthy", at=T0, client_ip=IP)       # flows start at T0-120, still active
    ms = lambda t: int(t * 1000)  # noqa: E731
    hit = call(fake, "GET", "/flow", nePk="1.NE", ip1=IP, anyStartTime=ms(T0 - 60), anyEndTime=ms(T0)).json()
    assert hit["returned_flows"] == 2
    miss = call(fake, "GET", "/flow", nePk="1.NE", ip1=IP, anyStartTime=ms(T0 - 900), anyEndTime=ms(T0 - 600)).json()
    assert miss["returned_flows"] == 0
    fake.state.flows["1.NE"][0]["end_s"] = int(T0 - 30)            # now terminated
    term = call(fake, "GET", "/flow", nePk="1.NE", ip1=IP, termStartTime=ms(T0 - 60), termEndTime=ms(T0)).json()
    assert term["returned_flows"] == 1 and term["inactive"]["total_flows"] == 1
    assert call(fake, "GET", "/flow", nePk="1.NE", anyStartTime="x", anyEndTime="1").status == 400


def test_firewall_drop_scenario(fake):
    fake.state.load_scenario("firewall_drop", at=T0, client_ip=IP)
    j = call(fake, "GET", "/flow", nePk="1.NE", ip1=IP, filter="firewallDropped").json()
    assert j["returned_flows"] == 1 and j["flows"][0][48] == 1 and j["flows"][0][59] == 1 and j["flows"][0][3] == "ssh"
    assert j["active"]["flows_firewall_dropped"] == 1 and j["flows_with_issues"] == 1
    assert call(fake, "GET", "/flow", nePk="1.NE", ip1=IP, filter="routeDropped").json()["returned_flows"] == 0


def test_qos_shaped_scenario(fake):
    fake.state.load_scenario("qos_shaped", at=T0, client_ip=IP)
    row = [r for r in call(fake, "GET", "/flow", nePk="1.NE", ip1=IP, application="speedtest_http").json()["flows"]][0]
    assert row[31] == 7 and row[58] == "Bulk_Data_transfer" and row[43] == 40
    ts = call(fake, "GET", "/stats/timeseries/trafficClass", nePk="1.NE", startTime=int(T0 - 180), endTime=int(T0), granularity="minute",
              trafficType="all_traffic", trafficClass=7).json()
    cols = ts["COLUMN_DEF"]
    assert all(r[cols.index("drop_pkts")] == 4200 for r in ts["DATA"]["1.NE"])
    calm = call(fake, "GET", "/stats/timeseries/trafficClass", nePk="1.NE", startTime=int(T0 - 60), endTime=int(T0), granularity="minute",
                trafficType="all_traffic", trafficClass=3).json()
    assert all(r[cols.index("drop_pkts")] == 0 for r in calm["DATA"]["1.NE"])
    assert call(fake, "GET", "/stats/timeseries/trafficClass", nePk="1.NE", startTime=1, endTime=2, granularity="minute", trafficClass=99).status == 400


# ----------------------------------------------------------------------------------------- interface + series
def test_interface_state_both_forms(fake):
    a = call(fake, "GET", "/interfaceState", nePk="1.NE", cached="True").json()
    b = call(fake, "GET", "/interfaceState/1.NE", cached="False").json()
    assert a == b and a["scalars"]["maxWanBandwidth"] == 200_000 and a["sysConfig"]["mode"] == "router"
    wan = [i for i in a["ifInfo"] if i["ifname"] == "wan0"][0]
    assert wan["wan-if"] is True and wan["lan-if"] is False and wan["oper"] is True and wan["ifSpeed"] == "1000" and wan["label"] == "2"
    assert wan["duplex"] == "full (auto)" and wan["publicIp"]
    assert call(fake, "GET", "/interfaceState", nePk="8.NE").status == 404


def util_from_series(j: dict, ne: str, max_kbps: int, step: int = 60) -> float:
    cols = j["COLUMN_DEF"]
    rows = [r for r in j["DATA"][ne] if r[cols.index("interface")] == "wan0"]
    last = rows[-1]
    bps = max(last[cols.index("rx_bytes")], last[cols.index("tx_bytes")]) * 8 / step
    return bps / (max_kbps * 1000) * 100


def test_saturated_wan_timeseries_utilisation(fake):
    fake.state.load_scenario("saturated_wan", at=T0)
    j = call(fake, "GET", "/stats/timeseries/interface", nePk="1.NE", startTime=int(T0 - 240), endTime=int(T0), granularity="minute",
             trafficType="all_traffic", interfaceName="wan0").json()
    assert j["COLUMN_DEF"] == orch.INTERFACE_COLUMNS and len(j["DATA"]["1.NE"]) == 5
    assert round(util_from_series(j, "1.NE", 200_000), 1) == 92.5
    assert round(fake.state.wan_util_pct("1.NE"), 1) == 92.5
    # old path form, and LAN rows only when no interface filter
    assert call(fake, "GET", "/stats/timeseries/interface/1.NE", startTime=int(T0 - 60), endTime=int(T0), granularity="minute").json()["DATA"]["1.NE"]


def test_wan_load_changes_over_time_for_autopause(fake, clock):
    fake.state.load_scenario("healthy", at=T0)
    q = dict(nePk="1.NE", granularity="minute", interfaceName="wan0")
    low = call(fake, "GET", "/stats/timeseries/interface", startTime=int(T0 - 120), endTime=int(T0), **q).json()
    assert util_from_series(low, "1.NE", 200_000) < 10
    r = request(fake.port, "POST", "/_fake/wan_load", {"ne_pk": "1.NE", "ifname": "wan0", "rx_bps": 170_000_000, "tx_bps": 1, "t_from": T0 + 5})
    assert r.status == 200 and r.json()["util_pct"] < 10      # not yet (clock still at T0)
    clock.t = T0 + 120
    assert fake.state.wan_util_pct("1.NE") == 85.0
    hi = call(fake, "GET", "/stats/timeseries/interface", startTime=int(clock.t - 60), endTime=int(clock.t), **q).json()
    assert util_from_series(hi, "1.NE", 200_000) == 85.0


def test_column_def_is_what_the_server_says(fake):
    fake.app.interface_columns = ["tx_bytes", "interface", "time", "rx_bytes"]
    j = call(fake, "GET", "/stats/timeseries/interface", nePk="1.NE", startTime=int(T0 - 60), endTime=int(T0), granularity="minute",
             interfaceName="wan0").json()
    assert j["COLUMN_DEF"] == ["tx_bytes", "interface", "time", "rx_bytes"]
    assert j["DATA"]["1.NE"][0][1] == "wan0"
    for bad in ({"startTime": "x", "endTime": "1", "granularity": "minute"}, {"startTime": "1", "endTime": "2", "granularity": "second"},
                {"startTime": "5", "endTime": "2", "granularity": "minute"}):
        assert call(fake, "GET", "/stats/timeseries/interface", nePk="1.NE", **bad).status == 400


# ------------------------------------------------------------------------------------------ health + alarms
def test_health_loss_and_latency(fake):
    fake.state.load_scenario("loss", at=T0)
    loss = call(fake, "GET", "/health/lossPeriodSummary", applianceId="1.NE", time=int(T0 // 3600 * 3600), overlayId=-1).json()
    assert loss["maxLossPercentage"] == 3.5 and loss["healthStatus"] == "CRITICAL" and loss["tunnelId"] == "to_dc" and loss["criticalMins"] == 11
    assert loss["normalMins"] == 49 and set(loss) == {"tunnelId", "healthStatus", "criticalMins", "majorMins", "normalMins", "maxLossPercentage"}
    lat = call(fake, "GET", "/health/latencyPeriodSummary", applianceId="1.NE", time=int(T0), overlayId=-1).json()
    assert lat["max"] == 22 and "maxLossPercentage" not in lat
    for kind, key in (("jitter", 9), ("mos", 3.2)):
        assert call(fake, "GET", f"/health/{kind}PeriodSummary", applianceId="1.NE", time=int(T0)).json()["max"] == key
    fake.app.health_shape = "list"
    assert isinstance(call(fake, "GET", "/health/lossPeriodSummary", applianceId="1.NE", time=int(T0)).json(), list)
    assert call(fake, "GET", "/health/lossPeriodSummary", applianceId="1.NE", time="soon").status == 400


def test_saturated_wan_health_and_alarm(fake):
    fake.state.load_scenario("saturated_wan", at=T0)
    lat = call(fake, "GET", "/health/latencyPeriodSummary", applianceId="1.NE", time=int(T0)).json()
    assert lat["healthStatus"] == "CRITICAL" and lat["majorMins"] == 14 and lat["max"] == 38
    al = call(fake, "POST", "/alarm/appliance", {"nePks": ["1.NE"]}, view="active", severity="major", orderBySeverity="True", maxAlarms=5,
              **{"from": int((T0 - 3600) * 1000), "to": int(T0 * 1000)}).json()
    assert len(al) == 1
    a = al[0]
    assert a["applianceId"] == "1.NE" and a["severity"] == "major" and a["name"] == "Tunnel state" and a["closed"] is False and a["hostName"] == "ec-core"
    assert set(a) >= {"sequenceId", "source", "acknowledged", "clearable", "timeOccurredInMills", "description", "type", "recommendedAction",
                      "serviceAffect", "typeId", "occurrenceCount"}


def test_alarms_body_forms_and_filters(fake):
    fake.state.add_alarm("1.NE", severity="minor", name="x", description="d", type_="t", t=T0 - 10)
    fake.state.add_alarm("1.NE", severity="critical", name="y", description="d", type_="t", t=T0 - 5, closed=True)
    legacy = call(fake, "POST", "/alarm/appliance", {"ids": ["1.NE"]}, view="all").json()      # pre-9.3 body key
    assert len(legacy) == 2
    assert [a["closed"] for a in call(fake, "POST", "/alarm/appliance", {"nePks": ["1.NE"]}, view="closed").json()] == [True]
    assert "clearedTimeInMills" in call(fake, "POST", "/alarm/appliance", {"nePks": ["1.NE"]}, view="closed").json()[0]
    assert call(fake, "POST", "/alarm/appliance", {"nePks": ["1.NE"]}, view="bogus").status == 400
    assert call(fake, "POST", "/alarm/appliance", {"nope": 1}).status == 400
    assert call(fake, "POST", "/alarm/appliance", {"nePks": ["9.NE"]}).status == 404
    ordered = call(fake, "POST", "/alarm/appliance", {"nePks": ["1.NE"]}, orderBySeverity="True").json()
    assert [a["severity"] for a in ordered] == ["critical", "minor"]


# --------------------------------------------------------------------------------------- control + plumbing
def test_scenarios_deterministic_and_control_api(fake):
    for name in orch.SCENARIOS:
        assert fake.state.load_scenario(name, at=T0) == fake.state.load_scenario(name, at=T0)
    assert request(fake.port, "POST", "/_fake/scenario", {"name": "loss", "at": T0}).status == 200
    assert request(fake.port, "POST", "/_fake/scenario", {"name": "nope"}).status == 400
    assert request(fake.port, "POST", "/_fake/force", {"status": 503, "count": 1}).status == 200
    assert call(fake, "GET", "/appliance").status == 503
    assert call(fake, "GET", "/appliance").status == 200
    log = request(fake.port, "GET", "/_fake/log").json()["calls"]
    assert any(c["status"] == 503 for c in log) and fake.app.calls_to("/appliance") == 2
    assert {c["auth"] for c in log} == {"api_key"}
    assert call(fake, "GET", "/nope").status == 404
    assert request(fake.port, "GET", "/elsewhere", headers={}).status == 404


def test_https_with_throwaway_ca(tmp_path):
    ca, leaf = fake_ca.make_server_tls(tmp_path)
    f = orch.start(tls=(leaf.cert_chain, leaf.key))
    try:
        c = http.client.HTTPSConnection("localhost", f.port, timeout=10, context=fake_ca.client_context(ca))
        c.request("GET", orch.PREFIX + "/gmsserver/briefInfo", headers={"X-Auth-Token": f.api_key})
        assert c.getresponse().status == 200
        c.close()
    finally:
        f.stop()
