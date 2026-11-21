"""mist fake: auth, filters, windows, pagination, rate limit, scenarios, and conformance to the Mist OAS 3.1 (when present)."""
from __future__ import annotations

import json
import os
import urllib.parse
from pathlib import Path

import pytest
from fakes_support import request

import fake_ca
from mist import server as mist

T0 = 1_795_000_000.0
SITE, ORG = mist.SITE_ID, mist.ORG_ID
# The Mist OpenAPI document ships in the mistapi 0.64.1 sdist (mist_openapi/mist.openapi.json); it is a dev-time
# reference, not vendored. Point EXP_MIST_OAS at a local copy to run the conformance check; without it the check skips.
_OAS_ENV = os.environ.get("EXP_MIST_OAS", "")
OAS_PATH = Path(_OAS_ENV) if _OAS_ENV else None


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
    f = mist.start(now_fn=clock)
    yield f
    f.stop()


def get(fake, path, token=None, scheme="Token", **q):
    hdr = {} if token is False else {"Authorization": f"{scheme} {token or fake.token}"}
    qs = urllib.parse.urlencode(q)
    return request(fake.port, "GET", path + ("?" + qs if qs else ""), headers=hdr)


def site(p):
    return f"/api/v1/sites/{SITE}/{p}"


# ------------------------------------------------------------------------------------- OAS conformance helper
def _validator(schema_name: str):
    if OAS_PATH is None or not OAS_PATH.is_file():
        pytest.skip("Mist OAS reference not present (set EXP_MIST_OAS)")
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
    doc = json.loads(OAS_PATH.read_text("utf-8"))
    reg = Registry().with_resource("mist.json", Resource.from_contents(doc, default_specification=DRAFT202012))
    return Draft202012Validator({"$ref": f"mist.json#/components/schemas/{schema_name}"}, registry=reg)


def conform(schema_name: str, body) -> None:
    errs = sorted(_validator(schema_name).iter_errors(body), key=lambda e: list(e.path))
    assert not errs, f"{schema_name}: " + "; ".join(f"{list(e.path)}: {e.message[:160]}" for e in errs[:5])


# ---------------------------------------------------------------------------------------------------- auth
def test_auth_is_token_scheme(fake):
    p = site("clients/search")
    for kw in ({"token": False}, {"scheme": "Bearer"}, {"token": "nope"}):
        r = get(fake, p, **kw)
        assert r.status == 401 and r.json() == {"detail": "Authentication credentials were not provided."}
    conform("response_http401", r.json())
    assert get(fake, p).status == 200


def test_unknown_site_and_org(fake):
    r = get(fake, "/api/v1/sites/00000000-0000-0000-0000-0000000000ff/clients/search")
    assert r.status == 404 and r.json() == {"id": "00000000-0000-0000-0000-0000000000ff"}
    conform("response_http404", r.json())
    assert get(fake, "/api/v1/orgs/00000000-0000-0000-0000-0000000000ff/clients/search").status == 404


# ------------------------------------------------------------------------------------------ client search
def test_wireless_search_by_ip_in_window(fake):
    info = fake.state.load_scenario("weak_rssi", at=T0)
    r = get(fake, site("clients/search"), ip="10.60.14.77", start=int(T0 - 300), end=int(T0 + 60))
    assert r.status == 200
    j = r.json()
    conform("response_client_search", j)
    assert j["total"] == 1 and j["results"][0]["mac"] == info["mac"] == "f018" "98aabb01"
    assert j["results"][0]["last_ip"] == "10.60.14.77" and "10.60.14.77" in j["results"][0]["ip"]
    assert j["start"] == int(T0 - 300) and j["end"] == int(T0 + 60)
    # org-level search takes the same filters plus site_id
    ro = get(fake, f"/api/v1/orgs/{ORG}/clients/search", ip="10.60.14.*", site_id=SITE, duration="10m")
    assert ro.status == 200 and ro.json()["total"] == 1
    conform("response_client_search", ro.json())
    assert get(fake, f"/api/v1/orgs/{ORG}/clients/search", ip="10.60.14.77", site_id="00000000-0000-0000-0000-0000000000ff").json()["total"] == 0


def test_search_wildcards_and_bad_patterns(fake):
    fake.state.load_scenario("healthy", at=T0)
    p = site("clients/search")
    for pat in ("10.60.14.*", "*60.14*", "10.60.14.77", "10.60.14.77,1.2.3.4"):
        assert get(fake, p, ip=pat, duration="1h").json()["total"] == 1, pat
    assert get(fake, p, ip="10.99.*", duration="1h").json()["total"] == 0
    assert get(fake, p, ip="*.77").status == 400                      # suffix-only wildcard: rejected, as the OAS says
    assert get(fake, p, mac="f0:18:98:aa:bb:01", duration="1h").json()["total"] == 1   # colon form accepted in filters
    assert get(fake, p, mac="f01898*", duration="1h").json()["total"] == 1
    assert get(fake, p, hostname="client*", duration="1h").json()["total"] == 1
    assert get(fake, p, ssid="Other", duration="1h").json()["total"] == 0


def test_window_semantics(fake):
    fake.state.load_scenario("healthy", at=T0)       # session starts at T0-600
    p = site("clients/search")
    assert get(fake, p, ip="10.60.14.77", start=int(T0 - 3000), end=int(T0 - 1200)).json()["total"] == 0   # before it began
    assert get(fake, p, ip="10.60.14.77", start="-5m").json()["total"] == 1
    assert get(fake, p, ip="10.60.14.77", start="-5m", end="now").json()["total"] == 1
    assert get(fake, p, ip="10.60.14.77", duration="10s").json()["total"] == 1   # still connected (open session)
    assert get(fake, p, start="bogus").status == 400
    assert get(fake, p, duration="3 days").status == 400
    assert get(fake, p, start=int(T0), end=int(T0 - 5)).status == 400


def test_nat_ambiguity_two_macs_one_ip(fake):
    info = fake.state.load_scenario("nat_ambiguity", at=T0)
    j = get(fake, site("clients/search"), ip="10.60.14.77", start=int(T0 - 400), end=int(T0 + 60)).json()
    assert j["total"] == 2 and {r["mac"] for r in j["results"]} == {info["mac"], info["other_mac"]}


def test_no_client(fake):
    fake.state.load_scenario("no_client", at=T0)
    j = get(fake, site("clients/search"), ip="10.60.14.77").json()
    assert j["total"] == 0 and j["results"] == []
    assert get(fake, site("stats/clients/f01898aabb01")).status == 404


def test_pagination_next_and_search_after(fake):
    for i in range(5):
        fake.state.add_wireless_session(mac=f"f0:18:98:00:00:{i:02x}", ip=f"10.60.14.{i + 1}", t_from=T0 - 100 - i)
    p = site("clients/search")
    seen, path, pages = [], p + "?limit=2&duration=10m", 0
    while path:
        r = request(fake.port, "GET", path, headers={"Authorization": f"Token {fake.token}"})
        j = r.json()
        conform("response_client_search", j)
        assert j["total"] == 5 and j["limit"] == 2
        seen += [x["mac"] for x in j["results"]]
        path = j.get("next")
        pages += 1
    assert pages == 3 and len(set(seen)) == 5
    assert get(fake, p, search_after="garbage").status == 400
    assert get(fake, p, limit="x").status == 400
    z = get(fake, p, limit=0, duration="10m").json()
    assert z["results"] == [] and z["total"] == 5 and "next" not in z
    assert get(fake, p, limit=100000, duration="10m").json()["limit"] == mist.MAX_LIMIT   # clamped


# --------------------------------------------------------------------------------------------- client stats
def test_client_stats_weak_rssi(fake):
    info = fake.state.load_scenario("weak_rssi", at=T0)
    for mac in (info["mac"], "f0:18:98:aa:bb:01", "F0-18-98-AA-BB-01"):
        r = get(fake, site(f"stats/clients/{mac}"))
        assert r.status == 200, mac
    j = r.json()
    conform("stats_wireless_client", j)
    assert j["rssi"] == -83 and j["snr"] == 9 and j["band"] == "5" and j["ap_mac"] == mist.AP1["mac"] and j["ip"] == "10.60.14.77"
    lst = get(fake, site("stats/clients")).json()
    conform("stats_client_any_of", lst)
    assert len(lst) == 1 and lst[0]["mac"] == info["mac"]
    assert get(fake, site("stats/clients/zz")).status == 404
    assert get(fake, site("stats/clients/f01898aabb99")).status == 404
    assert get(fake, site(f"stats/clients/{info['mac']}"), wired="true").status == 404


def test_stats_follow_the_clock_and_roaming(fake, clock):
    fake.state.load_scenario("roaming", at=T0)
    assert get(fake, site("stats/clients/f01898aabb01")).json()["ap_mac"] == mist.AP2["mac"]          # now: on AP2
    clock.t = T0 - 300                                                                                 # earlier: AP1
    assert get(fake, site("stats/clients/f01898aabb01")).json()["ap_mac"] == mist.AP1["mac"]
    clock.t = T0 - 3000
    assert get(fake, site("stats/clients/f01898aabb01")).status == 404
    clock.t = T0
    j = get(fake, site("clients/search"), ip="10.60.14.77", duration="15m").json()["results"][0]
    assert set(j["ap"]) == {mist.AP1["mac"], mist.AP2["mac"]}


# ------------------------------------------------------------------------------------------------ AP stats
def test_ap_stats_congested(fake):
    fake.state.load_scenario("congested_ap", at=T0)
    r = get(fake, site(f"stats/devices/{mist.AP1['id']}"))
    assert r.status == 200
    j = r.json()
    conform("stats_ap", j)
    r5 = j["radio_stat"]["band_5"]
    assert r5["util_all"] == 93 and r5["num_clients"] == 64 and r5["channel"] == 36 and r5["noise_floor"] == -86
    assert j["type"] == "ap" and j["name"] == "hallb-ap-12"
    lst = get(fake, site("stats/devices")).json()
    assert {a["mac"] for a in lst} == {mist.AP1["mac"], mist.AP2["mac"]}
    assert get(fake, site("stats/devices/00000000-0000-0000-0000-0000000000ee")).status == 404


# ------------------------------------------------------------------------------------------ wired + ports
def test_wired_client_and_port_errors(fake):
    fake.state.load_scenario("wired_port_errors", at=T0)
    r = get(fake, site("wired_clients/search"), ip="10.60.14.77", duration="15m")
    j = r.json()
    conform("search_wired_client", j)
    c = j["results"][0]
    assert c["mac"] == "f01898aabb01" and c["port_id"] == ["ge-0/0/12"] and c["device_mac"] == [mist.SWITCH["mac"]] and c["vlan"] == [160]
    assert get(fake, site("wired_clients/search"), ip="10.9.9.9", duration="15m").json()["total"] == 0
    assert get(fake, f"/api/v1/orgs/{ORG}/wired_clients/search", ip="10.60.14.77", duration="15m").json()["total"] == 1
    pj = get(fake, site("stats/ports/search"), mac=mist.SWITCH["mac"], port_id="ge-0/0/12").json()
    conform("response_switch_port_search", pj)
    p = pj["results"][0]
    assert p["rx_errors"] == 41822 and p["speed"] == 100 and p["full_duplex"] is False and "start" not in pj
    assert get(fake, site("stats/ports/search")).json()["total"] == 2
    assert get(fake, site("stats/ports/search"), full_duplex="false").json()["total"] == 1


# ------------------------------------------------------------------------------------------------ events
def test_client_events_roaming(fake):
    fake.state.load_scenario("roaming", at=T0)
    j = get(fake, site("clients/events/search"), duration="15m").json()
    conform("response_events_search", j)
    types = [e["type"] for e in j["results"]]
    assert types.count(mist.EVT_ROAM) == 4 and mist.EVT_FBT_FAIL in types and mist.EVT_AUTH_FAIL in types
    assert all("mac" not in e and "client_mac" not in e for e in j["results"])      # the OAS has no client MAC on events_client
    assert get(fake, site("clients/events/search"), type=mist.EVT_ROAM, duration="15m").json()["total"] == 4
    assert get(fake, site("clients/events/search"), ap=mist.AP2["mac"], duration="15m").json()["total"] == 2
    assert get(fake, site("clients/events/search"), start=int(T0 - 100), end=int(T0)).json()["total"] == 0
    assert get(fake, site("clients/events/search"), reason_code="15", duration="15m").json()["total"] == 1
    d = get(fake, "/api/v1/const/client_events").json()
    conform("const_events", d)
    assert {x["key"] for x in d} >= {mist.EVT_ROAM, mist.EVT_FBT_FAIL}


def cev(mac, **q):
    return f"/api/v1/sites/{SITE}/clients/{mac}/events", q


def test_get_site_events_for_client_only_this_clients_events(fake):
    """getSiteEventsForClient: MAC in the path, response_client_events_search / events_client, nothing from other clients."""
    info = fake.state.load_scenario("roaming_other_client", at=T0)
    own, other = info["mac"], info["other_mac"]
    j = get(fake, cev(own)[0], duration="15m").json()
    conform("response_client_events_search", j)
    assert j["total"] == 0 and j["results"] == []                       # the attendee has none; the other client's never leak
    j = get(fake, cev(other)[0], duration="15m").json()
    conform("response_client_events_search", j)
    assert j["total"] == 5 and all("mac" not in e and "client_mac" not in e for e in j["results"])
    assert [e["timestamp"] for e in j["results"]] == sorted((e["timestamp"] for e in j["results"]), reverse=True)
    colon = ":".join(other[i:i + 2] for i in range(0, 12, 2))
    assert get(fake, cev(colon)[0], duration="15m").json()["total"] == 5
    assert get(fake, cev(other)[0], duration="15m", type=mist.EVT_ROAM).json()["total"] == 3
    assert get(fake, cev(other)[0], duration="15m", ssid="nope").json()["total"] == 0
    assert get(fake, cev(other)[0], start=int(T0 - 100), end=int(T0)).json()["total"] == 0


def test_get_site_events_for_client_roaming_scenario_belongs_to_the_roaming_client(fake):
    info = fake.state.load_scenario("roaming", at=T0)
    j = get(fake, cev(info["mac"])[0], duration="15m").json()
    conform("response_client_events_search", j)
    assert j["total"] == 6
    assert get(fake, cev("f0:18:98:cc:dd:02")[0], duration="15m").status == 404      # unknown client -> 404 {"id": mac}
    assert get(fake, cev("zz")[0], duration="15m").status == 404


def test_get_site_events_for_client_pagination_auth_and_errors(fake):
    info = fake.state.load_scenario("roaming", at=T0)
    path = cev(info["mac"])[0]
    p1 = get(fake, path, duration="15m", limit=4).json()
    conform("response_client_events_search", p1)
    assert len(p1["results"]) == 4 and p1["total"] == 6 and "page=2" in p1["next"]
    p2 = get(fake, path, duration="15m", limit=4, page=2).json()
    assert len(p2["results"]) == 2 and "next" not in p2
    assert {e["timestamp"] for e in p1["results"]}.isdisjoint({e["timestamp"] for e in p2["results"]})
    assert get(fake, path, duration="15m", page=0).status == 400
    assert get(fake, path, token=False).status == 401
    assert get(fake, path, scheme="Bearer").status == 401
    assert request(fake.port, "GET", f"/api/v1/sites/{'0' * 8}-0000-0000-0000-{'0' * 12}/clients/{info['mac']}/events",
                   headers={"Authorization": f"Token {fake.token}"}).status == 404


# ------------------------------------------------------------------------------------- limits and faults
def test_rate_limit_rolling_hour(fake, clock):
    fake.app.set_rate_limit(3)
    p = site("clients/search")
    assert [get(fake, p).status for _ in range(3)] == [200, 200, 200]
    r = get(fake, p)
    assert r.status == 429 and r.json() == {"detail": mist.RATE_LIMIT_DETAIL}
    conform("response_http429", r.json())
    assert "retry-after" not in {k.lower() for k in r.headers}
    clock.t += 3601
    assert get(fake, p).status == 200
    # unauthenticated calls are not charged
    assert get(fake, p, token="bad").status == 401


def test_force_status_and_call_log(fake):
    fake.app.set_force(503, count=2)
    p = site("clients/search")
    assert [get(fake, p).status for _ in range(3)] == [503, 503, 200]
    assert fake.app.calls_to("clients/search") == 3
    r = request(fake.port, "GET", "/_fake/log")
    assert r.status == 200 and len(r.json()["calls"]) == 3


def test_non_get_is_405(fake):
    r = request(fake.port, "POST", site("clients/search"), body={}, headers={"Authorization": f"Token {fake.token}"})
    assert r.status == 405


def test_control_api_over_http(fake, clock):
    r = request(fake.port, "POST", "/_fake/scenario", {"name": "weak_rssi", "at": T0, "ip": "10.60.20.5", "mac": "aa:bb:cc:00:00:01"})
    assert r.status == 200 and r.json()["mac"] == "aabbcc000001"
    assert get(fake, site("clients/search"), ip="10.60.20.5").json()["total"] == 1
    assert request(fake.port, "POST", "/_fake/scenario", {"name": "nope"}).status == 400
    assert request(fake.port, "POST", "/_fake/rate_limit", {"per_hour": 1}).status == 200
    assert request(fake.port, "POST", "/_fake/reset", {}).status == 200
    assert get(fake, site("clients/search")).json()["total"] == 0


def test_every_scenario_loads_and_is_deterministic(fake):
    for name in mist.SCENARIOS:
        a = fake.state.load_scenario(name, at=T0)
        b = fake.state.load_scenario(name, at=T0)
        assert a == b


def test_https_with_throwaway_ca(tmp_path):
    ca, leaf = fake_ca.make_server_tls(tmp_path)
    f = mist.start(tls=(leaf.cert_chain, leaf.key))
    try:
        import http.client
        c = http.client.HTTPSConnection("localhost", f.port, timeout=10, context=fake_ca.client_context(ca))
        c.request("GET", site("clients/search"), headers={"Authorization": f"Token {f.token}"})
        assert c.getresponse().status == 200
        c.close()
    finally:
        f.stop()


def test_token_is_runtime_derived_not_a_literal():
    assert len(mist.default_token()) == 40 and mist.default_token() == mist.default_token()
    assert mist.default_token() not in (Path(mist.__file__).read_text())
