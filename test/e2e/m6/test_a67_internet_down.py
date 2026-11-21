"""A6.7: the internet is gone (lanctl cut-internet: the whole simulated internet drops everything). The page and the
on-network and DNS legs still work, the internet leg reports "unavailable", the diagnosis says so, and the result reaches the
dashboard on the LAN (12-speedtest-analytics.md section 11)."""
from __future__ import annotations

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e


def test_a67_internet_down_page_and_local_legs_work(core: M.Core, phone: M.Client):
    core.lanctl("cut-internet")
    try:
        # the box and the page are on the LAN: reachable
        assert phone.http("GET", f"{core.page}/")["status"] == 200
        r, tid = core.run_page(phone, name="a67", timeout=240, timeoutMs=150000, waitChecksMs=60000,
                               shotPre="a67-01-start-390", shotResults="a67-02-results-390", shotFinal="a67-03-final-390")
        print(f"A6.7 results after {r['doneAt']} ms with the internet down")
        first = r["first"]
        assert first["score"] not in (None, "", "—") or first["verdict"], first
        assert r["errors"] == [] and r["dialogs"] == []
        t = core.test_detail(tid)["test"]
        legs = t["legs"]
        assert legs["internet"]["status"] == "unavailable", legs["internet"]
        assert not any(k in legs["internet"] for k in ("down_mbps", "up_mbps")), "a non-ok leg carries no throughput numbers"
        assert legs["local"]["status"] == "ok" and legs["local"]["down_mbps"] > 0, legs["local"]
        assert legs["dns"]["source"] == "browser" and legs["dns"]["resolver_ip"] == M.GW_CORE, legs["dns"]
        # the diagnosis says so, in plain words (user text) and for the NOC
        d = core.wait_final(tid)["diagnosis"]
        text = (d["user_text"] + " " + d["noc_text"]).lower()
        assert "internet" in text, d
        shown = (first["why"] or "") + " " + (first["verdict"] or "") + " " + (first["notice"] or "") + " " + " ".join(first["checks"])
        print("A6.7 page text:", shown[:300])
        # the page must not promise what needs the internet (calls, streaming) while the internet is down
        assert "video calls and streaming" not in shown.lower() and "internet is back" in (first["verdict"] or ""), first["verdict"]
        # results reach the dashboard on the LAN (its federated query API, local-user session)
        dash = core.dash()
        rows = M.wait_for(lambda: [x for x in dash.get("speedtests", limit=50).get("items", []) if x["id"] == tid], 30, 2, "the test on the dashboard")
        assert rows[0]["id"] == tid
        assert dash.get(f"speedtests/{tid}")["test"]["legs"]["internet"]["status"] == "unavailable"
        assert dash.page("/speedtests").status == 200
    finally:
        core.lanctl("restore")
    # the internet is back: the next test has an internet leg again
    r2, tid2 = core.run_page(phone, name="a67-back", timeoutMs=90000)
    assert core.test_detail(tid2)["test"]["legs"]["internet"]["status"] == "ok"
