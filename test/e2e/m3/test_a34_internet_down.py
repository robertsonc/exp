"""A3.4 (SPEC.md section 9, M3): the internet uplink is down for the WHOLE site and the LAN dashboard keeps working.

`lanctl cut-internet` takes the simulated internet (the isp namespace) away on every path: the event LANs (via the edge)
and the management network. There is no manager in this layout and the dashboard's `sso.manager_url` is unresolvable,
so the dashboard has nothing but its LAN. During the window:

* a local user logs in (POST /auth/login) and a NOC token exchange works (the /noc#t=... page, in Chromium);
* live updates (SSE) keep arriving, the board renders (every probe's internet line red, with a where);
* probes keep measuring and collectors keep storing (records keep arriving in SQLite);
* by packet capture on the dashboard host (pktwatch.py, AF_PACKET) no packet leaves the management/LAN subnet toward
  any public address (04-dashboard.md 7.7, SPEC principle 2: the data plane never depends on the cloud).
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

import m3lib as M

pytestmark = pytest.mark.e2e

PROBES = [n["probe"] for n in M.NODES]
SUBNET = os.environ["EXP_HARNESS_SUBNET"]
WATCH_OUT = "/tmp/pktwatch.json"
NOC_JS = M.HERE / "noc_board.js"
PUBLIC_PING = "1.1.1.1"


@pytest.fixture(autouse=True)
def calm(stack: M.Multi) -> None:
    """Probes running and green, no fault in place."""
    for n in stack.nodes:
        if n.host.run("systemctl is-active exp-probe.service").stdout.strip() != "active":
            n.host.ok("systemctl start " + " ".join(n.probe_units()), timeout=120)
    stack.lanctl("restore")
    for lan in (1, 2):
        stack.canary(lan)

    def settled() -> bool:
        doc = stack.dash().get("states", voice="sysadmin")
        return M.all_green(doc["items"], PROBES) and all(c["ok"] for c in doc["collectors"])

    M.wait_for(settled, 300, step=3.0, what="every probe green before the outage")


def can_reach_public(m: M.Multi, d: M.L.Host | None = None) -> bool:
    """From the dashboard host by default; during the capture window ask ANOTHER host (the controls must not be traffic
    of the dashboard host, which is what the capture judges)."""
    d = d or m.dash_host
    ping = d.run(f"ping -c1 -W2 {PUBLIC_PING}", timeout=20).returncode == 0
    curl = d.run("curl -sS --max-time 4 -o /dev/null http://142.250.80.46/", timeout=20).returncode == 0
    assert ping == curl, f"ping and https disagree about the internet (ping={ping}, https={curl})"
    return ping


def record_counts(m: M.Multi) -> dict[str, int]:
    return {n.probe: int(n.host.sqlite("/var/lib/exp/collector/records.db",
                                       f"SELECT count(*) FROM records WHERE probe='{n.probe}'")[0]) for n in m.nodes}


def start_watch(m: M.Multi) -> None:
    d = m.dash_host
    d.put(M.HARNESS / "pktwatch.py", "/root/pktwatch.py")
    d.ok(f"rm -f {WATCH_OUT} /root/pktwatch.log; "
         f"nohup python3 /root/pktwatch.py {WATCH_OUT} {SUBNET} > /root/pktwatch.log 2>&1 &")
    M.wait_for(lambda: "ready" in d.run("cat /root/pktwatch.log").stdout, 20, step=0.5, what="the packet capture is running")


def stop_watch(m: M.Multi) -> dict[str, Any]:
    d = m.dash_host
    d.run("pkill -TERM -f '[p]ktwatch.py'")
    out = M.wait_for(lambda: d.run(f"cat {WATCH_OUT}").stdout or None, 20, step=0.5, what="the capture result")
    return json.loads(out)


def internet_red(m: M.Multi) -> list[dict[str, Any]] | None:
    doc = m.dash().get("states", voice="sysadmin")
    if {i["probe"] for i in doc["items"]} != set(PROBES):
        return None
    red = [i for i in doc["items"] if M.line_states({"lines": i["lines"]}).get("internet") not in (None, "ok")]
    return doc["items"] if len(red) == len(PROBES) else None


def test_a3_4_internet_down_the_lan_dashboard_keeps_working(stack: M.Multi, artifacts: Path) -> None:
    d = stack.dash_host
    # -- there is no manager: the SSO issuer's host does not exist for the dashboard (so nothing could reach it, up or down)
    cfg = json.loads(d.ok("cat /etc/exp/dashboard/config.json"))
    mgr = cfg["auth"]["sso"]["manager_url"]
    mgr_host = mgr.split("//", 1)[1].split("/", 1)[0].split(":")[0]
    assert d.run(f"getent hosts {mgr_host}").returncode != 0, f"{mgr_host} resolves from the dashboard host"
    assert d.run(f"curl -sS --max-time 4 -o /dev/null {mgr}/").returncode != 0, "the manager is reachable"

    # -- a NOC token (the unit loads credentials through LoadCredential=, a snapshot: restart to pick the new file up)
    from exp_common import ids
    noc = ids.new_token("expn")
    src = stack.log_dir / "noc_tokens.json"
    src.write_text(json.dumps([{"id": "noc-a34", "sha256": ids.token_hash(noc), "label": "wall screen", "role": "viewer",
                                "expires": "2099-01-01T00:00:00Z"}]))
    d.put(src, "/root/noc_tokens.json")
    d.ok("install -m 0600 -o root -g root /root/noc_tokens.json /etc/exp/dashboard/creds/noc_tokens.json"
         " && rm /root/noc_tokens.json")
    src.unlink()
    d.ok("systemctl restart exp-dashboard.service", timeout=60)
    stack._dash = None                                       # sessions do not survive the restart: log in again
    M.wait_for(lambda: stack.dash().get("probes")["items"], 60, step=2.0, what="the restarted dashboard serves again")

    # -- control: the simulated internet is reachable before the cut
    assert can_reach_public(stack), "the control failed: the dashboard host cannot reach the simulated internet"
    before = record_counts(stack)
    start_watch(stack)
    time.sleep(3)
    stack.lanctl("cut-internet")
    t_cut = time.time()
    try:
        assert json.loads(stack.lanctl("status"))["active"] is True
        assert can_reach_public(stack, stack.nodes[0].host) is False, "the internet is still reachable (management network)"

        items = M.wait_for(lambda: internet_red(stack), 90, step=3.0, what="every probe's internet line red")
        for i in items:
            ln = next(x for x in i["lines"] if x["key"] == "internet")
            assert ln["state"] in ("red", "bad", "down", "fail", "warn", "degraded") or ln["state"] != "ok", ln
            st = stack.dash().get("state", probe=i["probe"], voice="sysadmin")
            assert M.line_states(st)["internet"] != "ok" and M.line_states(st)["network"] == "ok", st["lines"]
            where = (st.get("verdict") or {}).get("where")
            assert where, f"{i['probe']}: the internet line is red but names no where: {st.get('verdict')}"

        # a local user logs in NOW (a fresh session, not the one made before the cut)
        local = M.L.Dash(stack.dashboard_url, stack.dash_fp, M.USER, stack.password)
        assert local.get("probes")["items"], "no probes for the fresh local session"
        # NOC token exchange through the real page
        env = {**os.environ, "EXP_E2E_NOC_TOKEN": noc}
        r = subprocess.run(["node", str(NOC_JS), stack.dashboard_url, str(artifacts / "a3_4-noc-internet-down.png")],
                           capture_output=True, text=True, env=env, timeout=120, cwd=str(M.REPO), check=False)
        try:
            page = json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise M.E2EError(f"noc_board.js printed no JSON (rc={r.returncode}): {r.stdout[-300:]} {r.stderr[-400:]}") from None
        assert "error" not in page, page
        assert "kiosk=1" in page["url"] and "expn_" not in page["url"] and page["whoami"] == 200, page["url"]
        assert "Hall B east" in page["text"] and "Hall C main" in page["text"], page["text"][:600]
        assert not page["errors"], page["errors"]
        # the operator's board (local session) renders, red internet visible
        shot = artifacts / "a3_4-board-internet-down.png"
        board = M.board(stack, "/", shot, "A3.4 board")
        assert shot.stat().st_size > 5000 and not board["errors"], board["errors"]
        assert "Hall B east" in board["text"] and "Internet" in board["text"], board["text"][:700]
        assert "All 3 probes are good" not in board["text"], "the board claims everything is fine without the internet"

        # live updates: beats of every probe through the dashboard's SSE stream
        events = M.read_sse(stack.dashboard_url, stack.dash_fp, local.cookie, "probes=" + ",".join(PROBES), 20)
        assert {dd["probe"] for e, dd in events if e == "beat"} == set(PROBES), [e for e, _ in events][:20]

        # probes keep measuring, collectors keep storing, until the window is long enough for several app tests (30 s)
        time.sleep(max(0.0, 75 - (time.time() - t_cut)))
        after = record_counts(stack)
        assert all(after[p] > before[p] for p in PROBES), (before, after)
        newest = {n.probe: int(n.host.sqlite("/var/lib/exp/collector/records.db",
                                             f"SELECT max(ts_ms) FROM records WHERE probe='{n.probe}'")[0]) / 1000
                  for n in stack.nodes}
        assert all(t > t_cut + 5 for t in newest.values()), {p: round(t - t_cut) for p, t in newest.items()}
        assert M.all_green(stack.dash().get("states", voice="sysadmin")["items"], PROBES) is False
    finally:
        cap = stop_watch(stack)
        stack.lanctl("restore")
        stack.save_logs("a3_4")

    assert cap["packets"] > 20, f"the capture saw almost nothing ({cap['packets']}): it is not working"
    assert cap["outside"] == [], f"the dashboard host sent/received packets outside {SUBNET}: {cap['outside'][:5]}"

    # restore: the internet is back and the lines are green again
    assert can_reach_public(stack) is True
    M.wait_for(lambda: M.all_green(stack.dash().get("states", voice="sysadmin")["items"], PROBES), 150, step=3.0,
               what="every probe green after the internet is back")
