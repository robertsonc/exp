"""A3.2 (SPEC.md section 9, M3): alerts and webhooks, end to end, on the multisite stack.

Faults come from the simulated LAN (per-port DNS blocks, a dead gateway); the collectors judge, open incidents and
POST Slack / Teams / JSON messages to a local https receiver that records every request as a JSON line. Every
assertion compares what the receiver got with what the incidents API says. Timing is the spec's:
  hold_down_s 20, hold_back_s 60, reopen_s 300, calm_s 600
except on col-b2 (the flapping scenario), which runs hold_back_s 30 / calm_s 90 so that "quiet until calm" is
observable in minutes instead of ten (m3lib.NODES). The tests run in file order on one stack; each one starts by
re-establishing a calm baseline (all lines green, nothing open, no fault, empty receiver), so a failure in one does
not poison the next.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

import pytest

import m3lib as M

pytestmark = pytest.mark.e2e

FORMATS = M.HOOK_FORMATS
PROBES = [n["probe"] for n in M.NODES]
HOLD_DOWN_S = 20


# ------------------------------------------------------------------------------------------ decoding
def title_of(p: dict[str, Any]) -> str:
    d = p["doc"]
    if p["fmt"] == "json":
        return str(d["title"])
    if p["fmt"] == "slack":
        m = re.match(r"^:[a-z_]+: \*(.+?)\* · ", d["text"])
        assert m, d["text"][:200]
        return m.group(1)
    return str(d["attachments"][0]["content"]["body"][0]["text"]).split(" · ")[0]


def kind_of(p: dict[str, Any]) -> str:
    """down | again | flapping | back, from the message itself (the title), the same way a person reads it."""
    t = title_of(p)
    if t.endswith("failing again"):
        return "again"
    if t.endswith("flapping"):
        return "flapping"
    if t.endswith("is back") or t.endswith("is reporting again"):
        return "back"
    return "down"


def kinds(m: M.Multi, node: M.Node, fmt: str, since: float) -> list[str]:
    return [kind_of(p) for p in sorted(m.pages(node, since), key=lambda x: x["seq"]) if p["fmt"] == fmt]


def wait_kinds(m: M.Multi, node: M.Node, expect: list[str], since: float, timeout: float, what: str) -> None:
    """Wait until EVERY format has received exactly `expect` (in order, no other message of any line)."""
    def ok() -> bool:
        return all(kinds(m, node, f, since) == expect for f in FORMATS)

    try:
        M.wait_for(ok, timeout, step=2.0, what=what)
    except M.E2EError:
        got = {f: kinds(m, node, f, since) for f in FORMATS}
        raise M.E2EError(f"{what}: wanted {expect} on every format, receiver has {got}") from None


def every_format(m: M.Multi, node: M.Node, since: float) -> dict[str, list[str]]:
    return {f: kinds(m, node, f, since) for f in FORMATS}


def incidents(m: M.Multi, probe: str) -> list[dict[str, Any]]:
    return sorted(m.dash().get("incidents", probe=probe)["items"], key=lambda i: i["start"])


def json_pages(m: M.Multi, node: M.Node, since: float) -> list[dict[str, Any]]:
    return sorted((p for p in m.pages(node, since) if p["fmt"] == "json"), key=lambda p: p["seq"])


# ------------------------------------------------------------------------------------------ baseline
@pytest.fixture(autouse=True)
def calm(stack: M.Multi) -> float:
    """Probes running and green, no fault, no open incident, empty receiver. Returns the baseline time."""
    for n in stack.nodes:
        if n.host.run("systemctl is-active exp-probe.service").stdout.strip() != "active":
            n.host.ok("systemctl start " + " ".join(n.probe_units()), timeout=120)
    stack.lanctl("restore")

    def settled() -> bool:
        doc = stack.dash().get("states", voice="sysadmin")
        if not (M.all_green(doc["items"], PROBES) and all(c["ok"] for c in doc["collectors"])):
            return False
        return not [i for p in PROBES for i in incidents(stack, p) if i["end"] is None and i["folded_into"] is None]

    M.wait_for(settled, 300, step=3.0, what="every probe green and no incident open (calm baseline)")
    for lan in (1, 2):
        stack.canary(lan)                                    # known-good control before any fault
    time.sleep(2)
    stack.lanctl("hooks-clear")
    return time.time()


def restore(m: M.Multi) -> float:
    m.lanctl("restore")
    assert json.loads(m.lanctl("status"))["active"] is False
    return time.time()


# ============================================================================================ (a) down / back
def test_a3_2_a_dns_block_pages_down_once_per_format_and_back_after_restore(stack: M.Multi, calm: float) -> None:
    n = stack.node("probe-b1")
    before = {i["id"] for i in incidents(stack, n.probe)}
    stack.block_dns(n)
    t_block = time.time()

    def down() -> dict[str, Any] | None:
        return next((i for i in incidents(stack, n.probe) if i["line"] == "dns" and i["kind"] == "down"
                     and i["id"] not in before and i["folded_into"] is None), None)

    inc = M.wait_for(down, 90, step=2.0, what="a dns 'down' incident on probe-b1")
    wait_kinds(stack, n, ["down"], calm, 60, "one 'down' page per format")
    time.sleep(12)                                           # stay failing: still exactly one page, not one per tick
    assert every_format(stack, n, calm) == {f: ["down"] for f in FORMATS}

    # after the hold: nothing was paged before the failure had lasted hold_down_s
    start = M.parse_iso(inc["start"])
    pages = [p for p in stack.pages(n, calm)]
    assert min(p["ts"] for p in pages) >= start + HOLD_DOWN_S - 1, (start, [p["ts"] for p in pages])
    assert start >= t_block - 15, "the incident is not about this fault"
    # the same incident everywhere: the JSON page carries the incident id the API lists; Slack and Teams name the probe
    jp = json_pages(stack, n, calm)
    assert [p["doc"]["incident"] for p in jp] == [inc["id"]] and jp[0]["doc"]["line"] == "dns"
    assert jp[0]["doc"]["kind"] == "down" and jp[0]["doc"]["board"] == n.probe
    assert (inc["where"] or {}).get("seg") in {"resolver", "dns_path"} if isinstance(inc["where"], dict) else inc["where"]
    stack.notes["a_down_inc"] = inc
    # nothing but DNS paged (what else failed with it is folded or green)
    assert {p["doc"]["line"] for p in jp} == {"dns"}

    # restore: back after hold_back_s of ok, once per format
    t_restore = restore(stack)
    stack.canary(1)
    wait_kinds(stack, n, ["down", "back"], calm, 150, "one 'back' page per format after the restore")
    backs = [p for p in stack.pages(n, calm) if kind_of(p) == "back"]
    assert len(backs) == len(FORMATS)
    assert min(p["ts"] for p in backs) >= t_restore + 58, "back was paged before hold_back_s of ok"
    rows = [i for i in incidents(stack, n.probe) if i["line"] == "dns" and i["id"] not in before]
    down_rows = [r for r in rows if r["kind"] == "down" and r["folded_into"] is None]
    back_rows = [r for r in rows if r["kind"] == "back"]
    assert len(down_rows) == 1 and len(back_rows) == 1, rows
    assert down_rows[0]["end"] and M.parse_iso(down_rows[0]["end"]) > M.parse_iso(down_rows[0]["start"])
    jp = json_pages(stack, n, calm)
    assert [p["doc"]["incident"] for p in jp] == [down_rows[0]["id"], back_rows[0]["id"]]
    stack.notes["a_back_end"] = down_rows[0]["end"]
    stack.save_logs("a3_2_a")


# ============================================================================================ (b) again
def test_a3_2_b_refailure_within_reopen_pages_again_not_a_new_down(stack: M.Multi, calm: float) -> None:
    """Builds on (a): the dns incident of probe-b1 closed a minute ago; a re-failure inside reopen_s (300 s) reopens it."""
    n = stack.node("probe-b1")
    if "a_back_end" not in stack.notes:
        pytest.skip("needs test (a) to have closed the dns incident of probe-b1 just before")
    assert time.time() - M.parse_iso(stack.notes["a_back_end"]) < 280, "too late: reopen_s (300 s) has passed since (a)"
    before = incidents(stack, n.probe)
    stack.block_dns(n)
    wait_kinds(stack, n, ["again"], calm, 90, "an 'again' page (not a new 'down') on every format")
    time.sleep(10)
    assert every_format(stack, n, calm) == {f: ["again"] for f in FORMATS}
    restore(stack)
    wait_kinds(stack, n, ["again", "back"], calm, 150, "'back' after the second recovery")
    new = [i for i in incidents(stack, n.probe) if i["id"] not in {b["id"] for b in before}]
    assert sorted(r["kind"] for r in new if r["line"] == "dns") == ["again", "back"], new     # no second 'down' row
    down = next(i for i in before if i["line"] == "dns" and i["kind"] == "down" and i["folded_into"] is None)
    again = next(r for r in new if r["kind"] == "again")
    assert again["start"] == down["start"], "'again' reopens the SAME incident"
    jp = json_pages(stack, n, calm)
    assert [(p["doc"]["kind"], p["doc"]["incident"]) for p in jp][0] == ("again", again["id"])
    assert any("2 times" in ln for ln in jp[0]["doc"]["lines"]), jp[0]["doc"]["lines"]
    assert any("2 times in all" in ln for ln in jp[1]["doc"]["lines"]), jp[1]["doc"]["lines"]
    stack.save_logs("a3_2_b")


# ============================================================================================ (c) flapping + hygiene
LINK_RE = r"^https://%s/probe/(probe-[a-z0-9]+)\?at=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)$"


def check_payloads(m: M.Multi, node: M.Node, pages: list[dict[str, Any]], start_iso: str) -> None:
    """Payload hygiene (03 section 6, SR-13): probe-supplied text arrives escaped in every format, the board link is
    present and rewinds to the incident's start. `node`'s probe label is m3lib.HOSTILE_LABEL (markup)."""
    link_re = re.compile(LINK_RE % re.escape(m.dash_host.ip))
    for p in pages:
        rec, doc = p["rec"], p["doc"]
        assert rec["headers"]["content-type"] == "application/json" and rec["headers"]["user-agent"] == "exp-collector"
        text = json.dumps(doc, ensure_ascii=False)
        # nothing a chat client could turn into a mention, a link or a tag survives
        assert "<!channel>" not in text and "<img>" not in text and "http://x.test" not in text, text
        assert "@here" not in text.replace("@\u200bhere", ""), text
        if p["fmt"] == "slack":
            body = doc["text"]
            assert "&lt;!channel&gt;" in body and "&lt;img&gt;" in body and "@\u200bhere" in body, body
            links = re.findall(r"<([^>]*)>", body)
            assert len(links) == 1 and links[0].split("|")[1] in ("Open the board at the start", "Rewind to the start"), body
            link = links[0].split("|")[0]
            rest = re.sub(r"<[^>]*>", "", body)
            assert "<" not in rest and ">" not in rest, body
        elif p["fmt"] == "teams":
            card = doc["attachments"][0]["content"]
            blob = " ".join(b["text"] for b in card["body"])
            assert not re.search(r"[<>\[\]]", blob), blob
            assert "\u2039!channel\u203a" in blob and "@\u200bhere" in blob, blob
            (action,) = card["actions"]
            assert action["type"] == "Action.OpenUrl"
            link = action["url"]
        else:
            assert doc["probe"].startswith("Hall B west &lt;!channel&gt;") and "@\u200bhere" in doc["probe"], doc["probe"]
            assert doc["board"] == node.probe
            link = doc["link"]
        mm = link_re.match(link)
        assert mm, f"unexpected board link {link!r}"
        assert mm.group(1) == node.probe
        assert abs(M.parse_iso(mm.group(2)) - M.parse_iso(start_iso)) <= 1.5, (link, start_iso)


def test_a3_2_c_third_failure_pages_flapping_once_then_quiet_until_calm(stack: M.Multi, calm: float) -> None:
    n = stack.node("probe-b2")                               # hold_back_s 30 / calm_s 90 (documented in the module doc)
    calm_s = n.alerts["calm_s"]
    expect: list[str] = []
    t_cycle = time.time()
    for kind in ("down", "back", "again", "back", "flapping"):
        expect.append(kind)
        if kind != "back":
            stack.block_dns(n)
        wait_kinds(stack, n, expect, calm, 120, f"a '{kind}' page on every format")
        if kind != "back":
            time.sleep(3)
            restore(stack)
    assert time.time() - t_cycle < 600, "three failures must land inside the 10-minute flap window"
    t_flap_restore = time.time()
    assert every_format(stack, n, calm) == {f: expect for f in FORMATS}
    # quiet until calm: the line is fine again, but no 'back' while it is muted (calm_s of ok is required)
    time.sleep(calm_s - 25)
    assert every_format(stack, n, calm) == {f: expect for f in FORMATS}, "a page arrived while muted"
    stack.block_dns(n)                                       # a further failure while muted stays quiet too
    time.sleep(HOLD_DOWN_S + 12)
    restore(stack)
    t_calm_restore = time.time()
    assert every_format(stack, n, calm) == {f: expect for f in FORMATS}, "a muted line paged a failure"
    wait_kinds(stack, n, [*expect, "back"], calm, calm_s + 90, "one 'back' after calm_s")
    back = max((p for p in stack.pages(n, calm) if kind_of(p) == "back"), key=lambda p: p["ts"])
    assert back["ts"] >= t_calm_restore + calm_s - 5, "the muted incident closed before it had been calm for calm_s"
    assert back["ts"] > t_flap_restore + calm_s
    rows = [i for i in incidents(stack, n.probe) if i["line"] == "dns"]
    assert sorted(r["kind"] for r in rows if r["folded_into"] is None) == sorted(
        ["down", "back", "again", "back", "flapping", "back"]), rows
    jp = json_pages(stack, n, calm)
    assert [p["doc"]["kind"] for p in jp] == ["down", "resolved", "again", "resolved", "flapping", "resolved"]
    ids = {r["id"] for r in rows}
    assert all(p["doc"]["incident"] in ids for p in jp)
    fl = jp[4]
    assert fl["doc"]["incident"] == next(r["id"] for r in rows if r["kind"] == "flapping")
    assert any("can't make up its mind" in ln.lower() for ln in fl["doc"]["lines"]), fl["doc"]["lines"]
    # payload hygiene over every message kind (down, back, again, back, flapping, back) and every format
    down_row = next(r for r in rows if r["kind"] == "down")
    check_payloads(stack, n, stack.pages(n, calm), down_row["start"])
    assert len(stack.pages(n, calm)) == 6 * len(FORMATS)
    stack.save_logs("a3_2_c")


# ============================================================================================ (d) folding
def test_a3_2_d_gateway_down_pages_network_and_folds_dhcp_dns_internet(stack: M.Multi, calm: float) -> None:
    n = stack.node("probe-c1")
    before = {i["id"] for i in incidents(stack, n.probe)}
    stack.lanctl("gateway-down", "--site", "2")
    t_cut = time.time()
    wait_kinds(stack, n, ["down"], calm, 120, "one Network 'down' page per format")
    jp = json_pages(stack, n, calm)
    net = next(i for i in incidents(stack, n.probe) if i["line"] == "network" and i["kind"] == "down" and i["id"] not in before)
    assert jp[0]["doc"]["incident"] == net["id"] and net["folded_into"] is None and jp[0]["doc"]["line"] == "network"
    assert "network" in jp[0]["doc"]["title"].lower()
    check_link_only(stack, n, calm, net["start"])
    # stay down long enough for the lines below it to fail and pass their own hold (internet's window is 120 s)
    time.sleep(max(0.0, 130 - (time.time() - t_cut)))
    rows = [i for i in incidents(stack, n.probe) if i["id"] not in before]
    folded = [r for r in rows if r["folded_into"]]
    assert folded and all(r["folded_into"] == net["id"] for r in folded), rows
    folded_lines = {r["line"] for r in folded}
    assert {"dns", "internet"} <= folded_lines <= {"dhcp", "dns", "internet", "apps"}, f"folded lines: {folded_lines}"
    # recorded but never paged: the only message is the network's
    assert every_format(stack, n, calm) == {f: ["down"] for f in FORMATS}
    assert {p["doc"]["line"] for p in json_pages(stack, n, calm)} == {"network"}

    restore(stack)
    stack.canary(2)
    wait_kinds(stack, n, ["down", "back"], calm, 180, "one 'back' per format after the gateway returns")
    time.sleep(70)                                           # folded lines must not page once the cause is gone either
    assert every_format(stack, n, calm) == {f: ["down", "back"] for f in FORMATS}
    rows = [i for i in incidents(stack, n.probe) if i["id"] not in before]
    assert all(r["end"] for r in rows if r["folded_into"]), "a folded incident is still open after recovery"
    assert not [r for r in rows if r["folded_into"] is None and r["line"] != "network"], rows
    stack.notes["d_folded"] = sorted(folded_lines)
    stack.save_logs("a3_2_d")


def check_link_only(m: M.Multi, node: M.Node, since: float, start_iso: str) -> None:
    """The board link of every format, for a probe whose label is plain."""
    link_re = re.compile(LINK_RE % re.escape(m.dash_host.ip))
    for p in m.pages(node, since):
        d = p["doc"]
        link = (re.findall(r"<([^>|]*)\|", d["text"])[0] if p["fmt"] == "slack"
                else d["attachments"][0]["content"]["actions"][0]["url"] if p["fmt"] == "teams" else d["link"])
        mm = link_re.match(link)
        assert mm and mm.group(1) == node.probe, link
        assert abs(M.parse_iso(mm.group(2)) - M.parse_iso(start_iso)) <= 1.5, (link, start_iso)


# ============================================================================================ (e) the URL is a secret
def test_a3_2_e_webhook_urls_never_appear_in_collector_logs(stack: M.Multi) -> None:
    delivered = 0
    for node in stack.nodes:
        log = node.host.run("journalctl --no-pager -u exp-collector.service 2>&1").stdout
        assert node.hook_secret not in log and f"{M.NET_IP}:{M.HOOKS_PORT}" not in log and "/hook/" not in log, \
            f"{node.cid}: the webhook URL leaked into the journal"
        delivered += len(re.findall(r"alert \w+ for \w+ delivered to (slack|teams|json)", log))
    assert delivered >= 3 * len(FORMATS), f"only {delivered} deliveries are logged: the scan would be vacuous"
