"""A2.5 - upgrade to a new release; a deliberately broken release auto-rolls back; an unsigned or tampered release
is refused (by the manager when it is published/imported, and by the agent even when something serves it anyway).

One Ubuntu 24.04 systemd host (agent + collector + dashboard) installed from release 0.1.0 with the product's one-liner.
Everything else is built here with the throwaway release key:
  * 0.1.1  the same tree, only the version differs (the repo's VERSION file is never touched);
  * 0.1.2  a copy of the tree whose `exp-dashboard health` always answers `fail` (the "deliberately broken release");
  * 0.1.3 / 0.1.4 / 0.1.5  unsigned, tampered-manifest and tampered-artifact variants: refused by the manager, and, written
    straight into the manager's store (as a compromised store would), refused by the agent as well.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from expharness import dockerhost
from expharness.dockerhost import wait_for

import m2lib
from conftest import start_host
from m2lib import build_release, copy_tree, host_row, set_site, status_report

SITE = "upg-e2e"
OLD, NEW, BROKEN = "0.1.0", "0.1.1", "0.1.2"
ZERO_SIG = "A" * 86 + "=="  # 64 zero bytes, base64: "not signed"


@dataclass
class Up:
    host: dockerhost.Host
    host_id: str
    cids: dict[str, str]
    tmp: Path
    dist: dict[str, Path] = field(default_factory=dict)
    install: Any = None

    def desired(self, stack) -> dict[str, Any]:
        return host_row(stack, self.host_id)

    def reconcile(self, stack) -> dict[str, Any]:
        rep = status_report(stack, self.host_id)
        return (rep or {}).get("reconcile") or {}


@pytest.fixture(scope="module")
def up(stack, host_image, tmp_path_factory):
    if stack.key is None:
        pytest.skip("the release signing key is not available (EXP_E2E_DIST was given)")
    from test_a23_support import default_intent  # noqa: PLC0415

    admin = stack.admin
    set_site(stack, SITE, "Upgrade E2E")
    admin.call("PATCH", f"/sites/{SITE}/release", {"version": stack.version}, ok=(200,))
    comps = {
        "collector": ("col-up", default_intent("collector", "e2e-up")),
        "dashboard": ("dash-up", default_intent("dashboard", "e2e-up")),
    }
    host_id, enrol, cids = m2lib.create_host(stack, SITE, "e2e-up", comps)
    host = start_host(stack, "a25")
    tmp = tmp_path_factory.mktemp("a25")
    u = Up(host, host_id, cids, tmp)
    try:
        u.install = host.run(enrol["command"], timeout=600)
        assert u.install.rc == 0, u.install
        yield u
    finally:
        try:
            (stack.artifacts / "a25-host-diagnostics.txt").write_text(host.diagnostics())
            (stack.artifacts / "a25-host-journal.txt").write_text(host.journal(None, 600))
        finally:
            host.remove()


def tree_state(host: dockerhost.Host) -> str:
    """Everything the agent may have put under /opt/exp (names + symlink targets), staging leftovers included."""
    return host.run("cd /opt/exp && find . -maxdepth 2 -printf '%p -> %l\\n' | sort").out


def current(host: dockerhost.Host, comp: str) -> str:
    return host.run(f"readlink /opt/exp/{comp}/current").out.strip()


def healthy_at(stack, u: Up, version: str, comps=("collector", "dashboard")):
    rep = status_report(stack, u.host_id)
    if not rep:
        return None
    by = {c["type"]: c for c in rep["components"]}
    ok = all(c in by and by[c]["health"] == "ok" and by[c].get("version") == version for c in comps)
    return rep if ok and rep["agent"]["version"] == version else None


def converged(stack, u: Up, version: str):
    h = host_row(stack, u.host_id)
    rep = healthy_at(stack, u, version)
    if rep and h["desired_version"] == h["applied_version"] and h["agent_version"] == version:
        return h
    return None


def sql_count(stack, q: str) -> int:
    return int(next(iter(stack.mgr.sql(q)[0].values())))


def run_cron(stack) -> None:
    r = stack.mgr.run_cron("*/5 * * * *")
    assert r.status == 200, r


def site(stack) -> dict[str, Any]:
    return stack.admin.get(f"/sites/{SITE}")


# ======================================================================================== baseline
def test_installed_release_is_0_1_0(stack, up):
    h = wait_for(lambda: converged(stack, up, OLD), 240, 3, "0.1.0 healthy", up.host.diagnostics)
    assert h["state"] == "enrolled"
    assert current(up.host, "collector") == OLD and current(up.host, "dashboard") == OLD
    assert up.host.run("cat /opt/exp/agent/current/VERSION").out.strip() == OLD


# ======================================================================================== manager refuses
def test_manager_refuses_unsigned_and_tampered_releases(stack, up):
    key, pub = stack.key, stack.pub
    bad = "0.1.3"
    signed = build_release(up.tmp / "d-bad", bad, key=key, pub=pub)
    up.dist[bad] = signed
    versions = lambda: {r["version"] for r in stack.admin.get("/releases")["items"]}  # noqa: E731
    before = versions()
    manifest = (signed / f"exp-{bad}-manifest.json").read_bytes()

    # --- an unsigned dev build: the publish script and the upload API both refuse it
    unsigned = build_release(up.tmp / "d-unsigned", "0.1.9", key=None, pub=None, unsigned=True)
    assert not list(unsigned.glob("*.sig"))
    r = stack.mgr.publish_release(unsigned, stack.pub)
    assert r.returncode != 0 and "no signature" in (r.stdout + r.stderr), r
    r = m2lib.upload_release(stack, unsigned, "0.1.9", signature=b"")
    assert r.status in (400, 422), r
    r = m2lib.upload_release(stack, signed, bad, signature=bytes(64))  # present but not a signature
    assert r.status == 422 and r.json()["error"]["code"] == "signature_invalid", r
    r = m2lib.upload_release(stack, signed, bad, signature=ZERO_SIG.encode())
    assert r.status == 422 and r.json()["error"]["code"] == "signature_invalid", r

    # --- a signed release whose manifest was modified afterwards
    mod = bytearray(manifest)
    mod[-3] ^= 0x01
    r = m2lib.upload_release(stack, signed, bad, manifest=bytes(mod))
    assert r.status == 422 and r.json()["error"]["code"] in ("signature_invalid", "manifest_invalid"), r

    # --- a correctly signed manifest with one artifact whose bytes changed
    arts = {p.name: p.read_bytes() for p in sorted(signed.glob(f"exp-*-{bad}-*.tar.gz"))}
    victim = next(n for n in arts if "dashboard" in n)
    data = arts[victim]
    arts[victim] = data[: len(data) // 2] + bytes([data[len(data) // 2] ^ 0xFF]) + data[len(data) // 2 + 1 :]
    r = m2lib.upload_release(stack, signed, bad, artifacts=arts)
    assert r.status == 422 and r.json()["error"]["code"] == "artifact_hash_mismatch", r
    tampered = up.tmp / "d-tampered"
    tampered.mkdir()
    for p in signed.iterdir():
        (tampered / p.name).write_bytes(arts[p.name] if p.name in arts else p.read_bytes())
    r = stack.mgr.publish_release(tampered, stack.pub)
    assert r.returncode != 0 and "sha256" in (r.stdout + r.stderr), r

    # nothing was recorded by any of it
    assert versions() == before
    assert sql_count(stack, f"SELECT count(*) AS n FROM artifacts WHERE version IN ('{bad}', '0.1.9')") == 0
    assert sql_count(stack, f"SELECT count(*) AS n FROM releases WHERE version IN ('{bad}', '0.1.9')") == 0
    # and the site cannot be pointed at them
    r = stack.admin.call("PATCH", f"/sites/{SITE}/release", {"version": bad})
    assert r.status == 422 and r.json()["error"]["code"] == "release_not_imported", r


# ======================================================================================== upgrade
def test_upgrade_to_0_1_1_with_a_canary_then_promotion(stack, up):
    d = build_release(up.tmp / "d-new", NEW, key=stack.key, pub=stack.pub)
    up.dist[NEW] = d
    pr = stack.mgr.publish_release(d, stack.pub)
    assert pr.returncode == 0, (pr.stdout + pr.stderr)[-600:]
    assert NEW in {r["version"] for r in stack.admin.get("/releases")["items"]}

    s = stack.admin.call("PATCH", f"/sites/{SITE}/release", {"version": NEW, "canary_host_id": up.host_id}, ok=(200,)).json()
    assert s["release_version"] == OLD, "the site keeps its release until the canary is promoted"
    assert s["canary_state"] == "pending" and s["canary_host_id"] == up.host_id

    h = wait_for(lambda: converged(stack, up, NEW), 420, 4, "the host on 0.1.1 and healthy", up.host.diagnostics)
    assert h["desired_version"] == h["applied_version"]
    assert current(up.host, "collector") == NEW and current(up.host, "dashboard") == NEW
    assert up.host.run("cat /opt/exp/agent/current/VERSION").out.strip() == NEW
    assert up.host.run("systemctl is-active exp-agent exp-collector exp-dashboard").out.split() == ["active"] * 3
    assert up.reconcile(stack).get("result") == "ok"
    # the agent confirmed itself: no pending self-update marker is left behind
    assert up.host.run("test -e /var/lib/exp/agent/pending.json").rc != 0

    # canary: healthy -> (10 min later) -> promoted for the whole site
    run_cron(stack)
    wait_for(lambda: site(stack)["canary_state"] == "healthy_waiting", 30, 1, "canary healthy_waiting")
    since = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 11 * 60))
    stack.mgr.sql(f"UPDATE sites SET canary_healthy_since = '{since}' WHERE site = '{SITE}'")
    run_cron(stack)
    s = wait_for(lambda: (x := site(stack))["canary_state"] == "promoted" and x, 30, 1, "canary promoted")
    assert s["release_version"] == NEW
    # promotion is not a change for this host (it was already on 0.1.1): the agent stays converged
    assert converged(stack, up, NEW)


# ======================================================================================== broken release
def test_broken_release_rolls_back_and_is_not_retried(stack, up):
    tree = copy_tree(up.tmp / "tree-broken")
    m2lib.break_health(tree, "dashboard", BROKEN)
    d = build_release(up.tmp / "d-broken", BROKEN, key=stack.key, pub=stack.pub, tree=tree)
    up.dist[BROKEN] = d
    r = m2lib.upload_release(stack, d, BROKEN)  # the manager accepts it: it is correctly signed
    assert r.status == 201, r

    stack.admin.call("PATCH", f"/sites/{SITE}/release", {"version": BROKEN, "canary_host_id": up.host_id}, ok=(200,))
    broken_desired = wait_for(
        lambda: (h := host_row(stack, up.host_id))["desired_version"] and h, 60, 2, "a new desired version"
    )["desired_version"]

    def rolled_back():
        rec = up.reconcile(stack)
        rep = status_report(stack, up.host_id) or {}
        return rec if rec.get("result") == "rolled_back" and rep["agent"]["desired_version"] == broken_desired else None

    rec = wait_for(rolled_back, 420, 4, "the agent reporting rolled_back", up.host.diagnostics)
    assert "dashboard" in rec["error"] and "rolled back to " + NEW in rec["error"], rec
    # the dashboard runs the previous, healthy version again; the manager shows it healthy
    assert current(up.host, "dashboard") == NEW
    assert up.host.run("systemctl is-active exp-dashboard").out.strip() == "active"
    rep = wait_for(lambda: healthy_dash(stack, up), 120, 3, "dashboard healthy again on 0.1.1", up.host.diagnostics)
    assert {c["type"]: c.get("version") for c in rep["components"]}["dashboard"] == NEW
    h = host_row(stack, up.host_id)
    assert h["applied_version"] != h["desired_version"], "a rolled-back desired state is never 'applied'"
    ev = [e["msg"] for e in (status_report(stack, up.host_id) or {}).get("events", [])]
    assert any("rolled back" in m for m in ev + [up.host.journal("exp-agent", 200)]), ev

    # the fleet raises it: a reconcile_failed issue for this host, and the canary is halted
    issues = stack.admin.get("/issues?kind=reconcile_failed&state=open")["items"]
    assert any(i["host_id"] == up.host_id for i in issues), issues
    run_cron(stack)
    s = wait_for(lambda: (x := site(stack))["canary_state"] == "failed" and x, 30, 1, "canary failed")
    assert s["release_version"] == NEW, "a failed canary never promotes"

    # not retried: same desired version -> the dashboard unit is not touched again
    stamp = m2lib.unit_enter_ts(up.host, "exp-dashboard")
    n_before = up.host.journal("exp-agent", 2000).count("rolled back to")
    time.sleep(100)  # > 3 poll intervals and 1 status interval
    assert m2lib.unit_enter_ts(up.host, "exp-dashboard") == stamp, "the broken version was retried"
    assert up.host.journal("exp-agent", 2000).count("rolled back to") == n_before == 1
    assert current(up.host, "dashboard") == NEW


def healthy_dash(stack, u: Up):
    rep = status_report(stack, u.host_id)
    by = {c["type"]: c for c in (rep or {}).get("components", [])}
    d = by.get("dashboard")
    return rep if d and d["health"] == "ok" and d.get("version") == NEW else None


def test_recovery_by_setting_the_previous_release(stack, up):
    """Rollback of the rollout = set the previous version; the host converges and the broken version is gone."""
    stack.admin.call("PATCH", f"/sites/{SITE}/release", {"version": NEW}, ok=(200,))
    h = wait_for(lambda: converged(stack, up, NEW), 420, 4, "the host back on 0.1.1, converged", up.host.diagnostics)
    assert up.reconcile(stack).get("result") == "ok"
    assert h["state"] == "enrolled"
    assert current(up.host, "collector") == NEW and current(up.host, "dashboard") == NEW
    assert up.host.run("cat /opt/exp/agent/current/VERSION").out.strip() == NEW
    assert BROKEN != current(up.host, "dashboard")
    wait_for(
        lambda: not any(i["host_id"] == up.host_id for i in stack.admin.get("/issues?kind=reconcile_failed&state=open")["items"]),
        240,
        5,
        "the reconcile_failed issue resolving (two clean reports)",
    )


# ======================================================================================== the agent refuses on its own
VARIANTS = [
    # label, version, kwargs of force_publish, error pattern
    ("unsigned", "0.1.3", {"signature_b64": ZERO_SIG}, r"signature|FAILED"),
    ("tampered manifest", "0.1.4", {"tamper_manifest": True}, r"signature|FAILED"),
    ("tampered artifacts", "0.1.5", {"tamper_artifacts": True}, r"sha256|checksum|digest|mismatch|does not match|size"),
]


@pytest.mark.parametrize(("label", "version", "kw", "pattern"), VARIANTS, ids=[v[0] for v in VARIANTS])
def test_agent_refuses_a_bad_release_even_when_served(stack, up, label, version, kw, pattern):
    d = build_release(up.tmp / f"d-{version}", version, key=stack.key, pub=stack.pub)
    kw = dict(kw)
    if kw.pop("tamper_manifest", False):
        man = (d / f"exp-{version}-manifest.json").read_bytes()
        mod = bytearray(man)
        mod[-3] ^= 0x01  # still parseable JSON would not matter: the signature no longer matches
        kw["manifest"] = bytes(mod)
    m2lib.force_publish(stack, d, version, **kw)
    before = tree_state(up.host)
    units_before = up.host.run("systemctl show exp-collector exp-dashboard -p ActiveEnterTimestampMonotonic").out
    stack.admin.call("PATCH", f"/sites/{SITE}/release", {"version": version}, ok=(200,))
    want = wait_for(lambda: host_row(stack, up.host_id)["desired_version"], 30, 1, "desired version")

    def refused():
        rep = status_report(stack, up.host_id) or {}
        rec = rep.get("reconcile") or {}
        return rec if rep.get("agent", {}).get("desired_version", 0) >= want and rec.get("result") == "error" else None

    h0 = want
    rec = wait_for(refused, 240, 3, f"the agent refusing the {label} release", up.host.diagnostics)
    assert re.search(pattern, rec["error"], re.I), rec
    # fail closed: the host is exactly as it was
    assert tree_state(up.host) == before, f"{label}: files appeared under /opt/exp"
    assert current(up.host, "collector") == NEW and current(up.host, "dashboard") == NEW
    assert up.host.run("cat /opt/exp/agent/current/VERSION").out.strip() == NEW
    assert up.host.run("systemctl show exp-collector exp-dashboard -p ActiveEnterTimestampMonotonic").out == units_before
    assert up.host.run("systemctl is-active exp-agent exp-collector exp-dashboard").out.split() == ["active"] * 3
    h = host_row(stack, up.host_id)
    assert h["applied_version"] != h["desired_version"] and h0 == h["desired_version"]
    assert h["agent_version"] == NEW
    # no staging directory is left either, and nothing looks like the refused version
    found = up.host.run("find /opt/exp /var/lib/exp -maxdepth 3 -not -path '*/agent/manifests/*'").out
    assert version not in found, found
    issues = stack.admin.get("/issues?kind=reconcile_failed&state=open")["items"]
    assert any(i["host_id"] == up.host_id for i in issues)
    # put the site back to the good release; the host converges again (and the refusal is not remembered as success)
    stack.admin.call("PATCH", f"/sites/{SITE}/release", {"version": NEW}, ok=(200,))
    wait_for(lambda: converged(stack, up, NEW), 300, 4, "converged on 0.1.1 again", up.host.diagnostics)


def test_no_secret_in_the_journal(up):
    journal = "\n".join(ln for ln in up.host.journal(None, 4000).splitlines() if "COMMAND=" not in ln)
    assert not dockerhost.TOKEN_RE.findall(journal)
    json.loads(up.host.read("/etc/exp/agent.json"))  # still valid, still there
