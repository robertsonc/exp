"""06-agent.md section 9 item 2: every host shape converges with REAL component artifacts and reports
healthy; probe data reaches the collector through the wiring the manager compiled.

Needs a built, signed release: EXP_DIST_DIR=<dir with exp-<v>-manifest.json[.sig] and the tarballs>
(packaging/build.sh --release) and its public key in EXP_RELEASE_PUBKEY (or packaging/keys/release-pub.pem).
Skipped otherwise: WP-7/WP-8 run it once the component tarballs exist. NOT exercised by WP-6 itself.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from harness import REPO, exp_ids, run_install, wait_for

DIST = os.environ.get("EXP_DIST_DIR", "")
PUB = os.environ.get("EXP_RELEASE_PUBKEY") or str(REPO / "packaging/keys/release-pub.pem")


def _why_skip() -> str | None:
    if not DIST:
        return "EXP_DIST_DIR is not set: this test needs built release tarballs of every component (WP-7/WP-8 run it)"
    d = Path(DIST)
    if not d.is_dir() or not list(d.glob("exp-*-manifest.json")):
        return f"EXP_DIST_DIR={DIST} has no exp-<version>-manifest.json"
    if not list(d.glob("exp-*-manifest.json.sig")):
        return f"EXP_DIST_DIR={DIST} holds an UNSIGNED dev build: the agent only installs signed releases"
    if not Path(PUB).is_file():
        return f"no release public key at {PUB} (set EXP_RELEASE_PUBKEY)"
    return None


pytestmark = pytest.mark.skipif(_why_skip() is not None, reason=_why_skip() or "")


def healthy(world, hid, *types):
    rep = world.last_report(hid)
    if not rep:
        return None
    by = {c["type"]: c for c in rep["components"]}
    return rep if all(t in by and by[t]["health"] == "ok" for t in types) else None


def test_all_shapes_converge_and_probe_data_reaches_the_collector(world, host24):
    host24.reset_host()
    version = world.load_dist(Path(DIST))
    world.serve_install_sh(pubkey_pem=Path(PUB).read_text(), agent_version=version)
    from harness import fc

    hid, token = world.add_host("srv-shapes")
    probe_token = exp_ids.new_token("expi")
    col = world.collector_component(
        version,
        creds={
            "ingest_tokens.json": json.dumps({"probe-a1": exp_ids.token_hash(probe_token)}),
            "dashboard_tokens.json": "{}",
            "webhooks.json": "[]",
        },
    )
    world.set_desired(hid, version, components=[col])
    r = run_install(host24, world, token)
    assert r.rc == 0, r
    rep = wait_for(lambda: healthy(world, hid, "collector"), 300, 5, "a healthy collector", host24.agent_log)
    facts = next(c for c in rep["components"] if c["type"] == "collector")["facts"]
    fp, listen = facts["tls_fingerprint_sha256"], facts["listen"]
    # a dashboard wired to that collector and a probe with two veth ports, as the manager would compile them
    host24.run(
        "for i in 0 1; do ip link add vp$i type veth peer name vp$i-peer; ip link set vp$i up; ip link set vp$i-peer up; done"
    )
    pcfg = fc.load_fixture("desired/probe-host.json")["components"][0]["config"]
    pcfg["collector"] = {"url": "https://" + listen, "tls_fingerprint_sha256": fp, "fallback": []}
    pcfg["mgmt_iface"] = "eth0"
    pcfg["ports"][0]["iface"], pcfg["ports"][1]["iface"] = "vp0", "vp1"
    dcfg_src = fc.load_fixture("desired/dashboard-host.json")["components"][0]
    dcfg = dict(dcfg_src["config"])
    dcfg["collectors"] = [
        {
            "collector_id": col["id"],
            "site": "hall-b",
            "url": "https://" + listen,
            "tls_fingerprint_sha256": fp,
        }
    ]
    dcfg["listen"] = {"https": "127.0.0.1:443", "http_redirect": "127.0.0.1:80"}
    dash = world.component("dashboard", version, dcfg, dcfg_src["creds"], dcfg_src["id"])
    probe = world.component("probe", version, pcfg, {"ingest_token": probe_token}, "probe-a1")
    world.set_desired(hid, version, components=[col, dash, probe])
    wait_for(
        lambda: healthy(world, hid, "collector", "dashboard", "probe"),
        420,
        5,
        "collector, dashboard and probe healthy",
        host24.agent_log,
    )
    probe_h = next(c for c in world.last_report(hid)["components"] if c["type"] == "probe")
    assert probe_h["health"] == "ok"
