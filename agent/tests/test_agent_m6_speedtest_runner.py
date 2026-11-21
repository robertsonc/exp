"""M6 (WP-6 at M6): agent support for the `runner` and `speedtest` component types and the all-in-one host.

Covers the REAL unit templates shipped in runner/systemd and speedtest/systemd (users, capabilities, hardening,
credentials, writable paths), convergence of probe + collector + runner + speedtest in the tmp-root harness
(no user / unit / credential-name collisions, fixed order), the scoped ping_group_range drop-in, the branding assets
and their removal on decommission."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

import fakes_common as fc
import pytest
from agent_helpers import SVC_UID, Env, component_files
from exp_common import ids as exp_ids

from exp_agent import assets, desired, install, pingsys, units
from exp_agent.decommission import local_cleanup, remove_component
from exp_agent.errors import PathRefused
from exp_agent.pathguard import Paths
from exp_agent.reconcile import Reconciler
from exp_agent.runner import Result

REPO = Path(__file__).resolve().parents[2]
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8" fill="#01a982"/></svg>'


def real_unit(c: str) -> str:
    return (REPO / c / "systemd" / f"exp-{c}.service").read_text(encoding="utf-8")


def real_files(c: str, version: str = "0.1.0") -> dict:
    files = component_files(c, version)
    files[f"systemd/exp-{c}.service"] = real_unit(c).encode()
    return files


def directives(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        k, _, v = line.partition("=")
        out.setdefault(f"{section}{k}", []).append(v.strip())
    return out


def rendered(c: str) -> dict[str, list[str]]:
    paths = Paths("/")
    return directives(
        units.render(f"exp-{c}.service", real_unit(c), units.placeholder_values(paths, c, "0.1.0"))
    )


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.path("/proc/sys/net/ipv4").mkdir(parents=True)
    e.set_ping("0 2147483647")
    yield e
    e.close()


def _set_ping(self: Env, value: str) -> None:
    self.path("/proc/sys/net/ipv4/ping_group_range").write_text(value + "\n")


Env.set_ping = _set_ping  # type: ignore[attr-defined]


# ----------------------------------------------------------------------------------------- the real unit templates
def test_runner_unit_is_unprivileged_and_hardened():
    d = rendered("runner")
    assert d["[Service]User"] == d["[Service]Group"] == ["exp-runner"]
    assert d["[Service]CapabilityBoundingSet"] == [""] and d["[Service]AmbientCapabilities"] == [""]
    for key in (
        "NoNewPrivileges",
        "ProtectKernelTunables",
        "RestrictSUIDSGID",
        "LockPersonality",
        "PrivateTmp",
    ):
        assert d[f"[Service]{key}"] == ["yes"], key
    assert d["[Service]ProtectSystem"] == ["strict"] and d["[Service]ProtectHome"] == ["yes"]
    assert d["[Service]StateDirectory"] == ["exp/runner"] and d["[Service]RuntimeDirectory"] == ["exp/runner"]
    assert "[Service]ReadWritePaths" not in d  # StateDirectory/RuntimeDirectory are the only writable places
    assert d["[Service]RestrictAddressFamilies"] == ["AF_INET AF_INET6 AF_UNIX"]
    assert "~@privileged @resources" in d["[Service]SystemCallFilter"]
    assert d["[Service]ExecStart"] == [
        "/opt/exp/runner/0.1.0/bin/exp-runner run --config /etc/exp/runner/config.json"
    ]


def test_speedtest_unit_has_exactly_cap_net_bind_service():
    d = rendered("speedtest")
    assert d["[Service]User"] == d["[Service]Group"] == ["exp-speedtest"]
    # the ONLY capability, in the bounding set AND the ambient set: ports 80/443/53 on serve.listen_ip. Not CAP_NET_RAW:
    # the path timer uses unprivileged ICMP sockets (agent-managed ping_group_range drop-in).
    assert d["[Service]AmbientCapabilities"] == ["CAP_NET_BIND_SERVICE"]
    assert d["[Service]CapabilityBoundingSet"] == ["CAP_NET_BIND_SERVICE"]
    text = real_unit("speedtest")
    assert "CAP_NET_RAW" not in "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "# Ports 80/443/53" in text  # the capability is justified in the unit itself
    for key in ("NoNewPrivileges", "PrivateDevices", "ProtectKernelTunables", "MemoryDenyWriteExecute"):
        assert d[f"[Service]{key}"] == ["yes"], key
    assert d["[Service]ProtectSystem"] == ["strict"]
    assert d["[Service]StateDirectory"] == ["exp/speedtest"] and "[Service]ReadWritePaths" not in d
    assert "~@privileged @resources" in d["[Service]SystemCallFilter"]


@pytest.mark.parametrize("c", ["runner", "speedtest"])
def test_unit_credentials_stay_in_the_component_creds_dir(c):
    paths = Paths("/")
    text = units.render(f"exp-{c}.service", real_unit(c), units.placeholder_values(paths, c, "0.1.0"))
    info = units.inspect(f"exp-{c}.service", text)
    files = units.referenced_credential_files(info, f"/etc/exp/{c}/creds")
    assert files and len(files) == len(set(files))
    assert info.has_install and not info.has_reload


def test_credential_names_match_the_contract():
    # 01-contracts.md 14.7: the files the manager compiles for these units
    assert sorted(f for f in re.findall(r"LoadCredential=([a-z_.0-9]+):", real_unit("speedtest"))) == sorted(
        ["collector_token", "runner_channel_token_sha256", "tls.crt", "tls.key"]
    )
    assert {
        "collector_token",
        "speedtest_channel_token",
        "device_key_secret",
        "integrations.json",
        "ingest_token",
    } <= set(re.findall(r"LoadCredential=([a-z_.0-9]+):", real_unit("runner")))


def test_agent_knows_both_types_users_and_order():
    assert desired.ORDER == ("collector", "runner", "speedtest", "dashboard", "probe")
    assert install.SERVICE_USERS["runner"] == ("exp-runner",)
    assert install.SERVICE_USERS["speedtest"] == ("exp-speedtest",)
    for c in ("runner", "speedtest"):  # requirements.apt only names allowlisted packages
        install.check_requirements(install.read_requirements(REPO / c))


# ----------------------------------------------------------------------------------------- all-in-one convergence
def converge_all_in_one(env: Env):
    for c in ("collector", "probe", "runner", "speedtest"):
        files = real_files(c) if c in ("runner", "speedtest") else component_files(c, "0.1.0")
        env.add_artifact(c, "0.1.0", files, "amd64" if c == "collector" else "noarch")
    env.sign_release("0.1.0")
    comps = [env.comp(c) for c in ("probe", "speedtest", "runner", "collector")]
    env.push(env.desired(comps))
    code, doc, _ = env.client.get_desired(None)
    assert code == 200
    return Reconciler(env.ctx).run(doc), comps


def test_all_in_one_host_converges_without_collisions(env):
    out, _ = converge_all_in_one(env)
    assert out.result == "ok", out.error
    p = env.ctx.paths
    # fixed order: collector -> runner -> speedtest -> probe (restarts)
    restarts = [c[2] for c in env.runner.argvs("systemctl", "restart")]
    order = []
    for u in restarts:
        name = u.split(".")[0].split("-")[1]
        if name not in order:
            order.append(name)
    assert order.index("collector") < order.index("runner") < order.index("speedtest") < order.index("probe")
    # one distinct service user per component, no overlap
    assert env.runner.users >= {"exp-collector", "exp-vm", "exp-runner", "exp-speedtest"}
    allowed = [x for x in install.SERVICE_USERS.values()]
    flat = [u for users in allowed for u in users]
    assert len(flat) == len(set(flat))
    # no unit file, credential dir or state dir is shared between components
    unit_files = sorted(os.listdir(p.systemd))
    assert len(unit_files) == len(set(unit_files))
    assert {
        "exp-runner.service",
        "exp-speedtest.service",
        "exp-collector.service",
        "exp-probe.service",
    } <= set(unit_files)
    for c in ("runner", "speedtest"):
        assert os.readlink(p.current(c)) == "0.1.0" and os.path.islink(p.bin_link(c))
        assert stat.S_IMODE(os.lstat(p.creds_dir(c)).st_mode) == 0o700
    cd = p.creds_dir("speedtest")
    assert sorted(os.listdir(cd)) == ["collector_token", "runner_channel_token_sha256", "tls.crt", "tls.key"]
    assert (
        cd / "tls.crt"
    ).read_bytes() == b""  # tls.mode = none: referenced files exist (empty) so the unit starts
    # the agent does not pre-create service state for these two: systemd StateDirectory= owns it
    assert not os.path.exists(p.state_dir("speedtest")) and not os.path.exists(p.state_dir("runner"))
    # health ran for both types and the status report carries them
    assert any("exp-speedtest" in c[0] and c[1] == "health" for c in env.runner.calls)
    assert any("exp-runner" in c[0] and c[1] == "health" for c in env.runner.calls)


def test_all_in_one_second_reconcile_changes_nothing(env):
    converge_all_in_one(env)
    env.runner.calls.clear()
    code, doc, _ = env.client.get_desired(None)
    out = Reconciler(env.ctx).run(doc)
    assert out.result == "ok" and not out.changed
    assert env.runner.mutating() == []


def test_unit_ports_in_the_all_in_one_fixture_do_not_collide():
    doc = fc.load_fixture("desired/all-in-one-speedtest.json")
    binds: list[tuple[str, str, int, str]] = []  # (component, ip, port, proto)
    for comp in doc["components"]:
        cfg = comp["config"]
        if comp["type"] == "collector":
            ip, _, port = cfg["listen"].rpartition(":")
            binds.append(("collector", ip, int(port), "tcp"))
            binds.append(("reflector", ip, cfg["reflector"]["port"], "tcp"))
            binds.append(("iperf3", ip, cfg["iperf3"]["port"], "tcp"))
            binds.append(("vm", "127.0.0.1", 8428, "tcp"))
        elif comp["type"] == "speedtest":
            ip = cfg["serve"]["listen_ip"]
            binds += [
                ("speedtest", ip, 80, "tcp"),
                ("speedtest-dns", ip, 53, "udp"),
                ("speedtest-dns", ip, 53, "tcp"),
            ]
            lip, _, lport = cfg["local_channel"]["listen"].rpartition(":")
            binds.append(("speedtest-channel", lip, int(lport), "tcp"))
        elif comp["type"] == "runner":
            sl = cfg["correlation"]["sources"]["syslog"]
            for spec in sl["listen"]:
                proto, _, port = spec.partition(":")
                binds.append(("runner", sl["bind"], int(port), "tcp" if proto == "tls" else proto))
    for i, a in enumerate(binds):
        for b in binds[i + 1 :]:
            same_endpoint = (a[2], a[3]) == (b[2], b[3])
            overlap = a[1] == b[1] or "0.0.0.0" in (a[1], b[1])  # noqa: S104
            assert not (same_endpoint and overlap and a[0] != b[0]), (a, b)


# ----------------------------------------------------------------------------------------- unprivileged ICMP drop-in
def test_no_dropin_when_the_range_already_covers_the_group(env):
    converge_all_in_one(env)
    assert not os.path.exists(env.ctx.paths.sysctl_dropin)
    assert env.runner.argvs("sysctl") == []


def test_dropin_widens_an_empty_range_to_exactly_the_service_group(env):
    env.set_ping("1 0")  # kernel default: disabled
    converge_all_in_one(env)
    p = env.ctx.paths
    text = p.sysctl_dropin.read_text()
    assert f"net.ipv4.ping_group_range = {SVC_UID} {SVC_UID}\n" in text
    assert "# exp-original: 1 0\n" in text
    assert stat.S_IMODE(os.lstat(p.sysctl_dropin).st_mode) == 0o644
    assert ["sysctl", "-w", f"net.ipv4.ping_group_range={SVC_UID} {SVC_UID}"] in env.runner.calls


def test_dropin_widens_a_narrow_range_minimally_and_is_idempotent(env):
    env.set_ping("0 100")
    gid = SVC_UID
    assert pingsys.ensure(env.ctx, gid) is True
    assert f"= 0 {gid}\n" in env.ctx.paths.sysctl_dropin.read_text()
    env.set_ping(f"0 {gid}")  # what sysctl -w did
    env.runner.calls.clear()
    assert pingsys.ensure(env.ctx, gid) is False  # same file, live value already right
    assert env.runner.argvs("sysctl") == []
    assert "# exp-original: 0 100\n" in env.ctx.paths.sysctl_dropin.read_text()  # original survives re-runs


def test_revert_restores_the_original_range_and_removes_only_our_file(env):
    env.set_ping("1 0")
    other = env.path("/etc/sysctl.d/99-other.conf")
    other.parent.mkdir(parents=True, exist_ok=True)
    other.write_text("vm.swappiness = 10\n")
    pingsys.ensure(env.ctx, SVC_UID)
    env.set_ping(f"{SVC_UID} {SVC_UID}")
    env.runner.calls.clear()
    assert pingsys.revert(env.ctx) is True
    assert not os.path.exists(env.ctx.paths.sysctl_dropin)
    assert other.read_text() == "vm.swappiness = 10\n"
    assert ["sysctl", "-w", "net.ipv4.ping_group_range=1 0"] in env.runner.calls
    assert pingsys.revert(env.ctx) is False


def test_sysctl_failure_is_not_fatal(env):
    env.set_ping("1 0")
    env.runner.fail[("sysctl",)] = Result(1, "", "permission denied")
    out, _ = converge_all_in_one(env)
    assert out.result == "ok", out.error  # the speedtest degrades (ping fallback), the host still converges
    assert any("unprivileged ICMP" in e["msg"] for e in env.ctx.state.pending_events())


def test_path_guard_allows_only_the_one_sysctl_file(tmp_path):
    paths = Paths(tmp_path)
    assert paths.guard(paths.host("/etc/sysctl.d/60-exp-speedtest-ping.conf"))
    for bad in (
        "/etc/sysctl.d/60-other.conf",
        "/etc/sysctl.d",
        "/etc/sysctl.conf",
        "/etc/sysctl.d/x/60-exp-speedtest-ping.conf",
    ):
        with pytest.raises(PathRefused):
            paths.guard(paths.host(bad))


# ----------------------------------------------------------------------------------------- assets
def reference(env: Env, *entries: dict) -> None:
    """SR-6: the manager serves an artifact only while the host's desired state references it."""
    comp = {
        "type": "speedtest",
        "assets": list(entries),
        "artifact": {"id": "art_00000000000000000000000000"},
    }
    host = env.app.hosts[env.host_id]
    host.desired = {"version": (host.desired or {}).get("version", 0), "components": [comp]}


def asset_entry(env: Env, data: bytes, ctype: str = "image/svg+xml") -> dict:
    aid = fc.det_id("art_", "logo" + hashlib.sha256(data).hexdigest()[:8])
    env.app.artifacts[aid] = data
    entry = {
        "name": "logo",
        "content_type": ctype,
        "artifact": {
            "id": aid,
            "name": "exp-speedtest-0.1.0-noarch.tar.gz",  # (the schema requires an artifact_name; the manager names logos like this)
            "url": f"/api/agent/v1/artifacts/{aid}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        },
    }
    reference(env, entry)
    return entry


def test_logo_is_installed_root_0644_and_replaced(env):
    a = asset_entry(env, SVG)
    assert assets.sync(env.ctx, [a]) is True
    logo = env.ctx.paths.etc_dir("speedtest") / "assets" / "logo"
    assert logo.read_bytes() == SVG and stat.S_IMODE(os.lstat(logo).st_mode) == 0o644
    env.runner.calls.clear()
    assert assets.sync(env.ctx, [a]) is False  # unchanged: nothing is downloaded again
    png = b"\x89PNG\r\n\x1a\n" + b"x" * 40
    assert assets.sync(env.ctx, [asset_entry(env, png, "image/png")]) is True
    assert logo.read_bytes() == png
    assert assets.sync(env.ctx, []) is True and not logo.exists()  # no longer desired -> removed


@pytest.mark.parametrize(
    "data,ctype",
    [
        (b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", "image/svg+xml"),
        (b"<svg xmlns='http://www.w3.org/2000/svg' onload='x()'></svg>", "image/svg+xml"),
        (
            b"<svg xmlns='http://www.w3.org/2000/svg'><image href='http://evil.example/a.png'/></svg>",
            "image/svg+xml",
        ),
        (b"<svg xmlns='http://www.w3.org/2000/svg'><foreignObject/></svg>", "image/svg+xml"),
        (b"GIF89a....", "image/png"),
        (b"not an image", "image/jpeg"),
    ],
)
def test_bad_logo_is_never_installed(env, data, ctype):
    assert assets.sync(env.ctx, [asset_entry(env, data, ctype)]) is False
    assert not (env.ctx.paths.etc_dir("speedtest") / "assets" / "logo").exists()
    assert any("asset logo skipped" in e["msg"] for e in env.ctx.state.pending_events())


def test_logo_with_a_wrong_hash_is_refused(env):
    a = asset_entry(env, SVG)
    a["artifact"]["sha256"] = "0" * 64
    assert assets.sync(env.ctx, [a]) is False
    assert not (env.ctx.paths.etc_dir("speedtest") / "assets" / "logo").exists()


def test_oversized_logo_is_refused(env):
    a = asset_entry(env, SVG)
    a["artifact"]["size"] = assets.MAX_ASSET_BYTES + 1
    assert assets.sync(env.ctx, [a]) is False


def test_reconcile_installs_the_logo_with_the_speedtest(env):
    env.add_artifact("speedtest", "0.1.0", real_files("speedtest"))
    env.sign_release("0.1.0")
    comp = env.comp("speedtest")
    comp["assets"] = [asset_entry(env, SVG)]
    env.push(env.desired([comp]))
    doc = env.client.get_desired(None)[1]
    assert Reconciler(env.ctx).run(doc).result == "ok"
    assert (env.ctx.paths.etc_dir("speedtest") / "assets" / "logo").read_bytes() == SVG


# ----------------------------------------------------------------------------------------- decommission
def test_decommission_removes_both_components_the_dropin_and_restores_the_range(env):
    env.set_ping("1 0")
    out, _ = converge_all_in_one(env)
    assert out.result == "ok"
    p = env.ctx.paths
    comp = asset_entry(env, SVG)
    assets.sync(env.ctx, [comp])
    env.set_ping(f"{SVC_UID} {SVC_UID}")
    env.runner.calls.clear()
    local_cleanup(env.ctx, dict(env.ctx.state.data["components"]))
    for c in ("runner", "speedtest"):
        assert not os.path.exists(p.comp_opt(c)) and not os.path.exists(p.etc_dir(c))
        assert not os.path.exists(p.unit(f"exp-{c}.service")) and not os.path.lexists(p.bin_link(c))
        assert not os.path.exists(p.state_dir(c))
    assert not os.path.exists(p.sysctl_dropin)
    assert ["sysctl", "-w", "net.ipv4.ping_group_range=1 0"] in env.runner.calls
    assert exp_ids  # (module imported for token helpers used by other tests)


def test_removing_the_speedtest_from_desired_state_reverts_the_dropin(env):
    env.set_ping("1 0")
    converge_all_in_one(env)
    assert os.path.exists(env.ctx.paths.sysctl_dropin)
    rec = env.ctx.state.data["components"]["speedtest"]
    remove_component(env.ctx, "speedtest", rec)
    assert not os.path.exists(env.ctx.paths.sysctl_dropin)
    assert not os.path.exists(env.ctx.paths.comp_opt("speedtest"))
    assert "speedtest" not in env.ctx.state.data["components"]
    assert (env.ctx.paths.comp_opt("runner") / "current").exists()  # the other components are untouched


def test_stray_dropin_is_cleaned_even_without_a_component_record(env):
    env.set_ping("1 0")
    pingsys.ensure(env.ctx, SVC_UID)
    local_cleanup(env.ctx, {})
    assert not os.path.exists(env.ctx.paths.sysctl_dropin)


def test_health_urls_and_tokens_helpers_unused_import_guard():
    assert json.dumps({}) and exp_ids
