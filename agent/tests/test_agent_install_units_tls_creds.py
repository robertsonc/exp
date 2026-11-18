"""install mechanics, unit rendering, TLS hook, credential files."""

from __future__ import annotations

import os
import stat
import subprocess

import pytest
from agent_helpers import ScriptedRunner

from exp_agent import creds, install, tls, units
from exp_agent.errors import AgentError, PathRefused, Refused
from exp_agent.pathguard import Paths, SafeFS
from exp_agent.runner import Result, Runner, check_argv


@pytest.fixture
def fs(tmp_path):
    root = tmp_path / "root"
    (root / "etc" / "systemd" / "system").mkdir(parents=True)
    f = SafeFS(Paths(root, uid=os.geteuid(), gid=os.getegid()), lambda p, u, g: f.chowns.append((p, u, g)))
    f.chowns = []
    return f


def mode(p) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


# ------------------------------------------------------------------------------------------ runner
def test_runner_argv_rules():
    with pytest.raises(Refused):
        check_argv("ls -l")  # a shell string
    with pytest.raises(Refused):
        check_argv([])
    with pytest.raises(Refused):
        check_argv(["curl", "-H", "Authorization: Bearer expa_" + "A" * 43])
    with pytest.raises(Refused):
        check_argv(["x", "expi_" + "B" * 20])
    with pytest.raises(Refused):
        check_argv(["x", "a\x00b"])
    r = Runner().run(["sh", "-c", "echo $0; exit 3", "a b; c"], timeout=5)  # metacharacters stay literal
    assert r.rc == 3 and r.stdout.strip() == "a b; c"
    assert Runner().run(["sleep", "5"], timeout=0.2).timed_out
    assert Runner().run(["definitely-not-a-command"], timeout=2).rc == 127


# ------------------------------------------------------------------------------------------ apt
def test_apt_allowlist():
    assert install.check_requirements(["curl", "iperf3"]) == ["curl", "iperf3"]
    for bad in (
        ["nmap"],
        ["curl", "netcat"],
        ["curl=1.0"],
        ["-oFoo=bar"],
        ["curl;rm"],
        ["CURL"],
        ["busybox", "../x"],
    ):
        with pytest.raises(Refused, match="allowlist"):
            install.check_requirements(bad)


def test_requirements_parsing(tmp_path):
    (tmp_path / "requirements.apt").write_text("# comment\nbusybox\n\n  iproute2  # trailing\nbusybox\n")
    assert install.read_requirements(tmp_path) == ["busybox", "iproute2"]
    assert install.read_requirements(tmp_path / "none") == []
    (tmp_path / "big").mkdir()
    (tmp_path / "big" / "requirements.apt").write_text("x" * 20000)
    with pytest.raises(Refused):
        install.read_requirements(tmp_path / "big")


def test_apt_install_only_missing_and_noninteractive():
    r = ScriptedRunner()
    r.installed_pkgs.add("curl")
    assert install.apt_install(r, ["curl", "iperf3"]) == ["iperf3"]
    assert r.argvs("apt-get") == [["apt-get", "install", "-y", "--no-install-recommends", "iperf3"]]
    assert install.apt_install(r, ["curl", "iperf3"]) == []
    r.fail[("apt-get",)] = Result(100, "", "E: unable to locate")
    with pytest.raises(AgentError):
        install.apt_install(r, ["tcpdump"])


def test_service_users_created_once():
    r = ScriptedRunner()
    assert install.ensure_users(r, "collector", lambda n: n in r.users) == ["exp-collector", "exp-vm"]
    assert install.ensure_users(r, "collector", lambda n: n in r.users) == []
    assert install.ensure_users(r, "probe", lambda n: n in r.users) == []
    assert [c[-1] for c in r.argvs("useradd")] == ["exp-collector", "exp-vm"]
    assert all(
        c[:5] == ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin"]
        for c in r.argvs("useradd")
    )


def test_commit_flip_and_prune(fs):
    base = fs.paths.comp_opt("probe")
    for v in ("0.1.0", "0.2.0", "0.3.0"):
        st = fs.mkdir(base / f".staging-{v}")
        (st / "bin").mkdir()
        (st / "bin" / "exp-probe").write_text("x")
        install.commit_staging(fs, st, fs.paths.version_dir("probe", v))
    assert sorted(os.listdir(base)) == ["0.1.0", "0.2.0", "0.3.0"]
    install.flip_current(fs, "probe", "0.2.0")
    assert (
        os.readlink(fs.paths.current("probe")) == "0.2.0" and install.current_version(fs, "probe") == "0.2.0"
    )
    link = fs.paths.bin_link("probe")
    assert os.path.realpath(link) == os.path.realpath(base / "0.2.0" / "bin" / "exp-probe")
    install.flip_current(fs, "probe", "0.3.0")
    assert os.path.realpath(link) == os.path.realpath(base / "0.3.0" / "bin" / "exp-probe")
    assert install.prune_versions(fs, "probe", {"0.3.0", "0.2.0"}) == ["0.1.0"]
    with pytest.raises(Refused):
        install.flip_current(fs, "probe", "9.9.9")


# ------------------------------------------------------------------------------------------ units
def test_render_only_the_six_placeholders(fs):
    vals = units.placeholder_values(fs.paths, "probe", "0.1.0")
    assert vals == {
        "@VERSION@": "0.1.0",
        "@PREFIX@": "/opt/exp/probe/0.1.0",
        "@CONFIG@": "/etc/exp/probe/config.json",
        "@CREDS@": "/etc/exp/probe/creds",
        "@STATE@": "/var/lib/exp/probe",
        "@RUN@": "/run/exp/probe",
    }
    text = "\n".join(f"X={k}" for k in vals)
    out = units.render("exp-probe.service", text, vals)
    assert "@" not in out and "X=/opt/exp/probe/0.1.0" in out
    for evil in ("@HOME@", "@USER@", "@CONFIG_X@"):
        with pytest.raises(Refused, match="unknown placeholder"):
            units.render("exp-probe.service", f"A={evil}", vals)
    assert units.render("exp-probe-lease@.service", "ExecStart=x %i", vals).endswith(
        "%i"
    )  # systemd specifiers pass
    with pytest.raises(PathRefused):
        units.placeholder_values(fs.paths, "../x", "0.1.0")


def test_template_loading_refuses_foreign_names_and_non_files(tmp_path):
    d = tmp_path / "systemd"
    d.mkdir()
    (d / "exp-ok.service").write_text("[Service]\n")
    (d / "exp-probe-lease@.service").write_text("[Service]\n")
    assert sorted(units.load_templates(tmp_path)) == ["exp-ok.service", "exp-probe-lease@.service"]
    for bad in ("evil.service", "exp-x.sh", "exp-.service", "EXP-x.service", "exp-x.service.d"):
        (d / bad).write_text("x") if "." in bad and not bad.endswith(".d") else (d / bad).mkdir()
        with pytest.raises(Refused):
            units.load_templates(tmp_path)
        (d / bad).unlink() if (d / bad).is_file() else (d / bad).rmdir()
    os.symlink("/etc/passwd", d / "exp-link.service")
    with pytest.raises(Refused):
        units.load_templates(tmp_path)


def test_credential_references_must_stay_in_the_component_creds_dir():
    info = units.inspect(
        "exp-a.service", "[Service]\nLoadCredential=tok:/etc/exp/probe/creds/ingest_token\n[Install]\n"
    )
    assert units.referenced_credential_files(info, "/etc/exp/probe/creds") == ["ingest_token"]
    assert info.has_install
    for path in (
        "/etc/exp/other/creds/x",
        "/etc/passwd",
        "/etc/exp/probe/creds/../../x",
        "/etc/exp/probe/creds/sub/x",
    ):
        i = units.inspect("exp-a.service", f"LoadCredential=t:{path}\n")
        with pytest.raises(Refused):
            units.referenced_credential_files(i, "/etc/exp/probe/creds")
    with pytest.raises(Refused):
        units.inspect("exp-a.service", "LoadCredential=broken\n")


def test_instances_only_for_known_roles_and_slug_ids():
    cfg = {
        "ports": [
            {"id": "c01", "role": "client"},
            {"id": "s01", "role": "target"},
            {"id": "w01", "role": "wifi"},
        ]
    }
    have = {"exp-probe-lease@.service", "exp-probe-target@.service"}
    assert units.instance_units("probe", cfg, have) == [
        "exp-probe-lease@c01.service",
        "exp-probe-target@s01.service",
    ]
    assert units.instance_units("probe", cfg, {"exp-probe-lease@.service"}) == ["exp-probe-lease@c01.service"]
    assert units.instance_units("collector", cfg, have) == []
    with pytest.raises(Refused):
        units.instance_units("probe", {"ports": [{"id": "../x", "role": "client"}]}, have)


def test_systemctl_wrapper_validates_unit_names():
    r = ScriptedRunner()
    sc = units.Systemctl(r)
    sc.restart(["exp-probe.service"])
    with pytest.raises(Refused):
        sc.restart(["exp-bad;rm -rf.service"])
    assert r.calls == [["systemctl", "restart", "exp-probe.service"]]
    r.fail[("systemctl", "enable")] = Result(1, "", "nope")
    with pytest.raises(AgentError):
        sc.enable(["exp-probe.service"])


def test_unit_files_written_only_under_systemd_dir_with_exp_names(fs):
    ch, rm = units.write_units(fs, {"exp-a.service": "[Service]\n"}, set())
    assert ch == ["exp-a.service"] and rm == []
    assert mode(fs.paths.unit("exp-a.service")) == 0o644
    assert units.write_units(fs, {"exp-a.service": "[Service]\n"}, {"exp-a.service"}) == ([], [])
    ch, rm = units.write_units(fs, {"exp-b.service": "x"}, {"exp-a.service"})
    assert rm == ["exp-a.service"] and not fs.paths.unit("exp-a.service").exists()
    with pytest.raises(PathRefused):
        units.write_units(fs, {"evil.service": "x"}, set())


# ------------------------------------------------------------------------------------------ creds
def test_creds_files_0600_dir_0700_and_prune(fs):
    assert creds.sync(fs, "dashboard", {"a": "1", "b.json": "{}"}, {"ref"}) is True
    d = fs.paths.creds_dir("dashboard")
    assert mode(d) == 0o700 and sorted(os.listdir(d)) == ["a", "b.json", "ref"]
    assert all(mode(d / n) == 0o600 for n in os.listdir(d)) and (d / "ref").read_bytes() == b""
    assert creds.sync(fs, "dashboard", {"a": "1", "b.json": "{}"}, {"ref"}) is False
    os.chmod(d / "a", 0o644)  # drift is repaired
    creds.sync(fs, "dashboard", {"a": "1", "b.json": "{}"}, {"ref"})
    assert mode(d / "a") == 0o600
    assert creds.sync(fs, "dashboard", {"a": "2"}, set()) is True
    assert os.listdir(d) == ["a"]


@pytest.mark.parametrize("name", ["../x", "a/b", ".hidden", "", "x" * 80, "a b", "/etc/passwd", "a\x00"])
def test_bad_credential_names_refused(fs, name):
    with pytest.raises(Refused):
        creds.sync(fs, "dashboard", {name: "v"}, set())
    with pytest.raises(Refused):
        creds.sync(fs, "dashboard", {}, {name})


def test_creds_dir_symlink_is_not_followed(fs, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    fs.mkdir(fs.paths.etc_dir("dashboard"))
    os.symlink(outside, fs.paths.creds_dir("dashboard"))
    with pytest.raises((PathRefused, OSError)):
        creds.sync(fs, "dashboard", {"a": "secret"}, set())
    assert os.listdir(outside) == []


# ------------------------------------------------------------------------------------------ TLS
def lookup(name):
    return (4242, 4242)


def test_tls_generated_with_san_cn_key_owner_and_never_regenerated(fs):
    r = ScriptedRunner()
    cfg = {"collector_id": "col-hallb", "listen": "10.32.98.25:8443"}
    assert tls.ensure_tls(fs, r, "collector", cfg, lookup) is True
    d = fs.paths.state_dir("collector") / "tls"
    key, cert = d / "key.pem", d / "cert.pem"
    assert mode(key) == 0o600 and mode(cert) == 0o644 and mode(d) == 0o755
    assert [c for c in fs.chowns if c[0].endswith("key.pem")][0][1:] == (4242, 4242)
    text = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-text"], capture_output=True, text=True, check=True
    ).stdout
    assert "CN = col-hallb" in text and "IP Address:10.32.98.25" in text and "prime256v1" in text
    assert os.listdir(fs.paths.state_dir("collector")) == ["tls"]  # private temp dir removed
    before = (cert.read_bytes(), key.read_bytes(), os.stat(cert).st_mtime_ns)
    assert tls.tls_is_valid(fs, r, "collector", cfg)
    assert tls.ensure_tls(fs, r, "collector", cfg, lookup) is False
    assert (cert.read_bytes(), key.read_bytes(), os.stat(cert).st_mtime_ns) == before
    # a mismatching pair is not valid and is replaced; a missing cert too
    key.write_bytes(
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
            capture_output=True,
            check=True,
        ).stdout
    )
    assert not tls.tls_is_valid(fs, r, "collector", cfg)
    assert tls.ensure_tls(fs, r, "collector", cfg, lookup) is True
    assert tls.tls_is_valid(fs, r, "collector", cfg)


def test_tls_dashboard_san_from_url_and_provided_mode_skipped(fs):
    r = ScriptedRunner()
    cfg = {
        "dashboard_id": "dash-main",
        "url": "https://10.32.98.30",
        "listen": {"https": "0.0.0.0:443"},
        "tls": {"mode": "self_signed"},
    }
    assert tls.san_for("dashboard", cfg) == ["IP:10.32.98.30"]
    assert tls.ensure_tls(fs, r, "dashboard", cfg, lookup) is True
    cfg2 = {**cfg, "tls": {"mode": "provided"}}
    assert tls.ensure_tls(fs, r, "probe", {}, lookup) is False
    assert tls.wants_tls("dashboard", cfg2) is False and tls.wants_tls("runner", {}) is False


def test_tls_refuses_a_service_writable_tls_dir_and_symlinks(fs, tmp_path):
    r = ScriptedRunner()
    cfg = {"collector_id": "col-a", "listen": "10.0.0.1:8443"}
    d = fs.mkdir(fs.paths.state_dir("collector") / "tls", 0o755)
    os.chmod(d, 0o777)  # a service could plant symlinks here
    with pytest.raises(Refused, match="not writable"):
        tls.ensure_tls(fs, r, "collector", cfg, lookup)
    os.chmod(d, 0o755)
    outside = tmp_path / "outside.pem"
    outside.write_text("x")
    os.symlink(outside, d / "key.pem")
    os.symlink(outside, d / "cert.pem")
    assert not tls.tls_is_valid(fs, r, "collector", cfg)
    with pytest.raises(PathRefused):  # the symlink target is outside the allowed roots
        tls.ensure_tls(fs, r, "collector", cfg, lookup)
    assert outside.read_text() == "x"


def test_tls_needs_the_service_user_and_a_usable_address(fs):
    r = ScriptedRunner()
    with pytest.raises(AgentError, match="does not exist"):
        tls.ensure_tls(fs, r, "collector", {"collector_id": "c", "listen": "10.0.0.1:8443"}, lambda n: None)
    with pytest.raises(Refused):
        tls.san_for("collector", {"listen": "0.0.0.0:8443"})
