"""Install each release tarball into an ubuntu:24.04 systemd container the way the agent would
(unpack to /opt/exp/<c>/<version>, render unit templates by placeholder substitution, daemon-reload) and
assert the end state: `exp-<c> version` prints the version, `selftest` passes, `health --json` emits valid
exp.health/1 JSON, and every unit passes `systemd-analyze verify`.

Marked `harness` (needs Docker with privileged containers). Tarballs come from $EXP_DIST_DIR if set,
otherwise each component is built with `packaging/build.sh --unsigned` into a tmp dir. With
EXP_PACKAGE_STRICT=1 a component that cannot be built is a failure; otherwise it is skipped with the build's
own error (components land in separate work packages, so a partial repo is normal during development).
If systemd containers cannot run here the tests skip with the exact reason.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "packaging" / "build.sh"
SCHEMAS = REPO / "shared" / "schemas"
DOCKERFILE = Path(__file__).resolve().parent / "Dockerfile.systemd"
IMAGE = "exp-pkg-systemd:24.04"
COMPONENTS = ["agent", "probe", "collector", "dashboard", "runner"]
ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine(), "")
STRICT = os.environ.get("EXP_PACKAGE_STRICT") == "1"
APT_ALLOWLIST = {"busybox", "busybox-static", "iproute2", "iputils-ping", "iperf3", "curl", "openssl",
                 "ca-certificates", "ethtool", "iw", "wpasupplicant", "tcpdump"}

pytestmark = pytest.mark.harness


def sh(argv: list[str], timeout: int = 300, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=check)


# ---------------------------------------------------------------- tarballs

@pytest.fixture(scope="session")
def dist(tmp_path_factory) -> Path:
    given = os.environ.get("EXP_DIST_DIR")
    if given:
        d = Path(given)
        assert list(d.glob("exp-*.tar.gz")), "EXP_DIST_DIR=%s has no exp-*.tar.gz" % d
        return d
    return tmp_path_factory.mktemp("dist")


def tarball_for(dist: Path, component: str, tmp: Path) -> Path:
    found = sorted(dist.glob("exp-%s-*.tar.gz" % component))
    found = [p for p in found if p.name.endswith("-noarch.tar.gz") or p.name.endswith("-%s.tar.gz" % ARCH)]
    if found:
        return found[0]
    if os.environ.get("EXP_DIST_DIR"):
        pytest.skip("no tarball for %s (arch %s) in EXP_DIST_DIR" % (component, ARCH or platform.machine()))
    out = dist / component
    r = sh([str(BUILD), "--unsigned", "--components", component, "--out", str(out)])
    got = sorted(out.glob("exp-%s-*.tar.gz" % component))
    got = [p for p in got if p.name.endswith("-noarch.tar.gz") or p.name.endswith("-%s.tar.gz" % ARCH)]
    if r.returncode != 0 or not got:
        msg = "packaging/build.sh --components %s failed (rc=%s): %s" % (component, r.returncode, r.stderr.strip()[-600:])
        if STRICT:
            pytest.fail(msg)
        pytest.skip(msg)
    return got[0]


# ---------------------------------------------------------------- systemd container

def _docker_ok() -> str:
    if not shutil.which("docker"):
        return "docker not installed"
    r = sh(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    return "" if r.returncode == 0 else "docker daemon unavailable: " + (r.stderr.strip()[-200:] or "docker info failed")


@pytest.fixture(scope="session")
def host() -> str:
    """A running systemd container (name). Skips with the exact reason if one cannot run here."""
    why = _docker_ok()
    if why:
        pytest.skip(why)
    if sh(["docker", "image", "inspect", IMAGE], timeout=30).returncode != 0:
        r = sh(["docker", "build", "-q", "-t", IMAGE, "-f", str(DOCKERFILE), str(DOCKERFILE.parent)], timeout=900)
        if r.returncode != 0:
            pytest.skip("cannot build %s: %s" % (IMAGE, r.stderr.strip()[-300:]))
    name = "exp-pkg-%s" % uuid.uuid4().hex[:8]
    r = sh(["docker", "run", "-d", "--name", name, "--hostname", name, "--privileged", "--cgroupns=host",
            "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "--tmpfs", "/run", "--tmpfs", "/run/lock", IMAGE], timeout=120)
    if r.returncode != 0:
        pytest.skip("cannot start a privileged systemd container: " + r.stderr.strip()[-300:])
    try:
        state = ""
        for _ in range(40):
            p = sh(["docker", "exec", name, "systemctl", "is-system-running"], timeout=20)
            state = p.stdout.strip()
            if state in ("running", "degraded"):
                break
            if sh(["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=20).stdout.strip() != "true":
                break
            sh(["sleep", "1"])
        if state not in ("running", "degraded"):
            logs = sh(["docker", "logs", "--tail", "5", name], timeout=20)
            pytest.skip("systemd did not reach running/degraded in the container (state=%r): %s"
                        % (state, (logs.stdout + logs.stderr).strip()[-300:]))
        yield name
    finally:
        sh(["docker", "rm", "-f", name], timeout=120)


def inc(host: str, script: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return sh(["docker", "exec", host, "bash", "-c", script], timeout=timeout)


# ---------------------------------------------------------------- the install, as the agent does it

def apt_requirements(tar: Path, top: str) -> list[str]:
    with tarfile.open(tar) as t:
        f = t.extractfile("%s/requirements.apt" % top)
        lines = f.read().decode().splitlines() if f else []
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def install(host: str, tar: Path, component: str) -> dict:
    m = re.fullmatch(r"exp-%s-(.+?)-(?:noarch|amd64|arm64)\.tar\.gz" % component, tar.name)
    assert m, "unexpected tarball name %s" % tar.name
    version = m.group(1)
    top = "exp-%s-%s" % (component, version)
    pkgs = apt_requirements(tar, top)
    assert set(pkgs) <= APT_ALLOWLIST, "requirements.apt outside the agent allowlist: %s" % sorted(set(pkgs) - APT_ALLOWLIST)
    prefix = "/opt/exp/%s/%s" % (component, version)
    assert sh(["docker", "cp", str(tar), "%s:/tmp/pkg.tar.gz" % host], timeout=60).returncode == 0
    r = inc(host, "set -e; mkdir -p %s && tar -xzf /tmp/pkg.tar.gz -C %s --strip-components=1 --no-same-owner" % (prefix, prefix))
    assert r.returncode == 0, r.stderr
    if pkgs:
        r = inc(host, "DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq --no-install-recommends %s"
                % " ".join(pkgs), timeout=600)
        assert r.returncode == 0, "apt install %s failed: %s" % (pkgs, r.stderr[-400:])
    # Render unit templates by plain placeholder substitution (never interpolating config values).
    subs = {"@VERSION@": version, "@PREFIX@": prefix, "@CONFIG@": "/etc/exp/%s/config.json" % component,
            "@CREDS@": "/etc/exp/%s/creds" % component, "@STATE@": "/var/lib/exp/%s" % component,
            "@RUN@": "/run/exp/%s" % component}
    sed = " ".join("-e 's|%s|%s|g'" % (k, v) for k, v in subs.items())
    r = inc(host, "set -e; for u in %s/systemd/exp-*.service %s/systemd/exp-*.timer; do [ -e \"$u\" ] || continue; "
                  "sed %s \"$u\" > /etc/systemd/system/$(basename \"$u\"); "
                  "chmod 0644 /etc/systemd/system/$(basename \"$u\"); done; "
                  "grep -l '@[A-Z]*@' /etc/systemd/system/exp-* 2>/dev/null && exit 3; "
                  "systemctl daemon-reload" % (prefix, prefix, sed))
    assert r.returncode == 0, "unit render/daemon-reload failed (rc=%s): %s%s" % (r.returncode, r.stdout, r.stderr)
    # Service users named by the units exist on a real host (the agent creates them).
    r = inc(host, "for ug in $(grep -hE '^(User|Group)=' %s/systemd/* 2>/dev/null | cut -d= -f2 | sort -u); do "
                  "getent group $ug >/dev/null || groupadd --system $ug; "
                  "id -u $ug >/dev/null 2>&1 || useradd --system --no-create-home --gid $ug "
                  "-s /usr/sbin/nologin $ug; done" % prefix)
    assert r.returncode == 0, r.stderr
    # 01-contracts.md section 11 host layout: /opt/exp/<c>/current -> the active version, /usr/local/bin/exp-<c> -> current
    r = inc(host, "set -e; ln -sfn %s /opt/exp/%s/current; ln -sfn /opt/exp/%s/current/bin/exp-%s /usr/local/bin/exp-%s"
            % (version, component, component, component, component))
    assert r.returncode == 0, "current/bin links failed: %s" % r.stderr
    if component == "agent":
        # What agent/install/install.sh does besides unpacking: install the version-independent rollback checker
        # that exp-agent-rollback.service runs (06-agent.md section 7), beside the versioned trees.
        r = inc(host, "install -m 0755 -o root -g root -- %s/lib/exp_agent/rollback_check.py /opt/exp/agent/rollback-check"
                % prefix)
        assert r.returncode == 0, "installing the rollback checker failed: %s" % r.stderr
    provision(host, component, prefix)
    return {"version": version, "prefix": prefix, "top": top}


FIXTURE_CONFIGS = {"probe": "probe.json", "collector": "collector.json", "dashboard": "dashboard.json",
                   "runner": "runner.json"}


def provision(host: str, component: str, prefix: str) -> None:
    """What the agent leaves on a host before first start: the validated config, empty credential files
    named by the units, and (collector/dashboard) a self-signed P-256 key+cert under @STATE@/tls. Test
    material is generated in the container; nothing secret is stored in the repo."""
    cfg = FIXTURE_CONFIGS.get(component)
    cdir, state = "/etc/exp/%s" % component, "/var/lib/exp/%s" % component
    r = inc(host, "mkdir -p %s/creds %s/tls && chmod 0755 %s && chmod 0700 %s/creds" % (cdir, state, cdir, cdir))
    assert r.returncode == 0, r.stderr
    if cfg:
        src = REPO / "test" / "fixtures" / "configs" / cfg
        assert sh(["docker", "cp", str(src), "%s:%s/config.json" % (host, cdir)]).returncode == 0
    inc(host, "for c in $(grep -hoE '^LoadCredential=[^:]+' %s/systemd/* 2>/dev/null | cut -d= -f2 | sort -u); do "
              "[ -e %s/creds/$c ] || : > %s/creds/$c; done" % (prefix, cdir, cdir))
    if component in ("collector", "dashboard"):
        r = inc(host, "cd %s/tls && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 "
                      "-keyout key.pem -out cert.pem -subj /CN=%s -addext subjectAltName=IP:127.0.0.1 2>&1 && chmod 0600 key.pem"
                % (state, component))
        assert r.returncode == 0, r.stdout


def run_env(component: str) -> str:
    return "CREDENTIALS_DIRECTORY=/etc/exp/%s/creds" % component


@pytest.fixture(scope="session")
def health_validator():
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    from referencing.jsonschema import DRAFT202012
    reg = referencing.Registry()
    for p in SCHEMAS.glob("*.schema.json"):
        reg = reg.with_resource(p.name, DRAFT202012.create_resource(json.loads(p.read_text())))
    return jsonschema.Draft202012Validator(json.loads((SCHEMAS / "health.schema.json").read_text()), registry=reg)


@pytest.mark.parametrize("component", COMPONENTS)
def test_install_and_run(component, host, dist, tmp_path, health_validator):
    tar = tarball_for(dist, component, tmp_path)
    info = install(host, tar, component)
    exe = "%s/bin/exp-%s" % (info["prefix"], component)

    # layout end state
    r = inc(host, "test -x %s && test -d %s/lib/exp_%s && test -d %s/lib/exp_common/schemas && test -f %s/VERSION"
            % (exe, info["prefix"], component, info["prefix"], info["prefix"]))
    assert r.returncode == 0, "tarball layout wrong"

    # version
    r = inc(host, "%s version" % exe, timeout=30)
    assert r.returncode == 0, r.stderr
    assert info["version"] in r.stdout, "version output %r lacks %s" % (r.stdout, info["version"])

    # selftest
    r = inc(host, "%s %s selftest --config /etc/exp/%s/config.json" % (run_env(component), exe, component), timeout=120)
    assert r.returncode == 0, "selftest failed (rc=%s): %s%s" % (r.returncode, r.stdout[-600:], r.stderr[-600:])

    # health --json: no config/creds on this host, so a non-zero exit is fine; the JSON shape is not optional
    r = inc(host, "%s %s health --json --config /etc/exp/%s/config.json" % (run_env(component), exe, component), timeout=30)
    assert len(r.stdout.encode()) <= 64 * 1024
    try:
        doc = json.loads(r.stdout)
    except ValueError:
        pytest.fail("health --json printed no JSON (rc=%s): stdout=%r stderr=%r" % (r.returncode, r.stdout[:300], r.stderr[:300]))
    errs = sorted(health_validator.iter_errors(doc), key=lambda e: list(e.path))
    assert not errs, "not valid exp.health/1: %s" % "; ".join(e.message for e in errs[:5])
    # health exit convention (01-contracts.md section 8.1, CR-wp1-health-exit): exit 0 for ok AND degraded, 1 only for fail
    assert (r.returncode == 0) == (doc["status"] in ("ok", "degraded")), \
        "exit code %s disagrees with status %s" % (r.returncode, doc["status"])

    # units
    r = inc(host, "ls /etc/systemd/system/exp-* 2>/dev/null")
    assert r.stdout.strip(), "no units were rendered"
    for unit in r.stdout.split():
        v = inc(host, "systemd-analyze verify %s 2>&1" % unit, timeout=60)
        assert v.returncode == 0 and "error" not in v.stdout.lower(), "systemd-analyze verify %s:\n%s" % (unit, v.stdout)


def test_units_never_interpolate_config_and_use_agent_placeholders_only():
    """Static: the templates in every built component use only the documented placeholders."""
    allowed = {"@VERSION@", "@PREFIX@", "@CONFIG@", "@CREDS@", "@STATE@", "@RUN@"}
    seen = 0
    for unit in list(REPO.glob("*/systemd/exp-*.service")) + list(REPO.glob("*/systemd/exp-*.timer")):
        seen += 1
        text = unit.read_text()
        assert set(re.findall(r"@[A-Z_]+@", text)) <= allowed, "%s uses an undocumented placeholder" % unit
    if not seen:
        pytest.skip("no unit templates in the repo yet")


def test_health_validator_rejects_bad_documents(health_validator):
    """Negative control: the schema check in test_install_and_run can fail."""
    bad = [{}, {"schema": "exp.health/1"}, {"schema": "exp.health/2", "status": "ok"},
           {"schema": "exp.health/1", "status": "fine", "version": "1.0.0"}]
    for doc in bad:
        assert list(health_validator.iter_errors(doc)), doc


def test_verify_gate_rejects_a_broken_unit(host):
    """Negative control: systemd-analyze verify really fails on a broken unit."""
    inc(host, "printf '[Service]\\nExecStart=relative/path --x\\nType=bogus\\n' > /etc/systemd/system/exp-broken.service")
    v = inc(host, "systemd-analyze verify /etc/systemd/system/exp-broken.service 2>&1", timeout=60)
    inc(host, "rm -f /etc/systemd/system/exp-broken.service")
    assert v.returncode != 0 or "error" in v.stdout.lower(), v.stdout
