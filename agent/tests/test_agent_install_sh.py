"""install.sh without a container: static properties and the embedded Python helper (the parts that parse
remote data or unpack the agent artifact run unprivileged against tmp dirs)."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "install" / "install.sh"
TEXT = SCRIPT.read_text("utf-8")
HELPER = re.search(r"<<'PYEOF' \|\| true\n(.*?)\nPYEOF\n", TEXT, re.S).group(1)
SERVED = (
    TEXT.replace("@@MANAGER_URL@@", "https://exp.example.com")
    .replace("@@AGENT_VERSION@@", "0.1.0")
    .replace(
        "@@RELEASE_PUBKEY_PEM@@",
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----",
    )
)
TOKEN = "expe_" + "A" * 43


def bash(
    script: Path | str, *args: str, text: str | None = None, tmp: Path | None = None
) -> subprocess.CompletedProcess[str]:
    path = script
    if text is not None:
        assert tmp is not None
        path = tmp / "s.sh"
        path.write_text(text)
    return subprocess.run(  # noqa: S603
        ["bash", str(path), *args],
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
        check=False,  # noqa: S607
    )


def helper(*argv: str, stdin: str = "", cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["python3", "-I", "-c", HELPER, *argv],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=cwd,
        check=False,  # noqa: S607
    )


def test_script_parses_and_has_the_contracted_shape():
    assert subprocess.run(["bash", "-n", str(SCRIPT)], check=False).returncode == 0  # noqa: S603,S607
    assert TEXT.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in TEXT
    assert os.access(SCRIPT, os.X_OK)
    for ph in ("@@MANAGER_URL@@", "@@AGENT_VERSION@@", "@@RELEASE_PUBKEY_PEM@@"):
        assert TEXT.count(ph) == 1, f"{ph} must occur exactly once (the manager substitutes every occurrence)"
    # the helper compiles under the oldest supported python
    compile(HELPER, "install.sh-helper", "exec")


OS_GATE = re.search(r"\n( +local supported=.*?\n +esac\n)", TEXT, re.S).group(1)


@pytest.mark.parametrize(
    "os_id,version,ok",
    [
        ("ubuntu", "22.04", True),
        ("ubuntu", "24.04", True),
        ("debian", "12", True),  # Debian 12 and 64-bit Raspberry Pi OS bookworm (which reports ID=debian)
        ("ubuntu", "20.04", False),
        ("debian", "11", False),
        ("debian", "13", False),
        ("raspbian", "12", False),  # 32-bit Raspberry Pi OS (armv7l)
        ("", "", False),
    ],
)
def test_preflight_os_gate_accepts_exactly_the_supported_set(tmp_path, os_id, version, ok):
    osr = tmp_path / "os-release"
    osr.write_text(f'NAME="x"\nID={os_id}\nVERSION_ID="{version}"\n')
    gate = OS_GATE.replace("/etc/os-release", str(osr))
    script = f"die() {{ printf '%s\\n' \"$*\" >&2; exit 1; }}\ngate() {{\n{gate}}}\ngate && echo PASSED\n"
    r = bash(tmp_path / "gate.sh", text=script, tmp=tmp_path)
    if ok:
        assert r.returncode == 0 and "PASSED" in r.stdout, r
    else:
        assert r.returncode != 0, r
        assert f"unsupported OS '{os_id} {version}'" in r.stderr, r
        assert "Ubuntu 22.04/24.04 or Debian 12 (incl. Raspberry Pi OS 64-bit)" in r.stderr, r


def test_every_curl_is_https_only_and_bounded_and_secrets_stay_out_of_argv():
    assert "--proto =https" in TEXT and "--max-time" in TEXT and "--fail" in TEXT
    curls = [ln for ln in TEXT.splitlines() if re.search(r"\bcurl\b", ln) and not ln.lstrip().startswith("#")]
    for ln in curls:
        assert (
            "CURL_COMMON" in ln
            or "--proto =https" in ln
            or "command -v" in ln
            or "curl openssl" in ln
            or "installing" in ln
            or "usage" in ln.lower()
            or "Behind a proxy" in ln
            or "curl -fsSL" in ln
        ), ln
    # the token and the secret reach curl only through pipes: --data @- and -K -
    assert "--data @-" in TEXT and "-K -" in TEXT
    assert not re.search(r"curl[^\n]*(\$token|\$\{token|\$secret|Bearer \$)", TEXT)
    assert "set +x" in TEXT


@pytest.mark.parametrize(
    "bad",
    [
        "-----BEGIN",
        "@@MANAGER_URL@@",
    ],
)
def test_unsubstituted_script_refuses_before_anything_else(tmp_path, bad):
    r = bash(SCRIPT, TOKEN)
    assert r.returncode == 1 and "unsubstituted placeholders" in r.stderr
    half = SERVED.replace("https://exp.example.com", "@@MANAGER_URL@@") if bad == "@@MANAGER_URL@@" else TEXT
    r = bash("", TOKEN, text=half, tmp=tmp_path)
    assert r.returncode == 1 and "unsubstituted placeholders" in r.stderr


@pytest.mark.parametrize(
    "field,value,msg",
    [
        ("https://exp.example.com", "http://exp.example.com", "plain https://host"),
        ("https://exp.example.com", "https://exp.example.com/path", "plain https://host"),
        ("https://exp.example.com", "https://u:p@exp.example.com", "plain https://host"),
        ("0.1.0", "0.1", "version number"),
        ("0.1.0", "0.1.0$(id)", "version number"),
    ],
)
def test_substituted_values_are_validated(tmp_path, field, value, msg):
    text = SERVED.replace(field, value, 1)
    r = bash("", TOKEN, text=text, tmp=tmp_path)
    assert r.returncode == 1 and msg in r.stderr, r.stderr


def test_a_bad_pubkey_is_refused(tmp_path):
    text = SERVED.replace(
        "MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "$(touch /tmp/pwned)"
    )
    r = bash("", TOKEN, text=text, tmp=tmp_path)
    assert r.returncode == 1 and "unexpected characters" in r.stderr
    assert not Path("/tmp/pwned").exists()


def test_malformed_token_is_refused_before_preflight(tmp_path):
    for tok in ("nope", "expe_short", TOKEN + "x", "expa_" + "A" * 43):
        r = bash("", tok, text=SERVED, tmp=tmp_path)
        assert r.returncode == 1 and "does not look like an enrol token" in r.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="the non-root refusal cannot be shown as root")
def test_non_root_is_refused_with_the_documented_usage(tmp_path):
    r = bash("", TOKEN, text=SERVED, tmp=tmp_path)
    assert r.returncode == 1 and "must run as root" in r.stderr and "sudo bash -s --" in r.stderr
    assert TOKEN not in r.stdout + r.stderr


# ----------------------------------------------------------------------------- helper: unpack
def tarball(tmp: Path, members, top="exp-agent-0.1.0", complete=True) -> Path:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tf:
        base = (
            {
                "VERSION": b"0.1.0\n",
                "bin/exp-agent": (b"#!/usr/bin/python3\n", 0o755),
                "lib/exp_agent/__init__.py": b"",
                "lib/exp_agent/rollback_check.py": b"#!/usr/bin/python3\n",
                "systemd/exp-agent.service": b"[Service]\n",
            }
            if complete
            else {}
        )
        for rel, spec in base.items():
            data, mode = spec if isinstance(spec, tuple) else (spec, 0o644)
            ti = tarfile.TarInfo(f"{top}/{rel}")
            ti.size, ti.mode = len(data), mode
            tf.addfile(ti, io.BytesIO(data))
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    p = tmp / "a.tar.gz"
    p.write_bytes(buf.getvalue())
    return p


def member(name, data=b"x", mode=0o644, type_=tarfile.REGTYPE, link=""):
    ti = tarfile.TarInfo(name)
    ti.type, ti.mode, ti.linkname = type_, mode, link
    ti.size = len(data) if type_ == tarfile.REGTYPE else 0
    return ti, data if type_ == tarfile.REGTYPE else None


def unpack(tmp: Path, tb: Path):
    parent = tmp / "agent"
    parent.mkdir(exist_ok=True)
    return helper("unpack", str(tb), str(parent), "exp-agent-0.1.0", "0.1.0"), parent


def test_unpack_accepts_a_clean_artifact_and_normalises_modes(tmp_path):
    r, parent = unpack(
        tmp_path, tarball(tmp_path, [member("exp-agent-0.1.0/lib/exp_agent/x.py", b"1", 0o666)])
    )
    assert r.returncode == 0, r.stderr
    stage = Path(r.stdout.strip())
    assert stage.parent == parent and stage.name.startswith(".staging-")
    assert (stage / "bin/exp-agent").stat().st_mode & 0o777 == 0o755
    assert (stage / "lib/exp_agent/x.py").stat().st_mode & 0o777 == 0o644  # group/other write is dropped
    assert (stage / "VERSION").read_text() == "0.1.0\n"


@pytest.mark.parametrize(
    "name,kw,msg",
    [
        ("exp-agent-0.1.0/../../evil", {}, "unsafe path"),
        ("/etc/evil", {}, "unsafe path"),
        ("other-top/x", {}, "unsafe path"),
        ("exp-agent-0.1.0/a\\b", {}, "unsafe path"),
        ("exp-agent-0.1.0/lib/l", {"type_": tarfile.SYMTYPE, "link": "/etc"}, "link or special"),
        (
            "exp-agent-0.1.0/lib/h",
            {"type_": tarfile.LNKTYPE, "link": "exp-agent-0.1.0/VERSION"},
            "link or special",
        ),
        ("exp-agent-0.1.0/lib/fifo", {"type_": tarfile.FIFOTYPE}, "link or special"),
        ("exp-agent-0.1.0/lib/dev", {"type_": tarfile.CHRTYPE}, "link or special"),
        ("exp-agent-0.1.0/bin/suid", {"mode": 0o4755}, "setuid"),
        ("exp-agent-0.1.0/bin/sgid", {"mode": 0o2755}, "setuid"),
        ("exp-agent-0.1.0/VERSION", {}, "duplicate"),
    ],
)
def test_unpack_refuses_unsafe_members_and_leaves_no_staging_dir(tmp_path, name, kw, msg):
    r, parent = unpack(tmp_path, tarball(tmp_path, [member(name, **kw)]))
    assert r.returncode == 1 and msg in r.stderr, r.stderr
    assert list(parent.iterdir()) == []
    assert not (tmp_path / "evil").exists() and not Path("/etc/evil").exists()


def test_unpack_refuses_an_incomplete_or_mislabelled_artifact(tmp_path):
    r, parent = unpack(tmp_path, tarball(tmp_path, [], complete=False))
    assert r.returncode == 1 and "has no" in r.stderr and list(parent.iterdir()) == []
    tb = tarball(tmp_path, [])
    parent = tmp_path / "agent2"
    parent.mkdir()
    r = helper("unpack", str(tb), str(parent), "exp-agent-0.1.0", "0.2.0")
    assert r.returncode == 1 and "VERSION is not 0.2.0" in r.stderr and list(parent.iterdir()) == []


# ----------------------------------------------------------------------------- helper: parsing
def desired(**over):
    d = {
        "schema": "exp.desired/1",
        "host_id": "h_" + "0" * 26,
        "version": 1,
        "decommission": False,
        "site": {"id": "hall-b", "name": "Hall B"},
        "agent": {"version": "0.1.0", "artifact": "art_" + "0" * 26},
        "release": {
            "version": "0.1.0",
            "manifest_url": "/api/agent/v1/releases/0.1.0/manifest",
            "signature_url": "/api/agent/v1/releases/0.1.0/manifest.sig",
        },
    }
    d.update(over)
    return d


def test_desired_parsing(tmp_path):
    f = tmp_path / "d.json"
    f.write_text(json.dumps(desired()))
    r = helper("desired", str(f))
    assert r.returncode == 0 and r.stdout.strip().split("\t")[:3] == ["0.1.0", "art_" + "0" * 26, "0.1.0"]
    bad = [
        desired(decommission=True),
        desired(agent={"version": "0.1.0", "artifact": "art_../../x"}),
        desired(agent={"version": "x", "artifact": "art_" + "0" * 26}),
        desired(release={"version": "0.1.0", "manifest_url": "https://evil.example/m", "signature_url": ""}),
        desired(schema="nope"),
    ]
    for doc in bad:
        f.write_text(json.dumps(doc))
        assert helper("desired", str(f)).returncode == 1


def test_a_site_without_a_release_is_named_with_the_repair_command(tmp_path):
    """CR-wp6 follow-up: an enrolled host whose site has no release gets the manager's bare desired document. Say
    so, name the site, and give the no-token command that finishes the install once a release is set."""
    bare = {k: v for k, v in desired().items() if k not in ("agent", "release")}
    f = tmp_path / "d.json"
    f.write_text(json.dumps(bare))
    r = helper("desired", str(f), "https://manager.example.test")
    assert r.returncode == 1
    assert "site 'Hall B' has no release set in the manager yet" in r.stderr
    assert "curl -fsSL https://manager.example.test/install.sh | sudo bash" in r.stderr
    assert "missing the agent or release section" not in r.stderr
    # a document with only one of the two sections is still malformed, not "no release yet"
    f.write_text(json.dumps({k: v for k, v in desired().items() if k != "release"}))
    r = helper("desired", str(f), "https://manager.example.test")
    assert r.returncode == 1 and "missing the agent or release section" in r.stderr


def test_a_failing_desired_check_is_reported_once():
    """The helper prints its own reason; the script must stop there instead of adding "not usable" after it."""
    text = SCRIPT.read_text()
    assert 'desired_tsv="$(py desired "$TMP/desired.json" "$MANAGER_URL")" || exit 1' in text
    assert '<<<"$(py desired' not in text


def manifest(tmp_path, **over):
    m = {
        "schema": "exp.manifest/1",
        "version": "0.1.0",
        "min_agent_version": "0.1.0",
        "artifacts": [
            {
                "name": "exp-agent-0.1.0-noarch.tar.gz",
                "component": "agent",
                "arch": "noarch",
                "sha256": hashlib.sha256(b"x").hexdigest(),
                "size": 10,
            }
        ],
    }
    m.update(over)
    f = tmp_path / "m.json"
    f.write_text(json.dumps(m))
    return f


def test_manifest_entry_rules(tmp_path):
    r = helper("manifest-entry", str(manifest(tmp_path)), "0.1.0", "0.1.0", "amd64")
    assert r.returncode == 0 and r.stdout.split("\t")[0] == "exp-agent-0.1.0-noarch.tar.gz"
    # never below min_agent_version
    r = helper(
        "manifest-entry", str(manifest(tmp_path, min_agent_version="0.2.0")), "0.1.0", "0.1.0", "amd64"
    )
    assert r.returncode == 1 and "min_agent_version" in r.stderr
    r = helper("manifest-entry", str(manifest(tmp_path)), "0.1.0", "0.1.1", "amd64")  # not in the manifest
    assert r.returncode == 1 and "not in the signed manifest" in r.stderr
    r = helper("manifest-entry", str(manifest(tmp_path, version="0.9.9")), "0.1.0", "0.1.0", "amd64")
    assert r.returncode == 1
    bad = manifest(tmp_path)
    doc = json.loads(bad.read_text())
    doc["artifacts"][0]["sha256"] = "zz"
    bad.write_text(json.dumps(doc))
    assert helper("manifest-entry", str(bad), "0.1.0", "0.1.0", "amd64").returncode == 1


def test_enrol_body_carries_the_token_only_in_the_body_and_validates_it():
    r = helper("facts", "amd64", stdin=TOKEN)
    assert r.returncode == 0
    body = json.loads(r.stdout)
    assert body["token"] == TOKEN and body["facts"]["arch"] == "amd64" and body["facts"]["hostname"]
    assert helper("facts", "amd64", stdin="expe_nope").returncode == 1
