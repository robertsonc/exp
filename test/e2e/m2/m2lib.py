"""Helpers shared by the M2 lifecycle tests (A2.5 - A2.8): extra releases, a tiny HTTPS agent-API client, host setup."""

from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "test" / "harness"))
sys.path.insert(0, str(REPO / "shared" / "python"))

from expharness import dockerhost  # noqa: E402
from expharness.manager import clean_env  # noqa: E402

# what packaging/build.sh needs from a source tree (the runner has no code yet)
TREE_DIRS = ("agent", "probe", "collector", "dashboard", "runner", "shared")
BROKEN_HEALTH = (
    "import json as _j, sys as _s\n"
    'if len(_s.argv) > 1 and _s.argv[1] == "health":\n'
    "    print(_j.dumps({'schema': 'exp.health/1', 'status': 'fail', 'detail': 'deliberately broken release',\n"
    "                    'version': '%(v)s', 'uptime_s': 0, 'metrics': {}, 'facts': {}}))\n"
    "    _s.exit(1)\n"
)


def copy_tree(dst: Path) -> Path:
    """A throwaway copy of the product tree (the repo itself, VERSION included, is never touched)."""
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "node_modules", ".venv", ".git", "tests", "test")
    for d in TREE_DIRS:
        shutil.copytree(REPO / d, dst / d, ignore=ignore, symlinks=True)
    for f in ("VERSION", "LICENSE"):
        if (REPO / f).is_file():
            shutil.copy(REPO / f, dst / f)
    return dst


def break_health(tree: Path, component: str, version: str) -> None:
    """Patch `exp-<component> health` of a tree copy so that it always answers status=fail, exit 1."""
    entry = tree / component / "bin" / f"exp-{component}"
    text = entry.read_text()
    marker = "from exp_%s.cli import main" % component
    assert marker in text, f"unexpected entry point of {component}"
    entry.write_text(text.replace(marker, (BROKEN_HEALTH % {"v": version}) + marker, 1))


def build_release(
    out: Path,
    version: str,
    *,
    key: Path | None,
    pub: Path | None,
    tree: Path | None = None,
    unsigned: bool = False,
    timeout: float = 600,
) -> Path:
    """packaging/build.sh --release <version> (signed with the throwaway key) or an unsigned dev build."""
    argv = [str(REPO / "packaging" / "build.sh")]
    argv += ["--version", version, "--unsigned"] if unsigned else ["--release", version]
    argv += ["--out", str(out)]
    if tree is not None:
        argv += ["--repo", str(tree)]
    env = clean_env(SOURCE_DATE_EPOCH=os.environ.get("SOURCE_DATE_EPOCH", "1767225600"))
    if key is not None and pub is not None:
        env.update(EXP_RELEASE_KEY=str(key), EXP_RELEASE_PUBKEY=str(pub))
    r = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout, check=False, cwd=REPO)  # noqa: S603
    assert r.returncode == 0, f"build.sh {version} failed: {(r.stdout + r.stderr)[-800:]}"
    return out


# ---- the agent API as a (hostile or buggy) client would call it ---------------------------------
def _ctx(ca_pem: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=ca_pem)
    return ctx


def agent_call(stack, method: str, path: str, secret: str | None, body: bytes | None = None) -> tuple[int, bytes]:
    """One request to /api/agent/v1 with an explicit bearer secret. Returns (status, body)."""
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(  # noqa: S310
        stack.mgr.url + "/api/agent/v1" + path, data=body, method=method, headers=headers
    )
    ctx = _ctx(stack.ca_pem)
    # the manager name only resolves through /etc/hosts entries the fixture added; no proxy
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=30) as r:  # noqa: S310
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def agent_secret(host: dockerhost.Host) -> str:
    return json.loads(host.read("/etc/exp/agent.json"))["agent_secret"]


def set_site(stack, site: str, name: str = "") -> None:
    stack.admin.post("/sites", {"site": site, "name": name or site, "timezone": "UTC"}, ok=(201,))


def host_row(stack, host_id: str) -> dict[str, Any]:
    return stack.admin.get(f"/hosts/{host_id}")


def status_report(stack, host_id: str) -> dict[str, Any] | None:
    r = stack.admin.call("GET", f"/hosts/{host_id}/status")
    return r.json()["report"] if r.status == 200 else None


def unit_enter_ts(host: dockerhost.Host, unit: str) -> str:
    return host.run(f"systemctl show {unit} -p ActiveEnterTimestampMonotonic --value").out.strip()


def now_iso(offset_s: float = 0.0) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + offset_s))


# ---- hosts ---------------------------------------------------------------------------------------
def create_host(
    stack, site: str, name: str, comps: dict[str, tuple[str, dict[str, Any]]]
) -> tuple[str, dict[str, Any], dict[str, str]]:
    """The wizard's calls: a host with the given shapes, one component per shape. Returns (host_id, enrol, component_ids)."""
    created = stack.admin.post("/hosts", {"name": name, "site": site, "shapes": list(comps)}, ok=(201,))
    host_id = created["host"]["host_id"]
    cids = {}
    for typ, (cid, cfg) in comps.items():
        r = stack.admin.post(f"/hosts/{host_id}/components", {"type": typ, "id": cid, "config": cfg}, ok=(201,))
        cids[typ] = r["component_id"]
    return host_id, created["enrol"], cids


def components_ok(stack, host_id: str, types: tuple[str, ...]) -> dict[str, Any] | None:
    rep = status_report(stack, host_id)
    if not rep:
        return None
    by = {c["type"]: c for c in rep["components"]}
    return rep if all(t in by and by[t]["health"] == "ok" for t in types) else None


def comp_row(stack, host_id: str, typ: str) -> dict[str, Any]:
    items = stack.admin.get(f"/hosts/{host_id}/components")["items"]
    return next(c for c in items if c["type"] == typ)


def wait_for(fn, timeout: float, interval: float, what: str, host: dockerhost.Host | None = None) -> Any:
    return dockerhost.wait_for(fn, timeout, interval, what, host.diagnostics if host else None)


# ---- multipart uploads (POST /releases/upload) ---------------------------------------------------------
def multipart(parts: list[tuple[str, str, bytes]]) -> tuple[str, bytes]:
    boundary = "----expe2e" + os.urandom(8).hex()
    out = b""
    for name, filename, data in parts:
        out += (
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + data
            + b"\r\n"
        )
    out += f"--{boundary}--\r\n".encode()
    return f"multipart/form-data; boundary={boundary}", out


def upload_release(
    stack,
    dist: Path,
    version: str,
    *,
    manifest: bytes | None = None,
    signature: bytes | None = None,
    artifacts: dict[str, bytes] | None = None,
):
    """POST releases/upload with the files of `dist`, any of which can be replaced (tampering)."""
    mf = dist / f"exp-{version}-manifest.json"
    man = manifest if manifest is not None else mf.read_bytes()
    sig = signature if signature is not None else (dist / f"exp-{version}-manifest.json.sig").read_bytes()
    arts = artifacts
    if arts is None:
        arts = {p.name: p.read_bytes() for p in sorted(dist.glob(f"exp-*-{version}-*.tar.gz"))}
    ctype, body = multipart(
        [("manifest", mf.name, man), ("signature", mf.name + ".sig", sig)] + [("artifacts", n, b) for n, b in arts.items()]
    )
    return stack.mgr.request(
        "POST",
        "/api/admin/v1/releases/upload",
        headers={"Cf-Access-Jwt-Assertion": stack.token(), "Content-Type": ctype, "Accept": "application/json"},
        body=body,
        timeout=180,
    )


def force_publish(
    stack,
    dist: Path,
    version: str,
    *,
    signature_b64: str | None = None,
    manifest: bytes | None = None,
    tamper_artifacts: bool = False,
) -> None:
    """Write a release straight into the local D1/R2 WITHOUT the manager's checks: what a compromised store or a
    manager bug would serve. The agent must refuse it on its own (it trusts only the pinned release key)."""
    import base64
    import hashlib
    import tempfile

    mgr = stack.mgr
    man_bytes = (dist / f"exp-{version}-manifest.json").read_bytes()
    doc = json.loads(man_bytes)
    sig = signature_b64 or (dist / f"exp-{version}-manifest.json.sig").read_text().strip()
    rel_id = "rel_" + hashlib.sha256(f"forced:{version}".encode()).hexdigest()[:26].upper()
    mkey = f"releases/{version}/{rel_id}/manifest.json"
    cfg = str(REPO / "manager" / "wrangler.toml")
    persist = ["--local", "--persist-to", str(mgr.state)]
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)

        def put(key: str, data: bytes, ctype: str) -> None:
            f = tdp / hashlib.sha256(key.encode()).hexdigest()
            f.write_bytes(data)
            r = mgr.wrangler(
                "r2", "object", "put", f"exp-artifacts/{key}", "--file", str(f), "--content-type", ctype, *persist, "-c", cfg
            )
            assert r.returncode == 0, (r.stdout + r.stderr)[-500:]

        sql = []
        now = now_iso()
        for a in doc["artifacts"]:
            aid = "art_" + hashlib.sha256(f"forced:{version}:{a['name']}".encode()).hexdigest()[:26].upper()
            data = (dist / a["name"]).read_bytes()
            if tamper_artifacts:
                mid = len(data) // 2  # same size, one byte flipped in the middle of the payload
                data = data[:mid] + bytes([data[mid] ^ 0xFF]) + data[mid + 1 :]
            put(f"artifacts/{aid}", data, "application/gzip")
            sql.append(
                "INSERT OR REPLACE INTO artifacts (artifact_id, org_id, version, name, component, arch, sha256, size, r2_key, created_at, updated_at) "
                f"VALUES ('{aid}', 'default', '{version}', '{a['name']}', '{a['component']}', '{a['arch']}', '{a['sha256']}', {a['size']}, 'artifacts/{aid}', '{now}', '{now}');"
            )
        put(mkey, manifest if manifest is not None else man_bytes, "application/json")
        notes = doc.get("notes_url")
        sql.insert(
            0,
            "INSERT OR REPLACE INTO releases (version, org_id, manifest_r2_key, signature, min_agent_version, verified_at, source, notes_url, rel_id, manifest_created, created_at, updated_at) "
            f"VALUES ('{version}', 'default', '{mkey}', '{sig}', '{doc['min_agent_version']}', '{now}', 'upload', {('NULL' if not notes else repr(notes))}, '{rel_id}', '{doc['created']}', '{now}', '{now}');",
        )
        sqlf = tdp / "force.sql"
        sqlf.write_text("\n".join(sql) + "\n")
        r = mgr.wrangler("d1", "execute", "DB", *persist, "--file", str(sqlf), "--yes", "-c", cfg)
        assert r.returncode == 0, (r.stdout + r.stderr)[-500:]
    base64.b64decode(sig)  # (sanity: callers pass real base64)


# ---- a full host (collector + dashboard + probe on a veth LAN), as the A2.3 flow builds it -------------------------------
class Full:
    """A converged all-in-one host: the agent, collector, dashboard and a probe with one veth client port."""

    def __init__(self, host, host_id, ids, cids, enrol, install):
        self.host, self.host_id, self.ids, self.cids, self.enrol, self.install = host, host_id, ids, cids, enrol, install
        self.shapes = tuple(ids)

    def collector(self, stack) -> tuple[str, int, str, dict[str, str]]:
        cf = comp_row(stack, self.host_id, "collector").get("facts") or {}
        ip, port = cf["listen"].rsplit(":", 1)
        tok = json.loads(self.host.run("cat $(find /etc/exp/dashboard -name collector_tokens.json | head -1)").out)
        return ip, int(port), cf["tls_fingerprint_sha256"], {"Authorization": f"Bearer {tok[self.ids['collector']]}"}


def provision_full(
    stack,
    site: str,
    label: str,
    name: str,
    *,
    tmpfs_mb: int | None = None,
    shapes=("collector", "dashboard", "probe"),
    converge_s: float = 420,
) -> Full:
    from conftest import start_host  # noqa: PLC0415
    from test_a23_add_host import probe_intent  # noqa: PLC0415
    from test_a23_support import default_intent  # noqa: PLC0415

    admin = stack.admin
    if admin.call("GET", f"/sites/{site}").status != 200:
        set_site(stack, site, site)
    admin.call("PATCH", f"/sites/{site}/release", {"version": stack.version}, ok=(200,))
    ids = {t: f"{t[:3]}-{label}" for t in shapes}
    comps = {t: (ids[t], probe_intent() if t == "probe" else default_intent(t, name)) for t in shapes}
    host_id, enrol, cids = create_host(stack, site, name, comps)
    host = start_host(stack, label)
    full = Full(host, host_id, ids, cids, enrol, None)
    try:
        if tmpfs_mb:
            r = host.run(f"mkdir -p /var/lib/exp && mount -t tmpfs -o size={tmpfs_mb}m,mode=0755 tmpfs /var/lib/exp")
            assert r.rc == 0, r
        if "probe" in shapes:
            dockerhost.build_lan(host)
        full.install = host.run(enrol["command"], timeout=600)
        assert full.install.rc == 0, full.install
        wait_for(
            lambda: (h := host_row(stack, host_id))["facts"] and h["facts"].get("interfaces") and h, 120, 2, "host facts", host
        )
        if "probe" in shapes:
            r = admin.call(
                "PUT", f"/components/{cids['probe']}/ports", {"ports": [{"id": "c01", "iface": "vp0", "role": "client"}]}
            )
            assert r.status == 200, r
        wait_for(lambda: components_ok(stack, host_id, shapes), converge_s, 3, "all shapes healthy", host)
    except BaseException:
        host.remove()
        raise
    return full


def fetch_records(
    coll: tuple[str, int, str, dict[str, str]], probe: str, t_from: float, t_to: float, test: str | None = None
) -> list[dict[str, Any]]:
    ip, port, fp, auth = coll
    frm, to = (time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t)) for t in (t_from, t_to))
    out: list[dict[str, Any]] = []
    cursor = ""
    for _ in range(200):
        q = (
            f"/api/v1/records?probe={probe}&from={frm}&to={to}&limit=1000"
            + (f"&test={test}" if test else "")
            + (f"&cursor={cursor}" if cursor else "")
        )
        page = dockerhost.jget(ip, port, q, fp, auth)
        out += page["items"]
        cursor = page.get("next_cursor") or ""
        if not cursor:
            return out
    raise AssertionError("records pagination does not end")


def ingest_one(coll, token: str, probe: str, site: str) -> tuple[int, bytes]:
    """POST one measurement to the collector's ingest API with an arbitrary probe token (a leaked/old one)."""
    from exp_common.ids import new_ulid  # noqa: PLC0415

    ip, port, fp, _ = coll
    rec = {
        "schema": "exp.measurement/1",
        "id": new_ulid(),
        "ts": now_iso(),
        "probe": probe,
        "site": site,
        "test": "token_check",
        "outcome": "ok",
        "duration_ms": 1,
    }
    st, _h, body = dockerhost.pinned_request(
        ip,
        port,
        "POST",
        "/ingest/v1/measurements",
        fp,
        {"Authorization": f"Bearer {token}", "Content-Type": "application/x-ndjson", "User-Agent": "exp-probe/0.0-e2e"},
        (json.dumps(rec) + "\n").encode(),
    )
    return st, body


def probe_token(host: dockerhost.Host) -> str:
    """The probe's current ingest token, read from its credentials directory on the host."""
    out = host.run("grep -rhoE 'expi_[A-Za-z0-9_-]+' /etc/exp/probe/creds").out.split()
    assert len(out) == 1, f"expected one ingest token in /etc/exp/probe/creds, found {len(out)}"
    return out[0]
