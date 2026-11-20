#!/usr/bin/env python3
"""fake_manager: an in-memory manager agent-API for the agent (WP-6) to build against.

Implements shared/openapi/agent.yaml: enrol (single-use expe_ tokens, atomic), desired (ETag / 304),
signed release manifest + signature, artifact download (403 unless referenced by the host's desired
state), status intake (validated against exp.status/1), secret rotation with a grace period,
decommission. Releases are really signed with an Ed25519 key (openssl CLI) so the agent's
`openssl pkeyutl -verify -rawin` path can be exercised end to end.

A localhost-only control API under /_fake/ lets tests shape the world (hosts, enrol tokens, desired
docs, forced 5xx / unreachable, received status reports).

Run:    python test/fakes/fake_manager.py --listen 127.0.0.1:8080 --scenario default
Import: ``from fake_manager import start; fake = start(); fake.app.add_host(...); ...; fake.stop()``
"""
from __future__ import annotations

import argparse
import base64
import collections
import gzip
import hashlib
import io
import json
import logging
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared" / "python"))
from exp_common import config as exp_config  # noqa: E402
from exp_common import ids as exp_ids  # noqa: E402

import fakes_common as fc  # noqa: E402

log = logging.getLogger("exp.fakes.manager")

MAX_STATUS = 256 * 1024
MAX_ENROL_BODY = 64 * 1024
ROTATE_GRACE_S = 600
ENROL_TOKEN_TTL_S = 3600
POLL_INTERVAL_S = 30
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?\Z")
_ART = re.compile(r"art_[0-9A-HJKMNP-TV-Z]{26}\Z")
_HOST = re.compile(r"h_[0-9A-HJKMNP-TV-Z]{26}\Z")
det_id = fc.det_id

PLACEHOLDER_INSTALL_SH = """#!/bin/sh
# exp fake install.sh placeholder (fake_manager). Contains no secrets.
# The real script is served by the manager; this stub only proves the endpoint is reachable.
set -eu
echo "exp fake install.sh: enrol token must be passed as an argument; nothing was installed." >&2
exit 0
"""


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.details, self.headers = details, headers


class _Drop(Exception):
    """Close the connection without answering (simulates an unreachable manager)."""


def make_tarball(name: str, version: str) -> bytes:
    """A tiny deterministic tar.gz shaped like an exp artifact (VERSION + bin stub)."""
    top = name[:-len(".tar.gz")] if name.endswith(".tar.gz") else name
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        for rel, data, mode in ((f"{top}/VERSION", f"{version}\n".encode(), 0o644),
                                (f"{top}/bin/{top.rsplit('-', 2)[0]}", b"#!/bin/sh\necho fake\n", 0o755)):
            ti = tarfile.TarInfo(rel)
            ti.size, ti.mode, ti.mtime = len(data), mode, 0
            ti.uname = ti.gname = "root"
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class ReleaseKey:
    """Ed25519 release signing key managed with the openssl CLI (argv only, no shell)."""

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.key, self.pub = self.dir / "release-key.pem", self.dir / "release-pub.pem"
        self.openssl = shutil.which("openssl")
        if self.openssl and not (self.key.is_file() and self.pub.is_file()):
            self._run([self.openssl, "genpkey", "-algorithm", "ed25519", "-out", str(self.key)])
            self.key.chmod(0o600)
            self._run([self.openssl, "pkey", "-in", str(self.key), "-pubout", "-out", str(self.pub)])

    @staticmethod
    def _run(argv: list[str]) -> None:
        subprocess.run(argv, check=True, capture_output=True, timeout=30)  # noqa: S603

    @property
    def public_pem(self) -> str:
        if self.pub.is_file():
            return self.pub.read_text("ascii")
        return ("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
                "-----END PUBLIC KEY-----\n")

    def sign(self, data: bytes) -> str:
        """base64 raw Ed25519 signature over `data` (a fixed placeholder when openssl is missing)."""
        if not self.openssl:
            return base64.b64encode(b"\x00" * 64).decode()
        with tempfile.TemporaryDirectory(prefix="expsign-") as td:
            src, out = Path(td) / "m", Path(td) / "sig"
            src.write_bytes(data)
            self._run([self.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key),
                       "-in", str(src), "-out", str(out)])
            return base64.b64encode(out.read_bytes()).decode()


class RateLimiter:
    def __init__(self, limit: int, window_s: float, now_fn: Callable[[], float]) -> None:
        self.limit, self.window, self.now = limit, window_s, now_fn
        self.hits: dict[str, collections.deque[float]] = collections.defaultdict(collections.deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self.lock:
            t = self.now()
            dq = self.hits[key]
            while dq and t - dq[0] >= self.window:
                dq.popleft()
            if len(dq) >= self.limit:
                return False
            dq.append(t)
            return True

    def retry_after(self, key: str) -> int:
        with self.lock:
            dq = self.hits.get(key)
            if not dq:
                return 1
            return max(1, int(self.window - (self.now() - dq[0])) + 1)


class Host:
    def __init__(self, host_id: str, name: str, site: str, state: str) -> None:
        self.host_id, self.name, self.site, self.state = host_id, name, site, state
        self.secret_hash: str | None = None
        self.previous: list[tuple[str, float]] = []   # (sha256, valid_until_epoch)
        self.desired: dict[str, Any] | None = None
        self.facts: dict[str, Any] | None = None
        self.reports: list[dict[str, Any]] = []
        self.last_seen: float | None = None
        self.poll_count = 0


class ManagerApp:
    def __init__(self, *, state_dir: str | Path | None = None, now_fn: Callable[[], float] = time.time,
                 enrol_rate: tuple[int, float] = (10, 60.0), install_sh: str | Path | None = None,
                 control: bool = True) -> None:
        self.now = now_fn
        self.lock = threading.RLock()
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        if state_dir is None:
            self._tmp = tempfile.TemporaryDirectory(prefix="fake-manager-")
            state_dir = self._tmp.name
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.key = ReleaseKey(self.state_dir / "release-key")
        self.hosts: dict[str, Host] = {}
        self.enrol_tokens: dict[str, dict[str, Any]] = {}     # sha256 -> {host_id, expires_at, used}
        self.releases: dict[str, tuple[bytes, str]] = {}       # version -> (manifest bytes, sig b64)
        self.artifacts: dict[str, bytes] = {}                  # art_id -> bytes
        self.artifact_by_name: dict[str, tuple[str, str, int]] = {}  # name -> (art_id, sha256, size)
        self.force: dict[str, Any] | None = None
        self.enrol_limiter = RateLimiter(enrol_rate[0], enrol_rate[1], now_fn)
        self.install_sh = Path(install_sh) if install_sh else None
        self.control_enabled = control
        self.requests = 0
        self.enrol_successes = 0

    def close(self) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None

    # ------------------------------------------------------------------------------- world setup
    def add_host(self, *, host_id: str | None = None, name: str = "srv-02", site: str = "hall-b",
                 enrolled: bool = False, agent_secret: str | None = None) -> dict[str, str]:
        """Create a host. If `enrolled`, it already has an agent secret (returned)."""
        with self.lock:
            hid = host_id or exp_ids.new_id("h_")
            if not _HOST.match(hid):
                raise ValueError("host_id must be h_<ULID>")
            host = Host(hid, name, site, "enrolled" if enrolled else "pending")
            out = {"host_id": hid}
            if enrolled:
                secret = agent_secret or exp_ids.new_token("expa")
                host.secret_hash = exp_ids.token_hash(secret)
                out["agent_secret"] = secret
            self.hosts[hid] = host
            return out

    def issue_enrol_token(self, host_id: str, ttl_s: float = ENROL_TOKEN_TTL_S,
                          token: str | None = None) -> str:
        with self.lock:
            if host_id not in self.hosts:
                raise KeyError(host_id)
            tok = token or exp_ids.new_token("expe")
            if not exp_ids.is_token(tok, "expe"):
                raise ValueError("token must be an expe_ token")
            self.enrol_tokens[exp_ids.token_hash(tok)] = {
                "host_id": host_id, "expires_at": self.now() + ttl_s, "used": False}
            return tok

    def set_desired(self, host_id: str, doc: dict[str, Any], synthesize: bool = True) -> str:
        """Install `doc` as the host's desired state; returns the ETag. Version auto-bumps if omitted."""
        with self.lock:
            host = self.hosts[host_id]
            d = json.loads(json.dumps(doc))
            d["host_id"] = host_id
            if "version" not in doc:
                d["version"] = (host.desired["version"] + 1) if host.desired else 1
            elif host.desired and d["version"] < host.desired["version"]:
                raise ValueError("desired version must not go backwards")
            d.setdefault("generated_at", fc.iso_from_epoch(self.now()))
            if synthesize:
                self._bind_artifacts(d)
            exp_config.validate(d, "desired.schema.json")
            host.desired = d
            self._persist_desired(host)
            return self.etag_of(host)

    def desired_from_fixture(self, host_id: str, name: str, synthesize: bool = True) -> str:
        doc = fc.load_fixture(f"desired/{name}" if name.endswith(".json") else f"desired/{name}.json")
        doc.pop("version", None)
        return self.set_desired(host_id, doc, synthesize)

    def _persist_desired(self, host: Host) -> None:
        d = self.state_dir / "desired"
        d.mkdir(exist_ok=True)
        (d / f"{host.host_id}.json").write_text(json.dumps(host.desired, indent=2), "utf-8")

    def _bind_artifacts(self, doc: dict[str, Any]) -> None:
        """Make artifact references in `doc` servable: point them at release artifacts of the same
        name, else synthesize deterministic bytes (sha256/size rewritten to match)."""
        for comp in doc.get("components", []):
            art = comp.get("artifact")
            if not isinstance(art, dict):
                continue
            known = self.artifact_by_name.get(art.get("name", ""))
            if known:
                art["id"], art["sha256"], art["size"] = known
            else:
                data = self.artifacts.get(art["id"]) or make_tarball(art.get("name", "exp-x-0.0.0-noarch.tar.gz"),
                                                                     comp.get("version", "0.0.0"))
                self.artifacts[art["id"]] = data
                art["sha256"], art["size"] = hashlib.sha256(data).hexdigest(), len(data)
            art["url"] = f"/api/agent/v1/artifacts/{art['id']}"
        agent_art = (doc.get("agent") or {}).get("artifact")
        if isinstance(agent_art, str) and agent_art not in self.artifacts:
            ver = doc["agent"].get("version", "0.0.0")
            self.artifacts[agent_art] = make_tarball(f"exp-agent-{ver}-noarch.tar.gz", ver)

    def add_release(self, version: str, components: tuple[str, ...] = ("agent", "probe", "collector", "dashboard",
                                                                       "runner")) -> dict[str, Any]:
        """Build, sign and register release `version` with synthesized artifacts. Returns the manifest."""
        if not _VERSION.match(version):
            raise ValueError("bad version")
        arts = []
        with self.lock:
            for comp in components:
                for arch in (("amd64", "arm64") if comp == "collector" else ("noarch",)):
                    name = f"exp-{comp}-{version}-{arch}.tar.gz"
                    data = make_tarball(name, version)
                    aid = det_id("art_", name)
                    self.artifacts[aid] = data
                    sha = hashlib.sha256(data).hexdigest()
                    self.artifact_by_name[name] = (aid, sha, len(data))
                    arts.append({"name": name, "component": comp, "arch": arch, "sha256": sha, "size": len(data)})
            manifest = {"schema": "exp.manifest/1", "version": version, "created": fc.iso_from_epoch(self.now()),
                        "min_agent_version": "0.1.0", "artifacts": arts,
                        "notes_url": f"https://github.com/example-org/exp/releases/tag/v{version}"}
            exp_config.validate(manifest, "manifest.schema.json")
            raw = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
            self.releases[version] = (raw, self.key.sign(raw))
            return manifest

    def load_state_dir(self) -> None:
        """Pick up optional scenario files: hosts.json, releases/<v>/manifest.json(+.sig), artifacts/<art_id>."""
        sd = self.state_dir
        for p in sorted((sd / "artifacts").glob("art_*")) if (sd / "artifacts").is_dir() else []:
            if _ART.match(p.name):
                self.artifacts[p.name] = p.read_bytes()
        for vdir in sorted((sd / "releases").iterdir()) if (sd / "releases").is_dir() else []:
            man = vdir / "manifest.json"
            if man.is_file() and _VERSION.match(vdir.name):
                raw = man.read_bytes()
                sigp = vdir / "manifest.sig"
                sig = sigp.read_text("ascii").strip() if sigp.is_file() else self.key.sign(raw)
                self.releases[vdir.name] = (raw, sig)
        hosts = sd / "hosts.json"
        if hosts.is_file():
            for h in exp_config.load_json(hosts):
                made = self.add_host(host_id=h.get("host_id"), name=h.get("name", "srv-02"),
                                     site=h.get("site", "hall-b"), enrolled=h.get("enrolled", True),
                                     agent_secret=h.get("agent_secret"))
                if h.get("desired"):
                    self.desired_from_fixture(made["host_id"], h["desired"])
        for p in sorted((sd / "desired").glob("h_*.json")) if (sd / "desired").is_dir() else []:
            hid = p.stem
            if hid in self.hosts:
                doc = exp_config.load_json(p)
                self.set_desired(hid, doc, synthesize=True)

    def load_default_scenario(self) -> dict[str, str]:
        """Release 0.1.0, one enrolled host with a probe desired state, one pending host with a token."""
        self.add_release("0.1.0")
        fixture = fc.load_fixture("desired/probe-host.json")
        made = self.add_host(host_id=fixture["host_id"], name="srv-02", site="hall-b", enrolled=True,
                             agent_secret=fc.fixture_token("expa", "srv-02"))
        self.desired_from_fixture(made["host_id"], "probe-host")
        pending = self.add_host(name="srv-03", site="hall-b", enrolled=False)
        tok = self.issue_enrol_token(pending["host_id"], token=fc.fixture_token("expe", "srv-03"))
        return {"enrolled_host": made["host_id"], "agent_secret": made["agent_secret"],
                "pending_host": pending["host_id"], "enrol_token": tok}

    # --------------------------------------------------------------------------------- behaviour
    @staticmethod
    def etag_of(host: Host) -> str:
        if host.desired is None:
            raise ValueError("host has no desired state")
        return f'"{host.host_id}:{host.desired["version"]}"'

    def set_force(self, status: int | None = None, unreachable: bool = False, count: int | None = None,
                  retry_after: int = 1) -> None:
        if status is not None and not (status == 429 or 500 <= status <= 599):
            raise ValueError("forced status must be 429 or 5xx")
        with self.lock:
            self.force = {"status": status, "unreachable": unreachable, "count": count,
                          "retry_after": retry_after} if (status or unreachable) else None

    def take_force(self) -> dict[str, Any] | None:
        with self.lock:
            f = self.force
            if not f:
                return None
            if f["count"] is not None:
                if f["count"] <= 0:
                    self.force = None
                    return None
                f["count"] -= 1
            return dict(f)

    def authenticate(self, token: str | None) -> Host:
        """Host whose current secret (or a previous one still inside its grace) matches `token`."""
        if not token or not exp_ids.is_token(token, "expa"):
            raise ApiError(401, "invalid_token", "missing or invalid agent secret", headers={"WWW-Authenticate": "Bearer"})
        digest = exp_ids.token_hash(token)
        now = self.now()
        found: Host | None = None
        with self.lock:
            for h in self.hosts.values():
                if h.state == "removed":
                    continue
                ok = h.secret_hash is not None and exp_ids.tokens_equal(digest, h.secret_hash)
                for ph, until in h.previous:
                    if exp_ids.tokens_equal(digest, ph) and until > now:
                        ok = True
                if ok and found is None:
                    found = h
        if found is None:
            raise ApiError(401, "invalid_token", "missing or invalid agent secret", headers={"WWW-Authenticate": "Bearer"})
        return found

    def enrol(self, token: str, facts: dict[str, Any]) -> dict[str, Any]:
        digest = exp_ids.token_hash(token)
        with self.lock:   # the whole check-and-mark is one critical section: single use is atomic
            rec = self.enrol_tokens.get(digest)
            if rec is None:
                raise ApiError(401, "invalid_token", "unknown enrol token")
            if rec["used"] or rec["expires_at"] <= self.now():
                raise ApiError(410, "token_used_or_expired", "enrol token already used or expired")
            rec["used"] = True
            host = self.hosts[rec["host_id"]]
            secret = exp_ids.new_token("expa")
            host.secret_hash = exp_ids.token_hash(secret)
            host.previous = []
            host.state = "enrolled"
            host.facts = facts
            host.last_seen = self.now()
            if host.desired is None:
                self._default_desired(host)
            self.enrol_successes += 1
            return {"agent_id": host.host_id, "agent_secret": secret, "poll_interval_s": POLL_INTERVAL_S,
                    "release_pubkey_pem": self.key.public_pem, "manager_time": fc.iso_from_epoch(self.now())}

    def _default_desired(self, host: Host) -> None:
        version = sorted(self.releases)[-1] if self.releases else "0.1.0"
        doc = {"schema": "exp.desired/1", "host_id": host.host_id, "version": 1,
               "generated_at": fc.iso_from_epoch(self.now()),
               "org": {"id": "default", "name": "HPE Event NOC"},
               "site": {"id": host.site, "name": host.site, "timezone": "UTC"},
               "agent": {"version": version, "artifact": det_id("art_", f"exp-agent-{version}-noarch.tar.gz"),
                         "poll_interval_s": POLL_INTERVAL_S, "status_interval_s": 60},
               "release": {"version": version, "manifest_url": f"/api/agent/v1/releases/{version}/manifest",
                           "signature_url": f"/api/agent/v1/releases/{version}/manifest.sig"},
               "components": [], "actions": [], "decommission": False}
        self.artifacts.setdefault(doc["agent"]["artifact"], make_tarball(f"exp-agent-{version}-noarch.tar.gz", version))
        host.desired = doc

    def referenced_artifacts(self, host: Host) -> set[str]:
        d = host.desired or {}
        refs = {c["artifact"]["id"] for c in d.get("components", []) if isinstance(c.get("artifact"), dict)}
        for c in d.get("components", []):  # M6: speedtest branding assets are referenced by the desired state too (SR-6)
            for asset in c.get("assets", []) if isinstance(c.get("assets"), list) else []:
                if isinstance(asset, dict) and isinstance(asset.get("artifact"), dict):
                    refs.add(asset["artifact"]["id"])
        agent_art = (d.get("agent") or {}).get("artifact")
        if isinstance(agent_art, str):
            refs.add(agent_art)
        return refs

    def rotate(self, host: Host) -> dict[str, Any]:
        with self.lock:
            d = host.desired or {}
            acts = [a for a in d.get("actions", []) if a.get("type") == "rotate_agent_secret"]
            if not acts:
                raise ApiError(409, "rotation_not_requested", "desired state carries no rotate_agent_secret action")
            now = self.now()
            host.previous = [(h, u) for h, u in host.previous if u > now]
            if host.secret_hash:
                host.previous.append((host.secret_hash, now + ROTATE_GRACE_S))
            secret = exp_ids.new_token("expa")
            host.secret_hash = exp_ids.token_hash(secret)
            d["actions"] = [a for a in d.get("actions", []) if a.get("type") != "rotate_agent_secret"]
            d["version"] += 1       # the action is consumed, so the agent does not rotate again
            self._persist_desired(host)
            return {"agent_secret": secret, "grace_s": ROTATE_GRACE_S}

    def decommissioned(self, host: Host) -> None:
        with self.lock:
            if not (host.desired or {}).get("decommission"):
                raise ApiError(409, "not_decommissioning", "desired state does not carry decommission: true")
            host.state = "removed"
            host.secret_hash = None
            host.previous = []


# --------------------------------------------------------------------------------------- handler

class Handler(fc.BaseHandler):
    app: ManagerApp  # type: ignore[assignment]

    def dispatch(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        app = self.app
        with app.lock:
            app.requests += 1
        try:
            if path == "/healthz":
                return self._get_only(method, lambda: self.send_text(200, "ok"))
            if path == "/install.sh":
                return self._get_only(method, self._install_sh)
            if path.startswith("/_fake/"):
                return self._control(method, path)
            if path.startswith("/api/agent/v1/"):
                return self._agent(method, path[len("/api/agent/v1/"):])
            raise ApiError(404, "not_found", "no such path")
        except ApiError as e:
            self.send_err(e.status, e.code, e.message, e.details, e.headers)
        except _Drop:
            self.close_connection = True
            try:
                self.connection.shutdown(2)
            except OSError:
                pass

    @staticmethod
    def _get_only(method: str, fn: Callable[[], None]) -> None:
        if method not in ("GET", "HEAD"):
            raise ApiError(405, "method_not_allowed", "GET only", headers={"Allow": "GET, HEAD"})
        fn()

    def _install_sh(self) -> None:
        text = PLACEHOLDER_INSTALL_SH
        if self.app.install_sh is not None:
            text = self.app.install_sh.read_text("utf-8")
        self.send_text(200, text, "text/x-shellscript")

    # --- agent API ----------------------------------------------------------------------------
    def _agent(self, method: str, rest: str) -> None:
        app = self.app
        f = app.take_force()
        if f:
            if f["unreachable"]:
                raise _Drop
            self.drain(self.content_length() or 0)
            code = {429: "rate_limited", 503: "unavailable"}.get(f["status"], "internal_error")
            raise ApiError(f["status"], code, code.replace("_", " "), headers={"Retry-After": str(f["retry_after"])}
                           if f["status"] in (429, 503) else None)
        if rest == "enrol":
            self._need(method, "POST")
            return self._enrol()
        m = re.fullmatch(r"releases/([^/]+)/(manifest|manifest\.sig)", rest)
        m_art = re.fullmatch(r"artifacts/([^/]+)", rest)
        table: dict[str, tuple[str, Callable[[Host], None]]] = {
            "desired": ("GET", self._desired), "status": ("POST", self._status),
            "rotate": ("POST", self._rotate), "decommissioned": ("POST", self._decommissioned)}
        if rest in table:
            want, fn = table[rest]
            self._need(method, want)
            return fn(self._auth())
        if m:
            self._need(method, "GET")
            self._auth()
            return self._release(m.group(1), m.group(2))
        if m_art:
            self._need(method, "GET")
            return self._artifact(self._auth(), m_art.group(1))
        raise ApiError(404, "not_found", "no such endpoint")

    @staticmethod
    def _need(method: str, want: str) -> None:
        if method != want:
            raise ApiError(405, "method_not_allowed", f"{want} only", headers={"Allow": want})

    def _auth(self) -> Host:
        try:
            return self.app.authenticate(fc.bearer_token(self.header("Authorization")))
        except ApiError:
            self.drain(self.content_length() or 0) if (self.content_length() or 0) > 0 else None
            raise

    def _enrol(self) -> None:
        app = self.app
        ip = self.client_address[0]
        if not app.enrol_limiter.allow(ip):
            self.drain(self.content_length() or 0)
            raise ApiError(429, "rate_limited", "too many enrol attempts",
                           headers={"Retry-After": str(app.enrol_limiter.retry_after(ip))})
        body = self.read_body(MAX_ENROL_BODY)
        if body is None:
            raise ApiError(400, "invalid_request", "body too large")
        try:
            doc = exp_config.parse_json(body, "body")
        except ValueError as exc:
            raise ApiError(400, "invalid_request", str(exc)[:300]) from exc
        errors: list[dict[str, str]] = []
        if not isinstance(doc, dict):
            raise ApiError(400, "invalid_request", "body must be an object")
        token = doc.get("token")
        if not exp_ids.is_token(token, "expe"):
            errors.append({"path": "/token", "message": "must be an expe_ token"})
        facts = doc.get("facts")
        if not isinstance(facts, dict):
            errors.append({"path": "/facts", "message": "required object"})
        else:
            try:
                exp_config.validate(facts, {"$ref": "status.schema.json#/properties/facts"})
            except exp_config.ConfigError as exc:
                errors.extend({"path": "/facts" + i.path, "message": i.message} for i in exc.errors[:20])
        if errors:
            raise ApiError(400, "invalid_request", "schema validation failed", {"errors": errors})
        result = app.enrol(token, facts)  # type: ignore[arg-type]
        self.send_json(201, result, {"Cache-Control": "no-store"})

    def _desired(self, host: Host) -> None:
        app = self.app
        with app.lock:
            host.last_seen = app.now()
            host.poll_count += 1
            if host.desired is None:
                app._default_desired(host)
            etag = app.etag_of(host)
            doc = host.desired
        inm = self.header("If-None-Match")
        if inm and _etag_matches(inm, etag):
            return self.send_empty(304, {"ETag": etag})
        self.send_json(200, doc, {"ETag": etag, "Cache-Control": "no-store"})

    def _release(self, version: str, what: str) -> None:
        with self.app.lock:
            rel = self.app.releases.get(version) if _VERSION.match(version) else None
        if rel is None:
            raise ApiError(404, "not_found", "no such release")
        raw, sig = rel
        if what == "manifest":
            self.send_bytes(200, raw, "application/json")
        else:
            self.send_bytes(200, sig.encode("ascii"), "text/plain")

    def _artifact(self, host: Host, art_id: str) -> None:
        app = self.app
        with app.lock:
            if not _ART.match(art_id) or art_id not in app.referenced_artifacts(host):
                raise ApiError(403, "forbidden", "artifact is not referenced by this host's desired state")
            data = app.artifacts.get(art_id)
        if data is None:
            raise ApiError(404, "not_found", "artifact bytes not available")
        sha = hashlib.sha256(data).hexdigest()
        etag = f'"{sha}"'
        inm = self.header("If-None-Match")
        if inm and _etag_matches(inm, etag):
            return self.send_empty(304, {"ETag": etag})
        self.send_bytes(200, data, "application/gzip", {"ETag": etag})

    def _status(self, host: Host) -> None:
        body = self.read_body(MAX_STATUS)
        if body is None:
            raise ApiError(413, "payload_too_large", f"status report exceeds {MAX_STATUS} bytes")
        try:
            doc = exp_config.parse_json(body, "status report")
        except ValueError as exc:
            raise ApiError(400, "invalid_request", str(exc)[:300]) from exc
        try:
            exp_config.validate(doc, "status.schema.json")
        except exp_config.ConfigError as exc:
            raise ApiError(400, "invalid_request", "status report failed schema validation",
                           {"errors": [{"path": i.path, "message": i.message} for i in exc.errors[:20]]}) from exc
        with self.app.lock:
            host.reports.append(doc)
            del host.reports[:-200]
            host.last_seen = self.app.now()
            if host.state in ("pending", "stale"):
                host.state = "enrolled"
        self.send_empty(204)

    def _empty_body(self) -> None:
        body = self.read_body(4096)
        if body is None:
            raise ApiError(400, "invalid_request", "body too large")
        if not body.strip():
            return
        try:
            doc = exp_config.parse_json(body, "body")
        except ValueError as exc:
            raise ApiError(400, "invalid_request", str(exc)[:300]) from exc
        if doc != {}:
            raise ApiError(400, "invalid_request", "body must be an empty JSON object {}")

    def _rotate(self, host: Host) -> None:
        self._empty_body()
        self.send_json(200, self.app.rotate(host), {"Cache-Control": "no-store"})

    def _decommissioned(self, host: Host) -> None:
        self._empty_body()
        self.app.decommissioned(host)
        self.send_empty(204)

    # --- /_fake control (loopback only) --------------------------------------------------------
    def _control(self, method: str, path: str) -> None:
        app = self.app
        if not app.control_enabled or not self.client_is_loopback():
            raise ApiError(403, "forbidden", "control API is loopback-only")
        parts = path[len("/_fake/"):].strip("/").split("/")
        op = parts[0]
        try:
            if method == "GET" and op == "hosts":
                with app.lock:
                    return self.send_json(200, {"items": [
                        {"host_id": h.host_id, "name": h.name, "site": h.site, "state": h.state,
                         "desired_version": (h.desired or {}).get("version"), "polls": h.poll_count,
                         "reports": len(h.reports)} for h in app.hosts.values()]})
            if method == "GET" and op == "status" and len(parts) == 2:
                with app.lock:
                    host = app.hosts[parts[1]]
                    return self.send_json(200, {"reports": list(host.reports)})
            if method == "GET" and op == "stats":
                return self.send_json(200, {"requests": app.requests, "enrol_successes": app.enrol_successes})
            if method in ("POST", "PUT"):
                doc, ok = self.read_json(8 * 1024 * 1024)
                if not ok:
                    return None
                if op == "hosts" and method == "POST":
                    return self.send_json(200, app.add_host(
                        host_id=doc.get("host_id"), name=doc.get("name", "srv-02"), site=doc.get("site", "hall-b"),
                        enrolled=bool(doc.get("enrolled", False)), agent_secret=doc.get("agent_secret")))
                if op == "enrol-token" and method == "POST":
                    ttl = float(doc.get("ttl_s", ENROL_TOKEN_TTL_S))
                    tok = app.issue_enrol_token(doc["host_id"], ttl, doc.get("token"))
                    return self.send_json(200, {"token": tok, "expires_at": fc.iso_from_epoch(app.now() + ttl)})
                if op == "desired" and len(parts) == 2 and method == "PUT":
                    if "fixture" in doc:
                        etag = app.desired_from_fixture(parts[1], doc["fixture"], doc.get("synthesize", True))
                    else:
                        etag = app.set_desired(parts[1], doc["doc"], doc.get("synthesize", True))
                    return self.send_json(200, {"etag": etag})
                if op == "force" and method == "POST":
                    app.set_force(doc.get("status"), bool(doc.get("unreachable", False)), doc.get("count"),
                                  int(doc.get("retry_after", 1)))
                    return self.send_json(200, {"ok": True})
                if op == "release" and method == "POST":
                    man = app.add_release(doc["version"])
                    return self.send_json(200, man)
        except (KeyError, ValueError, TypeError) as exc:
            raise ApiError(400, "invalid_request", f"{type(exc).__name__}: {exc}"[:300]) from exc
        except exp_config.ConfigError as exc:
            raise ApiError(400, "invalid_request", str(exc.summary)[:300],
                           {"errors": [{"path": i.path, "message": i.message} for i in exc.errors[:20]]}) from exc
        raise ApiError(404, "not_found", "no such control op")


def _etag_matches(header: str, etag: str) -> bool:
    if header.strip() == "*":
        return True
    for cand in header.split(","):
        c = cand.strip()
        if c.startswith("W/"):
            c = c[2:]
        if c == etag:
            return True
    return False


# ------------------------------------------------------------------------------------ entry points

class FakeManager(fc.FakeServer):
    def stop(self) -> None:
        super().stop()
        self.app.close()


def start(*, host: str = "127.0.0.1", port: int = 0, tls: bool = False, state_dir: str | Path | None = None,
          scenario: str | None = None, **app_kwargs: Any) -> FakeManager:
    """Start a fake manager in-process; returns the running server (``.port``, ``.app``, ``.stop()``).

    scenario="default" seeds release 0.1.0, an enrolled host and a pending host with a fixture enrol token
    (see ``server.scenario_info``)."""
    app = ManagerApp(state_dir=state_dir, **app_kwargs)
    app.load_state_dir()
    info: dict[str, str] = {}
    if scenario == "default":
        info = app.load_default_scenario()
    elif scenario not in (None, "empty"):
        raise ValueError(f"unknown scenario {scenario!r} (default|empty)")
    tls_files = None
    if tls:
        cert, key, _ = fc.prepare_tls(app.state_dir)
        tls_files = (cert, key)
    server = FakeManager(Handler, app, host=host, port=port, tls=tls_files, name="fake_manager")
    server.scenario_info = info  # type: ignore[attr-defined]
    server.start()
    return server


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--listen", default="127.0.0.1:0", help="host:port (default 127.0.0.1, ephemeral port)")
    ap.add_argument("--tls", action=argparse.BooleanOptionalAction, default=False,
                    help="serve HTTPS with a self-signed cert generated under the state dir")
    ap.add_argument("--state-dir", help="scenario/state directory (hosts.json, desired/, releases/, artifacts/)")
    ap.add_argument("--scenario", choices=["default", "empty"], default="default")
    ap.add_argument("--install-sh", help="file served at GET /install.sh (default: placeholder)")
    ap.add_argument("--enrol-rate", type=int, default=10, help="enrol attempts per IP per minute (default 10)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    host, _, port_s = args.listen.rpartition(":")
    srv = start(host=host or "127.0.0.1", port=int(port_s or 0), tls=args.tls, state_dir=args.state_dir,
                scenario=args.scenario, install_sh=args.install_sh, enrol_rate=(args.enrol_rate, 60.0))

    def banner() -> str:
        lines = [f"fake_manager listening on {srv.base_url}"]
        if srv.fingerprint:
            lines.append(f"tls fingerprint (sha256): {srv.fingerprint}")
        info = getattr(srv, "scenario_info", {})
        for k, v in info.items():
            lines.append(f"  {k}: {v}")
        lines.append("control API: /_fake/ (loopback only)")
        return "\n".join(lines)

    fc.run_forever(srv, banner)
    return 0


if __name__ == "__main__":
    sys.exit(main())
