"""Helpers for the M1 acceptance suite (SPEC.md section 9, A1.1-A1.5).

Everything runs in Docker through test/harness/harness.sh: a simulated event LAN ("net" container), systemd
hosts, a REAL signed release installed by test/harness/install-manual.sh (the agent's steps, minus the manager).
The tests are driven from the docker host: state is read from the dashboard's API (pinned TLS, a local-user
session) and from the collector's SQLite / the probe's spool inside the containers.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "test" / "harness"
for _p in (REPO / "shared" / "python", REPO / "dashboard"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from exp_common import config as exp_config  # noqa: E402
from exp_common import ids as exp_ids  # noqa: E402
from exp_common import tlspin  # noqa: E402
from exp_dashboard.auth import hash_password  # noqa: E402

ARTIFACTS = Path(os.environ.get("EXP_E2E_ARTIFACTS", tempfile.gettempdir() + "/exp-e2e-artifacts"))
SITE = "hall-b"
COLLECTOR_ID = "col-lab"
DASHBOARD_ID = "dash-lab"
LINES = ["network", "dhcp", "dns", "internet", "apps"]       # M1: no wifi/path tests exist yet
BEAT_LINES = ["network", "dhcp", "dns", "internet"]          # the 10-s heartbeat lines
PORT_IDS = ["c01", "c02", "c03"]
APP_INTERVAL_S = 30
USER, ROLE = "e2e-operator", "operator"


class E2EError(AssertionError):
    pass


def sh(argv: list[str], *, timeout: float = 120, input_: str | None = None,
       check: bool = False) -> subprocess.CompletedProcess[str]:
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input_, check=False)  # noqa: S603
    if check and r.returncode != 0:
        raise E2EError(f"{' '.join(argv)[:200]} failed rc={r.returncode}: {(r.stderr or r.stdout)[-800:]}")
    return r


def wait_for(fn: Callable[[], Any], timeout: float, step: float = 1.0, what: str = "condition") -> Any:
    """Poll fn() until truthy; return it. Raises with the last value on timeout."""
    end = time.monotonic() + timeout
    last: Any = None
    while True:
        try:
            last = fn()
        except (OSError, ValueError, KeyError, E2EError, tlspin.TlsPinError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if last:
                return last
        if time.monotonic() >= end:
            raise E2EError(f"timed out after {timeout:g}s waiting for {what}; last: {str(last)[:600]}")
        time.sleep(step)


# -------------------------------------------------------------------------------------------- release
@dataclass
class Release:
    dist: Path
    pubkey: Path
    version: str


def find_release(tmp: Path) -> Release:
    """The signed release to install. EXP_E2E_DIST + EXP_E2E_PUBKEY name an existing one; otherwise one is built
    here with a throwaway Ed25519 key (generated in `tmp`, outside the repo; never committed)."""
    d, k = os.environ.get("EXP_E2E_DIST"), os.environ.get("EXP_E2E_PUBKEY")
    if d and k:
        dist = Path(d)
        man = sorted(dist.glob("exp-*-manifest.json"))
        if len(man) != 1:
            raise E2EError(f"EXP_E2E_DIST={d} must hold exactly one manifest")
        return Release(dist, Path(k), json.loads(man[0].read_text())["version"])
    key, pub, out = tmp / "release.pem", tmp / "release-pub.pem", tmp / "dist"
    sh(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True)
    sh(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True)
    key.chmod(0o600)
    version = (REPO / "VERSION").read_text().strip()
    env = {**os.environ, "EXP_RELEASE_KEY": str(key), "EXP_RELEASE_PUBKEY": str(pub)}
    r = subprocess.run([str(REPO / "packaging" / "build.sh"), "--release", version, "--out", str(out)],  # noqa: S603
                       capture_output=True, text=True, env=env, timeout=900, check=False)
    if r.returncode != 0:
        raise E2EError(f"packaging/build.sh failed: {(r.stderr or r.stdout)[-800:]}")
    return Release(out, pub, version)


# -------------------------------------------------------------------------------------------- hosts
class Host:
    def __init__(self, name: str, container: str, ip: str) -> None:
        self.name, self.container, self.ip = name, container, ip

    def run(self, script: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return sh(["docker", "exec", self.container, "bash", "-c", script], timeout=timeout)

    def ok(self, script: str, timeout: float = 120) -> str:
        r = self.run(script, timeout)
        if r.returncode != 0:
            raise E2EError(f"[{self.name}] `{script[:160]}` rc={r.returncode}: {(r.stderr or r.stdout)[-800:]}")
        return r.stdout

    def put(self, src: Path, dst: str) -> None:
        sh(["docker", "cp", str(src), f"{self.container}:{dst}"], check=True)

    def sqlite(self, db: str, query: str) -> list[str]:
        out = self.ok(f"sqlite3 -readonly {db} {_q(query)}")
        return [ln for ln in out.splitlines() if ln]


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


# -------------------------------------------------------------------------------------------- dashboard
class Dash:
    """A local-user session on the dashboard, over TLS pinned to its (self-signed) certificate."""

    def __init__(self, base: str, fp: str, username: str, password: str) -> None:
        self.base, self.fp = base.rstrip("/"), fp
        r = tlspin.request("POST", self.base + "/auth/login", fp, body=json.dumps(
            {"username": username, "password": password}).encode(),
            headers={"Content-Type": "application/json"})
        if r.status >= 400:
            raise E2EError(f"dashboard login refused: {r.status} {r.body[:200]!r}")
        m = re.search(r"__Host-exp_session=([A-Za-z0-9_-]+)", r.headers.get("set-cookie", ""))
        if not m:
            raise E2EError(f"no session cookie in the login response: {r.headers}")
        self.cookie = "__Host-exp_session=" + m.group(1)
        self.session_id = m.group(1)

    def get(self, path: str, **params: Any) -> Any:
        q = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        r = tlspin.request("GET", f"{self.base}/api/v1/{path}" + (f"?{q}" if q else ""), self.fp,
                           headers={"Cookie": self.cookie}, read_timeout=15)
        if r.status != 200:
            raise E2EError(f"GET {path} -> {r.status} {r.body[:300]!r}")
        return r.json()

    def page(self, path: str) -> tlspin.Response:
        return tlspin.request("GET", self.base + path, self.fp, headers={"Cookie": self.cookie})


# -------------------------------------------------------------------------------------------- the stack
@dataclass
class Stack:
    layout: str
    release: Release
    col: Host
    probe_host: Host
    probe_id: str
    password: str
    col_fp: str = ""
    dash_fp: str = ""
    ingest_token: str = ""
    dash_token: str = ""
    started_at: float = 0.0
    log_dir: Path = ARTIFACTS
    _dash: Dash | None = field(default=None, repr=False)

    # --- addresses
    @property
    def collector_url(self) -> str:
        return f"https://{self.col.ip}:8443"

    @property
    def dashboard_url(self) -> str:
        return f"https://{self.col.ip}"

    # --- clients
    def dash(self) -> Dash:
        if self._dash is None:
            self._dash = Dash(self.dashboard_url, self.dash_fp, USER, self.password)
        return self._dash

    def collector_get(self, path: str, **params: Any) -> Any:
        """The collector's own query API with the dashboard token (what the dashboard itself does)."""
        q = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        r = tlspin.request("GET", f"{self.collector_url}/api/v1/{path}" + (f"?{q}" if q else ""), self.col_fp,
                           headers={"Authorization": f"Bearer {self.dash_token}", "X-Exp-User": USER})
        if r.status != 200:
            raise E2EError(f"collector GET {path} -> {r.status} {r.body[:300]!r}")
        return r.json()

    def ingest(self, lines: list[dict[str, Any] | str], token: str | None = None) -> tlspin.Response:
        body = "\n".join(ln if isinstance(ln, str) else json.dumps(ln) for ln in lines).encode() + b"\n"
        return tlspin.request("POST", self.collector_url + "/ingest/v1/measurements", self.col_fp, body=body,
                              headers={"Authorization": f"Bearer {token or self.ingest_token}",
                                       "Content-Type": "application/x-ndjson", "User-Agent": "exp-probe/e2e"})

    # --- LAN fault API
    def lanctl(self, *args: str) -> str:
        r = sh([str(HARNESS / "harness.sh"), "lanctl", *args], timeout=60)
        if r.returncode != 0:
            raise E2EError(f"lanctl {' '.join(args)} failed: {(r.stderr or r.stdout)[-400:]}")
        return r.stdout

    def port_label(self, i: int = 0) -> str:
        return f"{self.probe_host.name}-tp{i}"

    # --- probe lifecycle
    def probe_units(self) -> list[str]:
        return ["exp-probe-netns.service"] + [f"exp-probe-lease@{p}.service" for p in PORT_IDS] + ["exp-probe.service"]

    def start_probe(self) -> float:
        t0 = time.time()
        self.probe_host.ok("systemctl start " + " ".join(self.probe_units()), timeout=90)
        self.started_at = t0
        return t0

    def state(self, at: str | None = None) -> dict[str, Any]:
        return self.dash().get("state", probe=self.probe_id, at=at, voice="sysadmin")

    def line_states(self, st: dict[str, Any] | None = None) -> dict[str, str]:
        st = st or self.state()
        return {ln["key"]: ln["state"] for ln in st["lines"]}

    def journal(self, host: Host, unit: str, n: int = 40) -> str:
        return host.run(f"journalctl -u {unit} --no-pager -n {n} 2>&1 | tail -c 3000").stdout

    def save_logs(self, tag: str) -> None:
        d = self.log_dir / tag
        d.mkdir(parents=True, exist_ok=True)
        for h in {self.col.container: self.col, self.probe_host.container: self.probe_host}.values():
            out = h.run("journalctl --no-pager -u 'exp-*' -n 400 2>&1").stdout
            (d / f"{h.name}-journal.txt").write_text(out)
        (d / "lanctl-status.json").write_text(self.lanctl("status"))


# -------------------------------------------------------------------------------------------- configs
def make_collector_config(listen_ip: str, probe_id: str) -> dict[str, Any]:
    return {
        "schema": "exp.collector.config/1", "collector_id": COLLECTOR_ID, "site": SITE,
        "listen": f"{listen_ip}:8443",
        "probes": [{"probe_id": probe_id, "site": SITE, "label": "Hall B e2e"}],
        "dashboards": [DASHBOARD_ID],
        "retention": {"metrics_days": 7, "records_days": 7},
        "vm": {"listen": "127.0.0.1:8428", "memory_allowed_pct": 30},
        "rules": {"edge_label": "EC", "lines": LINES},
        "alerts": {"enabled": True, "board_url": f"https://{listen_ip}", "timezone": "UTC", "voice": "sysadmin",
                   "hold_down_s": 20, "hold_back_s": 60, "reopen_s": 300, "calm_s": 600},
        "reflector": {"enabled": False, "port": 8862},
        "iperf3": {"enabled": False, "port": 5201},
        "ingest": {"max_body_mb": 4, "max_records": 1000},
    }


def make_dashboard_config(dash_ip: str, col_ip: str, col_fp: str) -> dict[str, Any]:
    return {
        "schema": "exp.dashboard.config/1", "dashboard_id": DASHBOARD_ID, "title": "HPE EXP - M1 lab",
        "url": f"https://{dash_ip}",
        "listen": {"https": "0.0.0.0:443", "http_redirect": "0.0.0.0:80"},
        "collectors": [{"collector_id": COLLECTOR_ID, "site": SITE, "url": f"https://{col_ip}:8443",
                        "tls_fingerprint_sha256": col_fp}],
        "voice": "sysadmin", "timezone": "UTC",
        "auth": {"sso": {"manager_url": "https://exp-manager.invalid", "issuer": "exp-manager:default"},
                 "session_hours": 12, "local_users": True, "noc_tokens": True},
        "tls": {"mode": "self_signed"},
    }


def make_probe_config(probe_id: str, col_url: str, col_fp: str) -> dict[str, Any]:
    ports = [{"id": pid, "iface": f"tp{i}", "role": "client", "vlan": None,
              "dhcp": {"hostname": f"exp-lab-{pid}", "vendor_class": "exp-probe", "client_id": "mac"}}
             for i, pid in enumerate(PORT_IDS)]
    return {
        "schema": "exp.probe.config/1", "probe_id": probe_id, "site": SITE,
        "collector": {"url": col_url, "tls_fingerprint_sha256": col_fp, "fallback": []},
        "mode": "netns", "mgmt_iface": "eth0", "ports": ports,
        # heartbeat: the defaults of 02-probe.md section 5 (ping 1.1.1.1/8.8.8.8, trace 8.8.8.8, google.com/...,
        # alternate resolver 1.1.1.1): the simulated upstream answers all of them, so nothing is overridden
        "heartbeat": {"interval_s": 10, "gateway": True, "dhcp": True, "dns": True,
                      "trace": {"target": "8.8.8.8", "pace_ms": 20, "max_hops": 30, "timeout_s": 2, "control_path": True},
                      "ping": ["1.1.1.1", "8.8.8.8"],
                      "dns_names": ["google.com", "apple.com", "microsoft.com", "cloudflare.com"],
                      "alternate_resolver": "1.1.1.1"},
        "tests": {"dhcp": {"interval_s": 300, "offer_collect_s": 3.0},
                  "dns": {"interval_s": 300, "names": ["www.google.com", "teams.microsoft.com"]},
                  "app": {"interval_s": APP_INTERVAL_S,
                          "targets": [{"app": "google-search", "url": "https://www.google.com/", "apdex_t_ms": 500}]}},
        "spool": {"max_mb": 500, "max_days": 7},
        "labels": {"zone": "floor-1"},
    }


def validated(doc: dict[str, Any], schema_name: str) -> dict[str, Any]:
    exp_config.validate(doc, REPO / "shared" / "schemas" / schema_name)
    return doc


def write_conf(root: Path, shape: str, config: dict[str, Any], creds: dict[str, str]) -> Path:
    d = root / shape
    (d / "creds").mkdir(parents=True, exist_ok=True)
    (d / "config.json").write_text(json.dumps(config, indent=1))
    for name, text in creds.items():
        p = d / "creds" / name
        p.write_text(text)
        p.chmod(0o600)
    return root


# -------------------------------------------------------------------------------------------- bring-up
def bring_up(layout: str, release: Release, work: Path) -> Stack:
    r = sh([str(HARNESS / "harness.sh"), "up", layout], timeout=420)
    if r.returncode != 0:
        raise E2EError(f"harness up {layout} failed: {(r.stderr or r.stdout)[-1500:]}")
    prefix = os.environ.get("EXP_HARNESS_PREFIX", "expm1")
    base = os.environ.get("EXP_HARNESS_SUBNET", "172.30.41.0/24").rsplit(".", 1)[0]
    if layout == "all":
        col = probe_host = Host("h1", f"{prefix}-h1", f"{base}.11")
    else:
        col = Host("hc", f"{prefix}-hc", f"{base}.12")
        probe_host = Host("hp", f"{prefix}-hp", f"{base}.13")
    probe_id = f"probe-{layout}"
    st = Stack(layout, release, col, probe_host, probe_id, secrets.token_urlsafe(18))
    st.ingest_token, st.dash_token = exp_ids.new_token("expi"), exp_ids.new_token("expd")
    for h in {col.container: col, probe_host.container: probe_host}.values():
        h.ok("mkdir -p /etc/exp /root/dist")
        h.put(release.pubkey, "/etc/exp/release-pub.pem")
        sh(["docker", "cp", f"{release.dist}/.", f"{h.container}:/root/dist"], check=True)
        h.put(HARNESS / "install-manual.sh", "/root/install-manual.sh")

    def install(host: Host, shape: str, config: dict[str, Any], creds: dict[str, str], *flags: str) -> str:
        conf = work / f"conf-{layout}-{shape}"
        shutil.rmtree(conf, ignore_errors=True)
        write_conf(conf, shape, config, creds)
        host.ok("rm -rf /root/exp-conf")
        sh(["docker", "cp", str(conf), f"{host.container}:/root/exp-conf"], check=True)
        out = host.ok(f"/root/install-manual.sh {' '.join(flags)} --conf /root/exp-conf /root/dist {shape} 2>&1",
                      timeout=300)
        (st.log_dir / "install").mkdir(parents=True, exist_ok=True)
        (st.log_dir / "install" / f"{layout}-{shape}.log").write_text(out)
        return out

    # collector first: everybody else pins its certificate
    out = install(col, "collector",
                  validated(make_collector_config(col.ip, probe_id), "collector.config.schema.json"),
                  {"ingest_tokens.json": json.dumps({probe_id: exp_ids.token_hash(st.ingest_token)}),
                   "dashboard_tokens.json": json.dumps({DASHBOARD_ID: exp_ids.token_hash(st.dash_token)}),
                   "webhooks.json": "[]"})
    m = re.search(r"^FINGERPRINT collector (\S+)$", out, re.M)
    if not m:
        raise E2EError("the installer printed no collector fingerprint:\n" + out[-800:])
    st.col_fp = m.group(1)
    out = install(col, "dashboard",
                  validated(make_dashboard_config(col.ip, col.ip, st.col_fp), "dashboard.config.schema.json"),
                  {"collector_tokens.json": json.dumps({COLLECTOR_ID: st.dash_token}),
                   "sso_secret": base64.b64encode(secrets.token_bytes(32)).decode(),
                   "local_users.json": json.dumps([{"username": USER, "role": ROLE,
                                                    "hash": hash_password(st.password)}]),
                   "noc_tokens.json": "[]"})
    m = re.search(r"^FINGERPRINT dashboard (\S+)$", out, re.M)
    if not m:
        raise E2EError("the installer printed no dashboard fingerprint:\n" + out[-800:])
    st.dash_fp = m.group(1)
    # the probe is installed but NOT started: A1.1 starts it and times "within 30 s of start"
    install(probe_host, "probe",
            validated(make_probe_config(probe_id, st.collector_url, st.col_fp), "probe.config.schema.json"),
            {"ingest_token": st.ingest_token}, "--no-start")
    # A1.4 ledger: every record the probe ever spools, recorded by a trigger in its own spool database
    # (the probe deletes shipped records, so this is the only way to know "what was shipped" afterwards)
    probe_host.ok(
        "install -d -m 0755 /var/lib/exp/probe && sqlite3 /var/lib/exp/probe/spool.db "
        + _q("CREATE TABLE IF NOT EXISTS spool (id TEXT PRIMARY KEY, ts TEXT NOT NULL, body BLOB NOT NULL);"
             "CREATE TABLE ledger (id TEXT PRIMARY KEY, ts TEXT NOT NULL);"
             "CREATE TRIGGER ledger_ins AFTER INSERT ON spool BEGIN "
             "INSERT OR IGNORE INTO ledger VALUES (new.id, new.ts); END;"))
    return st


def tear_down() -> None:
    sh([str(HARNESS / "harness.sh"), "down"], timeout=180)
