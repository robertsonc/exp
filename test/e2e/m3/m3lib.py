"""Helpers for the M3 multi-site acceptance suite (SPEC.md section 9, A3.1 federation, A3.2 webhooks).

The "multisite" harness layout (test/harness/harness.sh up multisite): two event LANs, three collectors (two at
site hall-b, one at hall-c), one probe per collector on its site's LAN, ONE dashboard federating all three, and a
local https webhook receiver the collectors' webhooks.json points at. Everything is installed from a REAL signed
release with test/harness/install-manual.sh, exactly as the M1 suite does (m1lib is reused for the generic parts).

Docker resources use their own prefix/subnet (expm3, 172.30.43.0/24) so this suite can run beside the M1 one.
"""
from __future__ import annotations

import base64
import concurrent.futures as cf
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

os.environ.setdefault("EXP_HARNESS_PREFIX", "expm3")
os.environ.setdefault("EXP_HARNESS_SUBNET", "172.30.43.0/24")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "m1"))

import m1lib as L  # noqa: E402  (the M1 helpers: Host, Dash, wait_for, release, configs)
from exp_common import ids as exp_ids  # noqa: E402
from exp_common import tlspin  # noqa: E402
from exp_dashboard.auth import hash_password  # noqa: E402

REPO, HARNESS = L.REPO, L.HARNESS
E2EError, wait_for, sh = L.E2EError, L.wait_for, L.sh
ARTIFACTS = Path(os.environ.get("EXP_E2E_ARTIFACTS", str(L.ARTIFACTS))) / "m3"
PREFIX = os.environ["EXP_HARNESS_PREFIX"]
BASE = os.environ["EXP_HARNESS_SUBNET"].rsplit(".", 1)[0]
NET_IP = f"{BASE}.2"                       # the net container: the webhook receiver listens here (9443)
HOOKS_PORT = 9443
DASHBOARD_ID = "dash-m3"
USER = L.USER
PORT_IDS = L.PORT_IDS
LINES = L.LINES
SITE_A, SITE_B = "hall-b", "hall-c"

# per collector: (host, ip octet, collector id, site, probe id, probe label, alerts overrides)
NODES: list[dict[str, Any]] = [
    {"host": "hb1", "oct": 21, "cid": "col-b1", "site": SITE_A, "probe": "probe-b1", "label": "Hall B east",
     "lan": 1, "alerts": {}},
    # col-b2 pages flapping: its hold_back_s/calm_s are shortened so that "quiet until calm" is observable in a few
    # minutes instead of the spec's 10 (documented in test_a32_alerts.py; the other collectors keep the defaults)
    {"host": "hb2", "oct": 22, "cid": "col-b2", "site": SITE_A, "probe": "probe-b2", "label": "Hall B west",
     "lan": 1, "alerts": {"hold_back_s": 30, "calm_s": 90}},
    {"host": "hc1", "oct": 23, "cid": "col-c1", "site": SITE_B, "probe": "probe-c1", "label": "Hall C main",
     "lan": 2, "alerts": {}},
]
DASH_HOST, DASH_OCT = "hd", 24
HOOK_FORMATS = ("slack", "teams", "json")


@dataclass
class Node:
    host: L.Host
    cid: str
    site: str
    probe: str
    label: str
    lan: int
    alerts: dict[str, Any]
    ingest_token: str = ""
    dash_token: str = ""
    fp: str = ""
    hook_secret: str = ""

    @property
    def url(self) -> str:
        return f"https://{self.host.ip}:8443"

    def port_label(self, i: int = 0) -> str:
        return f"{self.host.name}-tp{i}"

    def probe_units(self) -> list[str]:
        return ["exp-probe-netns.service"] + [f"exp-probe-lease@{p}.service" for p in PORT_IDS] + ["exp-probe.service"]


@dataclass
class Multi:
    release: L.Release
    nodes: list[Node]
    dash_host: L.Host
    password: str
    log_dir: Path
    dash_fp: str = ""
    notes: dict[str, Any] = field(default_factory=dict)
    _dash: L.Dash | None = field(default=None, repr=False)

    @property
    def dashboard_url(self) -> str:
        return f"https://{self.dash_host.ip}"

    def dash(self) -> L.Dash:
        if self._dash is None:
            self._dash = L.Dash(self.dashboard_url, self.dash_fp, USER, self.password)
        return self._dash

    def node(self, probe: str) -> Node:
        return next(n for n in self.nodes if n.probe == probe)

    def collector_get(self, node: Node, path: str, **params: Any) -> Any:
        q = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        r = tlspin.request("GET", f"{node.url}/api/v1/{path}" + (f"?{q}" if q else ""), node.fp,
                           headers={"Authorization": f"Bearer {node.dash_token}", "X-Exp-User": USER}, read_timeout=15)
        if r.status != 200:
            raise E2EError(f"collector {node.cid} GET {path} -> {r.status} {r.body[:300]!r}")
        return r.json()

    # --- LAN fault API (per site where it matters)
    def lanctl(self, *args: str) -> str:
        r = sh([str(HARNESS / "harness.sh"), "lanctl", *args], timeout=60)
        if r.returncode != 0:
            raise E2EError(f"lanctl {' '.join(args)} failed: {(r.stderr or r.stdout)[-400:]}")
        return r.stdout

    def block_dns(self, node: Node) -> None:
        for i in range(3):
            self.lanctl("block-dns", node.port_label(i))

    def canary(self, site_lan: int) -> None:
        gw = f"10.{site_lan}.0.1"
        for ip in (gw, "1.1.1.1", "8.8.8.8"):
            self.lanctl("canary", ip, "--site", str(site_lan))

    # --- probes
    def start_probes(self) -> float:
        t0 = time.time()
        with cf.ThreadPoolExecutor(len(self.nodes)) as ex:
            list(ex.map(lambda n: n.host.ok("systemctl start " + " ".join(n.probe_units()), timeout=120), self.nodes))
        return t0

    # --- webhook receiver (a JSONL file in the net container)
    def hook_records(self) -> list[dict[str, Any]]:
        r = sh(["docker", "exec", f"{PREFIX}-net", "cat", "/var/lib/lan/webhooks.jsonl"], timeout=30)
        if r.returncode != 0:
            raise E2EError(f"cannot read the webhook log: {r.stderr[-200:]}")
        return [json.loads(ln) for ln in r.stdout.splitlines() if ln.strip()]

    def hook_url(self, node: Node, fmt: str) -> str:
        return f"https://{NET_IP}:{HOOKS_PORT}/hook/{fmt}/{node.hook_secret}"

    def pages(self, node: Node | None = None, since: float = 0.0) -> list[dict[str, Any]]:
        """Webhook POSTs, decoded: [{fmt, probe(collector), seq, ts, doc, rec}]; `probe` is the owning probe id."""
        out = []
        by_secret = {n.hook_secret: n for n in self.nodes}
        for rec in self.hook_records():
            if rec["ts"] < since:
                continue
            fmt, _, secret = rec["path"].removeprefix("/hook/").partition("/")
            n = by_secret.get(secret)
            if n is None or (node is not None and n is not node):
                continue
            out.append({"fmt": fmt, "node": n, "seq": rec["seq"], "ts": rec["ts"], "doc": json.loads(rec["body"]), "rec": rec})
        return out

    def save_logs(self, tag: str) -> None:
        d = self.log_dir / tag
        d.mkdir(parents=True, exist_ok=True)
        for h in [n.host for n in self.nodes] + [self.dash_host]:
            (d / f"{h.name}-journal.txt").write_text(h.run("journalctl --no-pager -u 'exp-*' -n 600 2>&1").stdout)
        (d / "lanctl-status.json").write_text(self.lanctl("status"))
        try:
            (d / "webhooks.jsonl").write_text("\n".join(json.dumps(r) for r in self.hook_records()))
        except E2EError:
            pass


# ------------------------------------------------------------------------------------------ SSE
def read_sse(base: str, fp: str, cookie: str, query: str, seconds: float) -> list[tuple[str, dict[str, Any]]]:
    """Read the dashboard's `stream` for `seconds`; returns [(event, data)] (keepalives dropped). TLS is pinned to
    the dashboard's certificate fingerprint (checked by hand: urllib has no pin)."""
    host = base.removeprefix("https://")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, 443), timeout=10)
    s = ctx.wrap_socket(raw, server_hostname=host)
    try:
        der = s.getpeercert(binary_form=True)
        if not der or not tlspin.pins_match(der, [fp]):
            raise E2EError("dashboard certificate does not match the pin")
        s.sendall((f"GET /api/v1/stream?{query} HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n"
                   "Accept: text/event-stream\r\nConnection: close\r\n\r\n").encode())
        s.settimeout(1.0)
        buf = b""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                chunk = s.recv(65536)
            except TimeoutError:
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    if b" 200 " not in head.split(b"\r\n", 1)[0]:
        raise E2EError(f"stream refused: {head[:200]!r}")
    events: list[tuple[str, dict[str, Any]]] = []
    for block in body.decode("utf-8", "replace").split("\n\n"):
        ev, data = "message", ""
        for ln in block.splitlines():
            if ln.startswith("event:"):
                ev = ln[6:].strip()
            elif ln.startswith("data:"):
                data += ln[5:].strip()
        if data:
            try:
                events.append((ev, json.loads(data)))
            except ValueError:
                continue
    return events


# ------------------------------------------------------------------------------------------ configs
def collector_config(n: Node, board_url: str) -> dict[str, Any]:
    cfg = L.make_collector_config(n.host.ip, n.probe)
    cfg.update(collector_id=n.cid, site=n.site)
    cfg["probes"] = [{"probe_id": n.probe, "site": n.site, "label": n.label}]
    cfg["dashboards"] = [DASHBOARD_ID]
    cfg["alerts"].update(board_url=board_url, webhook_allow=[NET_IP], **n.alerts)
    return cfg


def dashboard_config(dash_ip: str, nodes: list[Node]) -> dict[str, Any]:
    cfg = L.make_dashboard_config(dash_ip, nodes[0].host.ip, nodes[0].fp)
    cfg.update(dashboard_id=DASHBOARD_ID, title="HPE EXP - M3 lab")
    cfg["collectors"] = [{"collector_id": n.cid, "site": n.site, "url": n.url, "tls_fingerprint_sha256": n.fp} for n in nodes]
    return cfg


def probe_config(n: Node) -> dict[str, Any]:
    cfg = L.make_probe_config(n.probe, n.url, n.fp)
    cfg["site"] = n.site
    for p in cfg["ports"]:
        p["dhcp"]["hostname"] = f"exp-{n.host.name}-{p['id']}"          # unique per probe (two probes share a LAN)
    return cfg


# ------------------------------------------------------------------------------------------ bring-up
def bring_up(release: L.Release, work: Path, log_dir: Path) -> Multi:
    r = sh([str(HARNESS / "harness.sh"), "up", "multisite"], timeout=600)
    if r.returncode != 0:
        raise E2EError(f"harness up multisite failed: {(r.stderr or r.stdout)[-1500:]}")
    nodes = [Node(L.Host(d["host"], f"{PREFIX}-{d['host']}", f"{BASE}.{d['oct']}"), d["cid"], d["site"], d["probe"],
                  d["label"], d["lan"], dict(d["alerts"])) for d in NODES]
    dash_host = L.Host(DASH_HOST, f"{PREFIX}-{DASH_HOST}", f"{BASE}.{DASH_OCT}")
    m = Multi(release, nodes, dash_host, secrets.token_urlsafe(18), log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    for n in nodes:
        n.ingest_token, n.dash_token = exp_ids.new_token("expi"), exp_ids.new_token("expd")
        n.hook_secret = secrets.token_urlsafe(24)

    def prep(h: L.Host) -> None:
        h.ok("mkdir -p /etc/exp /root/dist")
        h.put(release.pubkey, "/etc/exp/release-pub.pem")
        sh(["docker", "cp", f"{release.dist}/.", f"{h.container}:/root/dist"], check=True)
        h.put(HARNESS / "install-manual.sh", "/root/install-manual.sh")

    def install(host: L.Host, shape: str, config: dict[str, Any], creds: dict[str, str], *flags: str) -> str:
        conf = work / f"conf-{host.name}-{shape}"
        shutil.rmtree(conf, ignore_errors=True)
        L.write_conf(conf, shape, config, creds)
        host.ok("rm -rf /root/exp-conf")
        sh(["docker", "cp", str(conf), f"{host.container}:/root/exp-conf"], check=True)
        out = host.ok(f"/root/install-manual.sh {' '.join(flags)} --conf /root/exp-conf /root/dist {shape} 2>&1", timeout=420)
        (log_dir / "install").mkdir(parents=True, exist_ok=True)
        (log_dir / "install" / f"{host.name}-{shape}.log").write_text(out)
        return out

    def fingerprint(out: str, shape: str) -> str:
        mm = re.search(rf"^FINGERPRINT {shape} (\S+)$", out, re.M)
        if not mm:
            raise E2EError(f"the installer printed no {shape} fingerprint:\n{out[-600:]}")
        return mm.group(1)

    with cf.ThreadPoolExecutor(len(nodes) + 1) as ex:
        list(ex.map(prep, [n.host for n in nodes] + [dash_host]))

        def install_collector(n: Node) -> None:
            hooks = [{"id": f, "format": f, "url": m.hook_url(n, f)} for f in HOOK_FORMATS]
            out = install(n.host, "collector", L.validated(collector_config(n, m.dashboard_url), "collector.config.schema.json"),
                          {"ingest_tokens.json": json.dumps({n.probe: exp_ids.token_hash(n.ingest_token)}),
                           "dashboard_tokens.json": json.dumps({DASHBOARD_ID: exp_ids.token_hash(n.dash_token)}),
                           "webhooks.json": json.dumps(hooks)})
            n.fp = fingerprint(out, "collector")

        list(ex.map(install_collector, nodes))              # collectors first: the dashboard and the probes pin them

        def install_probe(n: Node) -> None:
            install(n.host, "probe", L.validated(probe_config(n), "probe.config.schema.json"),
                    {"ingest_token": n.ingest_token}, "--no-start")

        probes = [ex.submit(install_probe, n) for n in nodes]
        out = install(dash_host, "dashboard", L.validated(dashboard_config(dash_host.ip, nodes), "dashboard.config.schema.json"),
                      {"collector_tokens.json": json.dumps({n.cid: n.dash_token for n in nodes}),
                       "sso_secret": base64.b64encode(secrets.token_bytes(32)).decode(),
                       "local_users.json": json.dumps([{"username": USER, "role": L.ROLE, "hash": hash_password(m.password)}]),
                       "noc_tokens.json": "[]"})
        m.dash_fp = fingerprint(out, "dashboard")
        for f in probes:
            f.result()
    return m


def tear_down() -> None:
    sh([str(HARNESS / "harness.sh"), "down"], timeout=240)


# ------------------------------------------------------------------------------------------ small helpers
def line_states(state: dict[str, Any]) -> dict[str, str]:
    return {ln["key"]: ln["state"] for ln in state["lines"]}


def all_green(items: list[dict[str, Any]], probes: list[str]) -> bool:
    by = {i["probe"]: i for i in items}
    return all(p in by and by[p]["severity"] == "ok" and {ln["key"]: ln["state"] for ln in by[p]["lines"]}.keys() >= set(LINES)
               and all(ln["state"] == "ok" for ln in by[p]["lines"]) for p in probes)


# ------------------------------------------------------------------------------------------ time + browser
def iso(epoch: float) -> str:
    import datetime
    t = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (int(epoch * 1000) % 1000)


def parse_iso(s: str) -> float:
    import datetime
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


BOARD_JS = HERE.parent / "m1" / "board.js"


def board(m: Multi, path: str, shot: Path, tag: str, width: int = 1280, height: int = 900) -> dict[str, Any]:
    """Open a dashboard page in Chromium (Playwright, signed in as the local operator); returns title/text/errors."""
    import subprocess
    env = {**os.environ, "EXP_E2E_USER": USER, "EXP_E2E_PASSWORD": m.password}
    shot.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["node", str(BOARD_JS), m.dashboard_url, path, str(shot), str(width), str(height)],  # noqa: S603,S607
                       capture_output=True, text=True, env=env, timeout=120, cwd=str(REPO), check=False)
    try:
        out = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise E2EError(f"{tag}: board.js printed no JSON (rc={r.returncode}): {r.stdout[-300:]} {r.stderr[-500:]}") from None
    if "error" in out:
        raise E2EError(f"{tag}: board.js failed: {out['error']}")
    return out
