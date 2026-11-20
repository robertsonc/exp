"""Helpers for the M6 "core" acceptance suite (SPEC.md section 9 / 12-speedtest-analytics.md section 11, A6.x).

The harness layout `core` (test/harness/harness.sh up core): ONE all-in-one box `core` (probe + collector + runner + speedtest
+ dashboard) installed from a REAL signed release with test/harness/install-manual.sh, on a ROUTED core segment
(10.9.0.0/24, box 10.9.0.10) that the attendee VLAN (10.1.0.0/24, DHCP from the LAN dnsmasq) reaches through the gateway
without NAT; the gateway's resolver delegates t.speed.exp.test to the box; the fake Cloudflare speed server answers
speed.cloudflare.com (https, throwaway CA trusted by pin only); fake Mist + fake Orchestrator on the management network.

The attendee is Playwright Chromium (390 x 844 phone emulation) inside a client network namespace on the event bridge
(`Client`). Docker resources use their own prefix/subnet (expm6, 172.30.46.0/24) so the suite runs beside the others.
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
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

os.environ.setdefault("EXP_HARNESS_PREFIX", "expm6")
os.environ.setdefault("EXP_HARNESS_SUBNET", "172.30.46.0/24")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "m1"))
sys.path.insert(0, str(HERE.parents[1] / "fakes"))

import syslog_sender as ss  # noqa: E402  (test/fakes: the syslog generators/senders the runner's receiver is tested with)
import m1lib as L  # noqa: E402  (Host, Dash, Stack, wait_for, configs; puts shared/python + dashboard on sys.path)
from exp_common import ids as exp_ids  # noqa: E402
from exp_common import tlspin  # noqa: E402
from exp_dashboard.auth import hash_password  # noqa: E402

REPO, HARNESS = L.REPO, L.HARNESS
E2EError, wait_for, sh = L.E2EError, L.wait_for, L.sh
ARTIFACTS = Path(os.environ.get("EXP_E2E_ARTIFACTS", str(L.ARTIFACTS))) / "m6"
PREFIX = os.environ["EXP_HARNESS_PREFIX"]
BASE = os.environ["EXP_HARNESS_SUBNET"].rsplit(".", 1)[0]
NET_IP = f"{BASE}.2"
MGMT_IP = f"{BASE}.11"                # the box on the management network (collector, dashboard)
CORE_IP = "10.9.0.10"                 # the box on the core segment (speedtest page, DNS-leg authority)
GW_CORE = "10.9.0.1"
EDGE_LAN = "10.255.1.2"               # the edge's gateway-side address (path.edge)
ZONE = "t.speed.exp.test"
SITE = "hall-b"
RELEASE_VERSION = "0.2.0"
SPEEDTEST_ID, RUNNER_ID, DASHBOARD_ID = "spd-core", "run-core", "dash-m6"
NOUSER = "e2e-operator"
UI_JS = HERE / "ui" / "core_page.js"
BENCH_PY = HERE / "bench_client.py"


# -------------------------------------------------------------------------------------------- release
def find_release(tmp: Path) -> L.Release:
    """EXP_E2E_DIST + EXP_E2E_PUBKEY name a signed release; otherwise build 0.2.0 with a throwaway key (or the key in
    EXP_RELEASE_KEY / EXP_RELEASE_PUBKEY) with packaging/build.sh."""
    if os.environ.get("EXP_E2E_DIST") and os.environ.get("EXP_E2E_PUBKEY"):
        return L.find_release(tmp)
    key, pub, out = tmp / "release.pem", tmp / "release-pub.pem", tmp / "dist"
    if os.environ.get("EXP_RELEASE_KEY") and os.environ.get("EXP_RELEASE_PUBKEY"):
        key, pub = Path(os.environ["EXP_RELEASE_KEY"]), Path(os.environ["EXP_RELEASE_PUBKEY"])
    else:
        sh(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True)
        sh(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True)
    env = {**os.environ, "EXP_RELEASE_KEY": str(key), "EXP_RELEASE_PUBKEY": str(pub)}
    r = subprocess.run([str(REPO / "packaging" / "build.sh"), "--release", RELEASE_VERSION, "--out", str(out)],  # noqa: S603
                       capture_output=True, text=True, env=env, timeout=900, check=False)
    if r.returncode != 0:
        raise E2EError(f"packaging/build.sh failed: {(r.stderr or r.stdout)[-800:]}")
    return L.Release(out, pub, RELEASE_VERSION)


# -------------------------------------------------------------------------------------------- the stack
@dataclass
class Core(L.Stack):
    exps: str = ""            # speedtest -> collector token (exps_)
    expr: str = ""            # runner -> collector token (expr_)
    expl: str = ""            # runner -> speedtest channel token (expl_)
    expk: str = ""            # per-org device_key secret (expk_)
    mist_token: str = ""
    ec_key: str = ""
    work: Path = field(default_factory=Path)
    cf_spki: str = ""
    configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    clients: list[Any] = field(default_factory=list)
    base: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def page(self) -> str:
        return f"http://{CORE_IP}"

    # --- reconfiguration of an installed component (what the agent does on a desired-state change)
    def reconfigure(self, shape: str, mutate: Any, schema: str | None = None) -> dict[str, Any]:
        cfg = json.loads(self.col.ok(f"cat /etc/exp/{shape}/config.json"))
        mutate(cfg)
        sch = schema or {"speedtest": "speedtest.config.schema.json", "runner": "runner.config.schema.json",
                         "collector": "collector.config.schema.json"}[shape]
        L.validated(cfg, sch)
        tmp = self.work / f"reconf-{shape}.json"
        tmp.write_text(json.dumps(cfg, indent=1))
        self.col.put(tmp, f"/etc/exp/{shape}/config.json")
        self.col.ok(f"chmod 644 /etc/exp/{shape}/config.json && systemctl restart exp-{shape}.service", timeout=90)
        self.configs[shape] = cfg
        self.wait_healthy(shape)
        return cfg

    def reset_config(self, shape: str) -> None:
        """Back to the config the stack was installed with."""
        import copy
        base = copy.deepcopy(self.base[shape])
        self.reconfigure(shape, lambda cfg: (cfg.clear(), cfg.update(base)))

    def wait_healthy(self, shape: str, timeout: float = 60) -> None:
        def ok() -> bool:
            r = self.col.run(f"CREDENTIALS_DIRECTORY=/etc/exp/{shape}/creds /opt/exp/{shape}/current/bin/exp-{shape} health "
                             f"--json --config /etc/exp/{shape}/config.json")
            return r.returncode == 0
        wait_for(ok, timeout, 1, f"{shape} health")

    def set_credential(self, shape: str, name: str, text: str, restart: bool = True) -> None:
        p = self.work / f"cred-{shape}-{name}"
        p.write_text(text)
        self.col.put(p, f"/etc/exp/{shape}/creds/{name}")
        self.col.ok(f"chmod 600 /etc/exp/{shape}/creds/{name}")
        if restart:
            self.col.ok(f"systemctl restart exp-{shape}.service", timeout=90)
            self.wait_healthy(shape)

    # --- fakes (loopback-only control APIs, driven through lanctl in the net container)
    def fake(self, which: str, method: str, path: str, body: Any = None) -> Any:
        argv = ["fake", which, method, path] + ([json.dumps(body)] if body is not None else [])
        out = self.lanctl(*argv)
        return json.loads(out) if out.strip() else None

    def cf_set(self, **knobs: Any) -> Any:
        return self.fake("cf", "POST", "/_fake/set", knobs)

    def cf_stats(self) -> dict[str, Any]:
        return self.fake("cf", "GET", "/_fake/stats")["stats"]

    # --- the speedtest box and the collector
    def st_status(self) -> dict[str, Any]:
        return json.loads(self.col.ok("cat /run/exp/speedtest/status.json"))

    def tests(self, **params: Any) -> list[dict[str, Any]]:
        r = self.collector_get("speedtests", limit=200, **params)
        return r.get("items") or r.get("tests") or (r if isinstance(r, list) else [])

    def test_detail(self, tid: str, identifiers: bool = False) -> dict[str, Any]:
        return self.collector_get(f"speedtests/{tid}", identifiers="true" if identifiers else None)

    def collector_post(self, path: str, doc: dict[str, Any]) -> tlspin.Response:
        return tlspin.request("POST", f"{self.collector_url}/api/v1/{path}", self.col_fp, body=json.dumps(doc).encode(),
                              headers={"Authorization": f"Bearer {self.dash_token}", "X-Exp-User": L.USER,
                                       "Content-Type": "application/json"})

    def wait_test(self, n: int = 1, timeout: float = 60, **params: Any) -> list[dict[str, Any]]:
        return wait_for(lambda: (len(self.tests(**params)) >= n) and self.tests(**params), timeout, 1, f"{n} stored test(s)")

    def wait_final(self, tid: str, timeout: float = 180) -> dict[str, Any]:
        def fin() -> dict[str, Any] | None:
            d = self.test_detail(tid)
            ev = d.get("evidence_state")
            state = ev.get("state") if isinstance(ev, dict) else ev
            return d if state in ("final", "unavailable") else None
        return wait_for(fin, timeout, 2, f"test {tid} evidence final")

    def run_page(self, phone: Client, **opts: Any) -> tuple[dict[str, Any], str]:
        """A phone runs one test in Chromium; returns (browser result, stored test id)."""
        r = phone.chromium({"url": f"{self.page}/?z=hall-b", **opts})
        subs = r.get("submissions") or []
        if not subs or not (subs[-1].get("res") or {}).get("id"):
            raise E2EError(f"the page submitted no accepted result: {json.dumps(subs)[:600]} hosts={r.get('hosts')} failed={r.get('failed')}")
        return r, subs[-1]["res"]["id"]

    # --- correlation inputs: identity, syslog, final evidence
    def identify(self, phone: Client, scenario: str = "healthy", orch: str = "healthy") -> None:
        """Tell the fake Mist who has the phone's IP (`scenario`, see test/fakes/README.md) and the fake Orchestrator what it saw."""
        self.fake("mist", "POST", "/_fake/reset")
        self.fake("mist", "POST", "/_fake/scenario", {"name": scenario, "ip": phone.ip, "mac": phone.mac})
        self.fake("orch", "POST", "/_fake/scenario", {"name": orch, "client_ip": phone.ip})

    def syslog(self, *lines: str, proto: str = "udp") -> None:
        """Send syslog lines to the runner's receiver (UDP/TCP 5514 on the box's management address; the host is inside the allowlist)."""
        n = ss.send_udp(MGMT_IP, 5514, lines) if proto == "udp" else ss.send_tcp(MGMT_IP, 5514, list(lines), framing="newline")
        if n != len(lines):
            raise E2EError("syslog send was short")

    def final(self, tid: str, timeout: float = 240) -> dict[str, Any]:
        """The test once its evidence is final, with raw identifiers (admin view): {test, diagnosis, evidence[], evidence_state, ...}."""
        self.wait_final(tid, timeout)
        return self.test_detail(tid, identifiers=True)

    def db_hits(self, needle: str, db: str = "/var/lib/exp/collector/records.db") -> dict[str, int]:
        """Rows (per table) of a SQLite database on the box that contain `needle` in ANY column, as text, case-insensitively. An empty
        `needle` matches every row (a sanity check that the scan works at all)."""
        script = (
            "import sqlite3,sys,json\n"
            "n=sys.argv[1].lower(); db=sqlite3.connect('file:'+sys.argv[2]+'?mode=ro',uri=True); out={}\n"
            "for (t,) in db.execute(\"select name from sqlite_master where type='table'\"):\n"
            "    cols=[r[1] for r in db.execute(f'pragma table_info({t})')]\n"
            "    if not cols: continue\n"
            "    q=' or '.join(f'lower(cast({c} as text)) like ?' for c in cols)\n"
            "    k=db.execute(f'select count(*) from {t} where '+q,[f'%{n}%']*len(cols)).fetchone()[0]\n"
            "    if k: out[t]=k\n"
            "print(json.dumps(out))\n")
        out = self.col.ok(f"python3 -c {L._q(script)} {L._q(needle)} {L._q(db)}").strip().splitlines()[-1]
        return json.loads(out)

    def columns(self, db: str = "/var/lib/exp/collector/records.db") -> dict[str, list[str]]:
        script = ("import sqlite3,sys,json\n"
                  "db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)\n"
                  "print(json.dumps({t:[r[1] for r in db.execute(f'pragma table_info({t})')] for (t,) in "
                  "db.execute(\"select name from sqlite_master where type='table'\")}))\n")
        return json.loads(self.col.ok(f"python3 -c {L._q(script)} {L._q(db)}").strip().splitlines()[-1])

    @staticmethod
    def ev(full: dict[str, Any], kind: str) -> dict[str, Any]:
        for e in full["evidence"]:
            if e["kind"] == kind:
                return e
        raise E2EError(f"no {kind} evidence: {[e['kind'] for e in full['evidence']]}")

    @staticmethod
    def causes(full: dict[str, Any]) -> list[str]:
        return [c["id"] for c in full["diagnosis"]["cause"]]

    def cf_default(self) -> None:
        self.cf_set(latency_ms=12, loaded_latency_ms=30, down_bps=400_000_000, up_bps=100_000_000)

    def clean_slate(self) -> None:
        """No fault, no delay, no NAT, the default fake Cloudflare, healthy fakes."""
        self.lanctl("restore")
        self.cf_default()
        self.fake("mist", "POST", "/_fake/reset")
        self.fake("orch", "POST", "/_fake/scenario", {"name": "healthy"})

    # --- clients
    def new_client(self, name: str = "c1", mac: str | None = None, site: int = 1) -> Client:
        c = Client(self, name, mac or "02:cc:%02x:00:00:%02x" % (len(self.clients) + 1, secrets.randbelow(250) + 1), site)
        self.clients.append(c)
        return c

    def save_logs(self, tag: str) -> None:
        d = self.log_dir / tag
        d.mkdir(parents=True, exist_ok=True)
        out = self.col.run("journalctl --no-pager -u 'exp-*' -n 600 2>&1").stdout
        (d / "core-journal.txt").write_text(out)
        (d / "lanctl-status.json").write_text(self.lanctl("status"))
        for f in ("cf", "mist", "orch"):
            r = sh(["docker", "exec", f"{PREFIX}-net", "tail", "-n", "60", f"/var/log/lan/{f}.log"])
            (d / f"fake-{f}.log").write_text(r.stdout)

    def stop_clients(self) -> None:
        for c in self.clients:
            c.close()
        self.clients.clear()


class Client:
    """An attendee device: a network namespace on the event bridge with a DHCP lease from the LAN dnsmasq."""

    def __init__(self, core: Core, name: str, mac: str, site: int = 1) -> None:
        self.core, self.name, self.mac = core, name, mac
        self.proc = subprocess.Popen(["unshare", "-n", "sleep", "infinity"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603,S607
        self.pid = self.proc.pid
        time.sleep(0.2)
        label = f"cl-{name}"[:10]
        core.lanctl("plug", label, "--pid", str(self.pid), "--ifname", "eth0", "--mac", mac, "--site", str(site))
        self.label = label
        lease = json.loads(core.lanctl("client-dhcp", "--pid", str(self.pid), "--ifname", "eth0"))
        self.ip, self.router, self.dns = lease["ip"], lease["router"], lease["dns"]
        self.resolv = core.work / f"resolv-{name}.conf"
        self.resolv.write_text(f"nameserver {self.dns}\n")

    def close(self) -> None:
        try:
            self.core.lanctl("unplug", self.label)
        except E2EError:
            pass
        self.proc.kill()
        self.proc.wait(5)

    # --- run something inside the namespace
    def argv(self, *cmd: str) -> list[str]:
        return ["nsenter", "-t", str(self.pid), "-n", *cmd]

    def run(self, *cmd: str, timeout: float = 60, input_: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(self.argv(*cmd), capture_output=True, text=True, timeout=timeout, input=input_, check=False)  # noqa: S603

    def http(self, method: str, url: str, doc: Any = None, headers: dict[str, str] | None = None, data: bytes | None = None,
             timeout: float = 20) -> dict[str, Any]:
        """One HTTP request from this device (status, lower-cased headers, text body). Never raises on an HTTP error status."""
        snippet = (
            "import json,sys,urllib.request,urllib.error\n"
            "a=json.loads(sys.argv[1])\n"
            "d=None\n"
            "if a.get('json') is not None: d=json.dumps(a['json']).encode()\n"
            "elif a.get('stdin'):\n"
            "    d=sys.stdin.buffer.read()\n"
            "h=dict(a.get('headers') or {})\n"
            "if a.get('json') is not None: h.setdefault('Content-Type','application/json')\n"
            "req=urllib.request.Request(a['url'],data=d,method=a['method'],headers=h)\n"
            "try:\n"
            "    r=urllib.request.urlopen(req,timeout=a['timeout'])\n"
            "except urllib.error.HTTPError as e:\n"
            "    r=e\n"
            "b=r.read(8*2**20)\n"
            "print(json.dumps({'status':r.status if hasattr(r,'status') else r.code,'headers':{k.lower():v for k,v in r.headers.items()},"
            "'body':b.decode('utf-8','replace'),'len':len(b)}))\n")
        arg = {"method": method, "url": url, "json": doc, "headers": headers or {}, "timeout": timeout,
               "stdin": data is not None}
        r = subprocess.run(self.argv("python3", "-I", "-c", snippet, json.dumps(arg)), capture_output=True, timeout=timeout + 15,  # noqa: S603
                           input=data if data is not None else b"", check=False)
        r.stdout, r.stderr = r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
        if r.returncode != 0:
            raise E2EError(f"[{self.name}] http {method} {url} failed: {(r.stderr or r.stdout)[-400:]}")
        out = json.loads(r.stdout.strip().splitlines()[-1])
        try:
            out["json"] = json.loads(out["body"]) if out["body"][:1] in "{[" else None
        except ValueError:
            out["json"] = None
        return out

    def create_session(self, **extra: Any) -> dict[str, Any]:
        """POST /st/api/v1/sessions as this device. The response dict gains `proof` (the X-Exp-View-Proof the page would send)."""
        from exp_common import speedtest as st
        proof = st.view_proof(st.new_view_key(), "st_" + "0" * 26)
        doc = {"consent": {"text_version": 1}, "view_verifier": st.view_verifier(proof), **extra}
        r = self.http("POST", f"{self.core.page}/st/api/v1/sessions", doc)
        r["proof"] = proof
        j = r.get("json") or {}
        r["sid"], r["token"] = j.get("session_id"), j.get("leg_token")
        return r

    def view(self, sess: dict[str, Any], method: str, tail: str, doc: Any = None) -> dict[str, Any]:
        return self.http(method, f"{self.core.page}/st/api/v1/sessions/{sess['sid']}{tail}", doc,
                         headers={"X-Exp-View-Proof": sess["proof"]})

    def leg(self, sess: dict[str, Any], method: str, path: str, **kw: Any) -> dict[str, Any]:
        return self.http(method, f"{self.core.page}{path}", headers={"X-Exp-Leg-Token": sess["token"]}, **kw)

    # --- the phone
    def chromium(self, opts: dict[str, Any], timeout: float = 240, out_dir: Path | None = None) -> dict[str, Any]:
        """Run test/e2e/m6/ui/core_page.js (Playwright Chromium, 390 x 844 phone) inside this namespace, with this device's own
        resolver (resolv.conf bind-mounted in a private mount namespace). Returns the script's @@RESULT document."""
        out_dir = out_dir or (ARTIFACTS / "shots")
        out_dir.mkdir(parents=True, exist_ok=True)
        cfg = {"out": str(out_dir), **opts, "spki": [self.core.cf_spki, *opts.get("spki", [])]}
        cfg_path = self.core.work / f"ui-{self.name}-{int(time.time() * 1000)}.json"
        cfg_path.write_text(json.dumps(cfg))
        env = node_env()
        argv = self.argv("unshare", "-m", "sh", "-c", 'mount --bind "$1" /etc/resolv.conf && shift && exec "$@"', "sh",
                         str(self.resolv), shutil.which("node") or "node", str(UI_JS), str(cfg_path))
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, check=False)  # noqa: S603
        res = None
        for line in p.stdout.splitlines():
            if line.startswith("@@RESULT "):
                res = json.loads(line[9:])
        if res is None:
            raise E2EError("the browser scenario produced no result:\n" + (p.stdout + p.stderr)[-2500:])
        return res


# -------------------------------------------------------------------------------------------- configs
def node_env() -> dict[str, str]:
    """Environment for node: no proxy variables (the agent proxy must never be used) and test/e2e/m1/node_modules (where CI installs
    the pinned Playwright) on NODE_PATH next to a global install."""
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    local = REPO / "test" / "e2e" / "m1" / "node_modules"
    if local.is_dir():
        env["NODE_PATH"] = os.pathsep.join(x for x in (str(local), env.get("NODE_PATH", "")) if x)
    return env


def spki_pin(pem: str) -> str:
    r = sh(["bash", "-c", "openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64"],
           input_=pem, check=True)
    return r.stdout.strip()


def speedtest_config(col_url: str, col_fp: str, **over: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "schema": "exp.speedtest.config/1", "speedtest_id": SPEEDTEST_ID, "site": SITE,
        "zones": [{"id": "hall-a", "name": "Hall A"}, {"id": "hall-b", "name": "Hall B"}, {"id": "hallb-row12", "name": "Hall B, row 12"}],
        "zone_labels": {"subnets": [{"cidr": "10.1.0.0/24", "zone": "hall-b"}]},
        "branding": {"title": "Summit speed check", "languages": ["en"]},
        "consent": {"text": "We measure your speed and look at this device's Wi-Fi and traffic metadata to diagnose it. "
                            "No name or email is collected.", "version": 1},
        "targets": {"down_mbps": 25, "up_mbps": 10},
        "limits": {"tests_per_10min_per_ip": 100, "max_concurrent_per_ip": 2, "max_concurrent_tests": 20,
                   "max_concurrent_internet": 10, "bytes_local": 200000000, "bytes_internet": 200000000,
                   "leg_token_ttl_s": 60, "result_deadline_s": 180},
        "internet_leg": {"enabled": True, "provider": "cloudflare", "paused": False, "auto_pause_wan_util_pct": 80},
        "serve": {"placement": "core", "hostname": CORE_IP, "listen_ip": CORE_IP, "require_real_client_ip": True,
                  "client_subnets": ["10.1.0.0/24"], "translated_addresses": []},
        "tls": {"mode": "none"},
        "dns_leg": {"enabled": True, "zone": ZONE},
        "path": {"gateway": GW_CORE, "edge": EDGE_LAN, "edge1": "auto"},
        "privacy": {"retention_days": 30, "scrub_after_diagnosis": False},
        "core_guard": {"iface": "core0", "util_pct": 70, "min_bytes": 5000000},
        "collector": {"url": col_url, "tls_fingerprint_sha256": col_fp},
        "local_channel": {"listen": "127.0.0.1:8480"},
    }
    cfg.update(over)
    return cfg


def runner_config(col_url: str, col_fp: str, mist_site: str) -> dict[str, Any]:
    return {
        "schema": "exp.runner.config/1", "runner_id": RUNNER_ID, "site": SITE,
        "collector": {"url": col_url, "tls_fingerprint_sha256": col_fp},
        "drills_enabled": False,
        "correlation": {
            "enabled": True, "window_before_s": 300, "window_after_s": 5, "poll_interval_s": 2,
            "sources": {
                "mist": {"sites": [{"site_id": mist_site, "name": "Summit venue"}],
                         "zone_map": [{"zone": "hall-b", "ap_name_prefix": "hallb-ap-"}], "max_calls_per_test": 6, "cache_ttl_s": 5},
                "ec": {"appliances": [{"ne_pk": "1.NE", "hostname": "ec-core", "wan_interfaces": ["wan0"]}], "max_flows": 50,
                       "wan_util": {"enabled": True, "interval_s": 5}},
                "syslog": {"listen": ["udp:5514", "tcp:5514"], "bind": "0.0.0.0", "allow": ["10.0.0.0/8", f"{BASE}.0/24"],
                           "rate_limit_lines_per_s": 200, "max_line_bytes": 4096, "ring_minutes": 60,
                           "tls": {"mode": "self_signed"}},
                "sse": {"enabled": False},
            },
            "privacy": {"scrub_after_diagnosis": False},
            "speedtest_channel": {"url": "http://127.0.0.1:8480/local/v1"},
            "network": {"require_real_client_ip": True, "client_subnets": ["10.1.0.0/24"], "translated_addresses": [],
                        "zone_subnets": [{"cidr": "10.1.0.0/24", "zone": "hall-b"}]},
        },
    }


def collector_config(probe_id: str) -> dict[str, Any]:
    cfg = L.make_collector_config(MGMT_IP, probe_id)
    cfg["alerts"]["enabled"] = False
    cfg["speedtests"] = {"enabled": True, "speedtests": [SPEEDTEST_ID], "runners": [RUNNER_ID], "retention_days": 30,
                         "scrub_after_diagnosis": False, "targets": {"down_mbps": 25, "up_mbps": 10}, "max_evidence_kib": 256,
                         "correlation_window": {"before_s": 300, "after_s": 5}, "finalize_after_s": 40}
    return cfg


# -------------------------------------------------------------------------------------------- bring-up
def bring_up(release: L.Release, work: Path, log_dir: Path) -> Core:
    import mist.server as fake_mist
    import orchestrator.server as fake_orch
    r = sh([str(HARNESS / "harness.sh"), "up", "core"], timeout=420)
    if r.returncode != 0:
        raise E2EError(f"harness up core failed: {(r.stderr or r.stdout)[-1500:]}")
    core_h = L.Host("core", f"{PREFIX}-core", MGMT_IP)
    probe_id = "probe-core"
    st = Core("core", release, core_h, core_h, probe_id, secrets.token_urlsafe(18), work=work)
    st.log_dir = log_dir
    st.log_dir.mkdir(parents=True, exist_ok=True)
    st.ingest_token, st.dash_token = exp_ids.new_token("expi"), exp_ids.new_token("expd")
    st.exps, st.expr, st.expl, st.expk = (exp_ids.new_token(k) for k in ("exps", "expr", "expl", "expk"))
    st.mist_token = fake_mist.default_token()
    st.ec_key = fake_orch.default_credentials()[0]
    ca = sh(["docker", "exec", f"{PREFIX}-net", "cat", "/run/lan/pki/cf.pem"], check=True).stdout
    st.cf_spki = spki_pin(ca)
    core_h.ok("mkdir -p /etc/exp /root/dist")
    core_h.put(release.pubkey, "/etc/exp/release-pub.pem")
    sh(["docker", "cp", f"{release.dist}/.", f"{core_h.container}:/root/dist"], check=True)
    core_h.put(HARNESS / "install-manual.sh", "/root/install-manual.sh")

    def install(shape: str, config: dict[str, Any], creds: dict[str, str], schema: str, *flags: str) -> str:
        conf = work / f"conf-{shape}"
        shutil.rmtree(conf, ignore_errors=True)
        L.write_conf(conf, shape, L.validated(config, schema), creds)
        core_h.ok("rm -rf /root/exp-conf")
        sh(["docker", "cp", str(conf), f"{core_h.container}:/root/exp-conf"], check=True)
        out = core_h.ok(f"/root/install-manual.sh {' '.join(flags)} --conf /root/exp-conf /root/dist {shape} 2>&1", timeout=300)
        (st.log_dir / "install").mkdir(parents=True, exist_ok=True)
        (st.log_dir / "install" / f"{shape}.log").write_text(out)
        st.configs[shape] = config
        return out

    out = install("collector", collector_config(probe_id), {
        "ingest_tokens.json": json.dumps({probe_id: exp_ids.token_hash(st.ingest_token)}),
        "dashboard_tokens.json": json.dumps({DASHBOARD_ID: exp_ids.token_hash(st.dash_token)}),
        "webhooks.json": "[]",
        "speedtest_tokens.json": json.dumps({SPEEDTEST_ID: exp_ids.token_hash(st.exps)}),
        "runner_tokens.json": json.dumps({RUNNER_ID: exp_ids.token_hash(st.expr)}),
        "device_key_secret": st.expk}, "collector.config.schema.json")
    m = re.search(r"^FINGERPRINT collector (\S+)$", out, re.M)
    if not m:
        raise E2EError("no collector fingerprint:\n" + out[-800:])
    st.col_fp = m.group(1)
    mist_site = fake_mist.SITE_ID
    integrations = {"mist": {"api_base": f"https://{NET_IP}:8485", "token": st.mist_token},
                    "ec": {"url": f"https://{NET_IP}:8486", "api_key": st.ec_key}}
    install("runner", runner_config(st.collector_url, st.col_fp, mist_site), {
        "collector_token": st.expr, "device_key_secret": st.expk, "speedtest_channel_token": st.expl,
        "integrations.json": json.dumps(integrations)}, "runner.config.schema.json")
    install("speedtest", speedtest_config(st.collector_url, st.col_fp), {
        "collector_token": st.exps, "runner_channel_token_sha256": exp_ids.token_hash(st.expl)}, "speedtest.config.schema.json")
    dash_cfg = L.make_dashboard_config(MGMT_IP, MGMT_IP, st.col_fp)
    dash_cfg["dashboard_id"] = DASHBOARD_ID
    # all-in-one: the speedtest owns TCP 80 on the core address, so the dashboard binds the management address only
    # (a wildcard 0.0.0.0:80 redirect listener would collide; see CR-m6-e1-core-layout)
    dash_cfg["listen"] = {"https": f"{MGMT_IP}:443", "http_redirect": f"{MGMT_IP}:80"}
    out = install("dashboard", dash_cfg, {
        "collector_tokens.json": json.dumps({L.COLLECTOR_ID: st.dash_token}),
        "sso_secret": base64.b64encode(secrets.token_bytes(32)).decode(),
        "local_users.json": json.dumps([{"username": L.USER, "role": L.ROLE, "hash": hash_password(st.password)}]),
        "noc_tokens.json": "[]"}, "dashboard.config.schema.json")
    m = re.search(r"^FINGERPRINT dashboard (\S+)$", out, re.M)
    if not m:
        raise E2EError("no dashboard fingerprint:\n" + out[-800:])
    st.dash_fp = m.group(1)
    install("probe", L.make_probe_config(probe_id, st.collector_url, st.col_fp), {"ingest_token": st.ingest_token},
            "probe.config.schema.json", "--no-start")
    core_h.ok("install -d -m 0755 /var/lib/exp/probe")
    st.start_probe()
    # the fake Cloudflare as a real service: some latency, some bandwidth limits (knobs of the fake, see test/fakes/README.md)
    import copy
    st.base = copy.deepcopy(st.configs)
    st.cf_set(latency_ms=12, loaded_latency_ms=30, down_bps=400_000_000, up_bps=100_000_000)
    save_state(st)
    return st


STATE_KEYS = ("password", "col_fp", "dash_fp", "ingest_token", "dash_token", "exps", "expr", "expl", "expk", "mist_token", "ec_key",
              "cf_spki", "probe_id")


def save_state(st: Core) -> None:
    """Dev aid: EXP_E2E_REUSE=1 re-attaches to a still-running stack (EXP_E2E_KEEP=1) instead of rebuilding it. The file holds
    throwaway test credentials of a lab stack; it lives in the artifacts folder, never in the repository."""
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "core-state.json").write_text(json.dumps({**{k: getattr(st, k) for k in STATE_KEYS}, "base": st.base}))


def attach(release: L.Release, work: Path, log_dir: Path) -> Core | None:
    f = ARTIFACTS / "core-state.json"
    if not f.exists() or sh(["docker", "inspect", "-f", "{{.State.Running}}", f"{PREFIX}-core"]).stdout.strip() != "true":
        return None
    d = json.loads(f.read_text())
    core_h = L.Host("core", f"{PREFIX}-core", MGMT_IP)
    st = Core("core", release, core_h, core_h, d["probe_id"], d["password"], work=work)
    for k in STATE_KEYS:
        setattr(st, k, d[k])
    st.log_dir = log_dir
    st.log_dir.mkdir(parents=True, exist_ok=True)
    for shape in ("speedtest", "runner", "collector"):
        st.configs[shape] = json.loads(core_h.ok(f"cat /etc/exp/{shape}/config.json"))
    st.base = d["base"]
    return st


def tear_down() -> None:
    sh([str(HARNESS / "harness.sh"), "down"], timeout=180)
