"""Helpers for A3.3 (manager unreachable): the M2 control-plane stack (manager under `wrangler dev`, throwaway CA, local
Access issuer) plus ONE agent-managed Ubuntu systemd host that runs collector + dashboard + probe, enrolled through the
real one-liner, with the alerts' webhooks pointing at a local https receiver (the harness' webhook_receiver.py).

The M2 helpers (m2lib: admin API wrappers, host status, records) are reused as they are; the manager/stack fixture is
composed here from expharness (not imported from test/e2e/m2/conftest.py: two conftests cannot share one session
fixture, and the two stacks must be able to coexist in one pytest run, so every name/port here is its own).
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE.parent / "m2"))
sys.path.insert(0, str(HERE.parent / "m1"))
sys.path.insert(0, str(REPO / "test" / "harness"))

import m2lib  # noqa: E402  (the M2 helpers: admin API wrappers, host status, records)
from exp_dashboard.auth import hash_password  # noqa: E402
from expharness import dockerhost, hostsfile  # noqa: E402
from expharness.access import AccessIssuer, JwksServer  # noqa: E402
from expharness.manager import AdminClient, ManagerDev, free_port  # noqa: E402
from expharness.pki import make_pki  # noqa: E402

import m1lib as L  # noqa: E402  (puts shared/python and the dashboard package on sys.path)

TAG = f"m3c-{os.getpid()}"
SLOT = os.environ.get("EXP_E2E_SLOT_M3", "")           # distinct from the M2 suite's slot: both can run side by side
MANAGER_NAME = f"exp-manager-m3{SLOT}.test"
TEAM_DOMAIN = f"access-m3{SLOT}.exp-e2e.test"
JWKS_BIND = f"127.0.0.{90 + int(SLOT or 0)}"
HOOK_NAME = f"hooks-m3{SLOT}.exp-e2e.test"             # a public-looking name: the manager refuses private/.local/.lan hosts
AUD = "e2e-access-aud-m3-0123456789abcdef"
OWNER = "owner@e2e.test"
SITE = "outage-e2e"
USER = "operator"
BEAT_S = 10                                            # heartbeat interval of the probe intent below
ARTIFACTS_ROOT = Path(os.environ.get("EXP_E2E_ARTIFACTS") or tempfile.gettempdir()) / "m3"
OUTAGE_S = float(os.environ.get("EXP_M3_MANAGER_OUTAGE_S", "1800"))


class E2EError(AssertionError):
    pass


# ------------------------------------------------------------------------------------------ the manager stack
@dataclass
class ManagerStack:
    tmp: Path
    artifacts: Path
    mgr: ManagerDev
    issuer: AccessIssuer
    jwks: JwksServer
    admin: AdminClient
    version: str
    ca_pem: str
    dist: Path
    pub: Path

    def token(self, email: str = OWNER) -> str:
        return self.issuer.mint(email)


@contextlib.contextmanager
def manager_stack(dist: Path, pub: Path, artifacts: Path) -> Iterator[ManagerStack]:
    """wrangler dev + local Access issuer + the signed release published into the local D1/R2."""
    tmp = Path(tempfile.mkdtemp(prefix="exp-e2e-m3c-"))
    artifacts.mkdir(parents=True, exist_ok=True)
    pki = make_pki(tmp / "pki", [MANAGER_NAME, TEAM_DOMAIN], ["127.0.0.1", JWKS_BIND])
    issuer = AccessIssuer(tmp / "access", TEAM_DOMAIN, AUD)
    mgr = ManagerDev(tmp, host=MANAGER_NAME, team_domain=TEAM_DOMAIN, aud=AUD, owner_email=OWNER, ca_pem=pki.ca_pem,
                     cert=pki.cert, key=pki.key, release_pubkey=pub)
    hosts = hostsfile.HostsEntries({MANAGER_NAME: "127.0.0.1", TEAM_DOMAIN: JWKS_BIND}, tag=TAG)
    jwks = JwksServer(issuer.key.jwks, pki.cert, pki.key, JWKS_BIND)
    try:
        hosts.__enter__()
        jwks.start()
        mgr.prepare()
        pr = mgr.publish_release(dist, pub)
        if pr.returncode != 0:
            raise E2EError(f"publish-release.sh --local failed: {(pr.stdout + pr.stderr)[-800:]}")
        mgr.start()
        version = sorted(p.name for p in dist.glob("exp-*-manifest.json"))[0].split("-")[1]
        admin = AdminClient(mgr, lambda: issuer.mint(OWNER))
        yield ManagerStack(tmp, artifacts, mgr, issuer, jwks, admin, version, pki.ca_text, dist, pub)
    finally:
        mgr.stop()
        with contextlib.suppress(OSError):
            shutil.copy(mgr.log_path, artifacts / "wrangler-dev.log")
        jwks.stop()
        hosts.__exit__(None, None, None)
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------------------------------ webhook receiver
class HookReceiver:
    """test/harness/net/webhook_receiver.py on the runner host (reachable from the containers as `host-gateway`),
    with a certificate from its OWN throwaway CA (installed in the managed host's trust store only)."""

    def __init__(self, work: Path) -> None:
        self.work = work
        self.port = free_port()
        self.pki = make_pki(work / "hooks-pki", [HOOK_NAME], ["127.0.0.1"])
        self.log = work / "webhooks.jsonl"
        self.log.write_text("")
        self.proc: subprocess.Popen[bytes] | None = None

    @property
    def url(self) -> str:
        return f"https://{HOOK_NAME}:{self.port}/hook/json/e2e-secret-{os.getpid()}"

    def start(self) -> None:
        self.proc = subprocess.Popen(  # noqa: S603
            [sys.executable, str(REPO / "test" / "harness" / "net" / "webhook_receiver.py"), "--cert", str(self.pki.cert),
             "--key", str(self.pki.key), "--bind", "0.0.0.0", "--port", str(self.port), "--log", str(self.log),
             "--mode-file", str(self.work / "hooks.mode")],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        ctx = ssl.create_default_context(cafile=str(self.pki.ca_pem))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                import http.client
                c = http.client.HTTPSConnection("127.0.0.1", self.port, context=_noverify(ctx), timeout=3)
                c.request("GET", "/_health")
                if c.getresponse().status == 200:
                    return
            except OSError:
                time.sleep(0.3)
        raise E2EError("the webhook receiver did not start")

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.proc.wait(10)
            self.proc.kill()

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(ln) for ln in self.log.read_text().splitlines() if ln.strip()]

    def pages(self, since: float = 0.0) -> list[dict[str, Any]]:
        out = []
        for rec in self.records():
            if rec["ts"] >= since:
                out.append({"seq": rec["seq"], "ts": rec["ts"], "doc": json.loads(rec["body"])})
        return sorted(out, key=lambda p: p["seq"])


def _noverify(ctx: ssl.SSLContext) -> ssl.SSLContext:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def page_kind(p: dict[str, Any]) -> str:
    """down | again | flapping | back (the JSON webhook's own `kind`; everything that is not a failure is a recovery)."""
    k = str(p["doc"]["kind"])
    return k if k in ("down", "again", "flapping", "folded") else "back"


# ------------------------------------------------------------------------------------------ the managed site
@dataclass
class Site:
    host: dockerhost.Host
    host_id: str
    ids: dict[str, str]
    cids: dict[str, str]
    manager_ip: str = ""
    dash_password: str = ""
    notes: dict[str, Any] = field(default_factory=dict)
    _dash: Any = None

    # -- component endpoints (facts reported by the agent)
    def comp_facts(self, stack: ManagerStack, typ: str) -> dict[str, Any]:
        return m2lib.comp_row(stack, self.host_id, typ).get("facts") or {}

    def collector(self, stack: ManagerStack) -> tuple[str, int, str, dict[str, str]]:
        cf = self.comp_facts(stack, "collector")
        ip, port = cf["listen"].rsplit(":", 1)
        tok = json.loads(self.host.run("cat $(find /etc/exp/dashboard -name collector_tokens.json | head -1)").out)
        return ip, int(port), cf["tls_fingerprint_sha256"], {"Authorization": f"Bearer {tok[self.ids['collector']]}"}

    def dash(self, stack: ManagerStack, fresh: bool = False) -> Any:
        if self._dash is None or fresh:
            df = self.comp_facts(stack, "dashboard")
            base = str(df["url"]).rstrip("/")
            self._dash = L.Dash(base, df["tls_fingerprint_sha256"], USER, self.dash_password)
        return self._dash

    # -- the outage: drop every packet to the manager from this host (the manager itself keeps running and keeps its state)
    def block_manager(self, port: int) -> None:
        ip = self.manager_ip
        # SYNs are counted separately (rule 1: counts, then falls through) so that the number of connection attempts is
        # observable; the DROP rules kill new and established flows alike (a real outage: timeouts, not resets)
        r = self.host.run(
            f"iptables -w -N EXP_MGR_OUT 2>/dev/null; iptables -w -F EXP_MGR_OUT && "
            f"iptables -w -A EXP_MGR_OUT -p tcp --syn && iptables -w -A EXP_MGR_OUT -j DROP && "
            f"iptables -w -I OUTPUT 1 -d {ip} -p tcp --dport {port} -j EXP_MGR_OUT")
        if r.rc != 0:
            raise E2EError(f"cannot block the manager: {r}")

    def unblock_manager(self, port: int) -> None:
        ip = self.manager_ip
        self.host.run(f"while iptables -w -D OUTPUT -d {ip} -p tcp --dport {port} -j EXP_MGR_OUT 2>/dev/null; do :; done; "
                      "iptables -w -F EXP_MGR_OUT 2>/dev/null; iptables -w -X EXP_MGR_OUT 2>/dev/null; true")

    def manager_syns(self) -> int:
        out = self.host.run("iptables -w -L EXP_MGR_OUT -v -n -x 2>/dev/null | awk 'NR==3 {print $1}'").out.strip()
        return int(out) if out.isdigit() else 0

    # -- the LAN fault: the LAN's DNS stops answering (dnsmasq stays up; DHCP and the gateway are fine)
    def block_dns(self) -> None:
        r = self.host.run("ip netns exec lan iptables -w -I INPUT 1 -p udp --dport 53 -j DROP && "
                          "ip netns exec lan iptables -w -I INPUT 1 -p tcp --dport 53 -j DROP")
        if r.rc != 0:
            raise E2EError(f"cannot block the LAN's DNS: {r}")

    def restore_dns(self) -> None:
        self.host.run("ip netns exec lan iptables -w -F INPUT")

    # -- observation
    def unit_snapshot(self) -> dict[str, dict[str, str]]:
        """Every active exp-* service: main pid, restart count, when it entered `active`."""
        names = self.host.run(
            "systemctl list-units 'exp-*.service' --state=active --plain --no-legend --no-pager | awk '{print $1}'").out.split()
        snap: dict[str, dict[str, str]] = {}
        for u in names:
            out = self.host.run(f"systemctl show {u} -p MainPID -p NRestarts -p ActiveEnterTimestampMonotonic").out
            snap[u] = dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)
        return snap

    def desired_hash(self) -> str:
        return self.host.run("sha256sum /var/lib/exp/agent/desired.json | cut -d' ' -f1").out.strip()

    def probe_config(self) -> dict[str, Any]:
        return json.loads(self.host.read("/etc/exp/probe/config.json"))


def probe_intent(dns_interval_s: int = 300) -> dict[str, Any]:
    """The wizard's default probe intent, pointed at the test LAN (no external targets); only the DNS test's period varies."""
    names = list(dockerhost.LAN_NAMES)
    return {
        "mode": "netns",
        "heartbeat": {"interval_s": BEAT_S, "gateway": True, "dhcp": True, "dns": True, "ping": [dockerhost.LAN_GW],
                      "dns_names": names,
                      # the traceroute target is the LAN gateway too: the lab has no internet, so the default target
                      # (8.8.8.8) would be a real 'internet is down' incident and page from the start
                      "trace": {"target": dockerhost.LAN_GW, "control_path": False}},
        "tests": {"dhcp": {"interval_s": 300}, "dns": {"interval_s": dns_interval_s, "names": names},
                  "app": None, "throughput": None, "path": None, "wifi": None},
    }


def provision_site(stack: ManagerStack, hooks: HookReceiver, converge_s: float = 420) -> Site:
    """Site with webhook alerts, one host with collector + dashboard + probe, enrolled by the real one-liner, converged."""
    admin = stack.admin
    m2lib.set_site(stack, SITE, SITE)
    admin.call("PATCH", f"/sites/{SITE}/release", {"version": stack.version}, ok=(200,))
    r = admin.call("PUT", f"/sites/{SITE}/alerts", {
        "config": {"enabled": True, "voice": "plain", "hold_down_s": 20, "hold_back_s": 60, "reopen_s": 300, "calm_s": 600,
                   "webhook_allow": [HOOK_NAME]},
        "webhooks": [{"format": "json", "url": hooks.url}]})
    if r.status != 200:
        raise E2EError(f"PUT sites/{SITE}/alerts -> {r.status} {r.text[:400]}")
    ids = {"collector": "col-outage", "dashboard": "das-outage", "probe": "pro-outage"}
    comps = {
        "collector": (ids["collector"], {"retention": {"metrics_days": 30, "records_days": 7}}),
        "dashboard": (ids["dashboard"], {"title": "HPE EXP - outage", "auth": {"session_hours": 12, "local_users": True,
                                                                                  "noc_tokens": True},
                                         "tls": {"mode": "self_signed"}}),
        "probe": (ids["probe"], probe_intent()),
    }
    host_id, enrol, cids = m2lib.create_host(stack, SITE, "e2e-outage", comps)
    try:
        host = dockerhost.Host("a33", {MANAGER_NAME: "host-gateway", HOOK_NAME: "host-gateway"}, stack.ca_pem)
    except (dockerhost.SystemdUnavailable, RuntimeError) as exc:
        raise E2EError(f"cannot start the managed host: {exc}") from exc
    site = Site(host, host_id, ids, cids)
    try:
        host.write("/usr/local/share/ca-certificates/exp-e2e-hooks-ca.crt", hooks.pki.ca_text)
        r2 = host.run("update-ca-certificates", timeout=60)
        assert r2.rc == 0, r2
        dockerhost.build_lan(host)
        inst = host.run(enrol["command"], timeout=600)
        if inst.rc != 0:
            raise E2EError(f"the one-liner failed: {inst}")
        m2lib.wait_for(lambda: (h := m2lib.host_row(stack, host_id))["facts"] and h["facts"].get("interfaces") and h,
                       120, 2, "host facts", host)
        rr = admin.call("PUT", f"/components/{cids['probe']}/ports", {"ports": [{"id": "c01", "iface": "vp0", "role": "client"}]})
        if rr.status != 200:
            raise E2EError(f"PUT ports -> {rr.status} {rr.text[:300]}")
        m2lib.wait_for(lambda: m2lib.components_ok(stack, host_id, tuple(ids)), converge_s, 3, "all shapes healthy", host)
        # a local operator for the dashboard (the manager's SSO handoff is not available while it is unreachable)
        site.dash_password = "pw-" + os.urandom(9).hex()
        admin.post(f"/dashboards/{cids['dashboard']}/users",
                   {"username": USER, "role": "operator", "hash": hash_password(site.dash_password)}, ok=(201,))
        site.manager_ip = _manager_ip(host)
        return site
    except BaseException:
        host.remove()
        raise


def _manager_ip(host: dockerhost.Host) -> str:
    out = host.run(f"getent hosts {MANAGER_NAME} | awk '{{print $1}}'").out.strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", out):
        raise E2EError(f"the managed host cannot resolve {MANAGER_NAME}: {out!r}")
    return out


# ------------------------------------------------------------------------------------------ records
def epoch(ts: str) -> float:
    from datetime import datetime
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def beats(site: Site, coll: tuple[str, int, str, dict[str, str]], t0: float, t1: float) -> list[dict[str, Any]]:
    """The probe's heartbeat gateway records (one per beat) stored in the collector, oldest first."""
    return sorted(m2lib.fetch_records(coll, site.ids["probe"], t0, t1, "gateway"), key=lambda x: x["ts"])


def max_gap(rows: list[dict[str, Any]], t0: float, t1: float) -> float:
    ts = sorted([epoch(x["ts"]) for x in rows if t0 <= epoch(x["ts"]) <= t1] + [t0, t1])
    return max(b - a for a, b in zip(ts, ts[1:], strict=False))


def expected_attempts(outage_s: float, connect_s: float = 10.0, lo: float = 30.0, hi: float = 300.0) -> int:
    """Upper bound on the agent's connection attempts in an outage of `outage_s` (06-agent.md section 2: back off 30 s -> 5 min;
    each failed attempt also costs the connect timeout). The first attempt may already be in flight."""
    t, n, cur = 0.0, 0, 0.0
    while t < outage_s:
        n += 1
        cur = lo if cur <= 0 else min(hi, cur * 2)
        t += connect_s + cur
    return n


def wait_until(fn, timeout: float, step: float, what: str, diag=None) -> Any:  # noqa: ANN001
    return dockerhost.wait_for(fn, timeout, step, what, diag)

