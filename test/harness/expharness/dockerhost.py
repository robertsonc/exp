"""Docker systemd hosts for the end-to-end suites (the host under test is a plain Ubuntu systemd container)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import subprocess
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .manager import REPO, clean_env

HERE = Path(__file__).resolve().parent
TOKEN_RE = re.compile(r"exp[aeidn]_[A-Za-z0-9_-]{8,}")


def sh(argv: list[str], *, timeout: float = 120, input_: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        argv, capture_output=True, text=True, timeout=timeout, input=input_, check=False, env=clean_env()
    )


def docker_unavailable() -> str | None:
    try:
        r = sh(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"docker is not usable: {exc}"
    return None if r.returncode == 0 else f"docker daemon is not reachable: {(r.stderr or r.stdout).strip()[:200]}"


_image_cache: dict[str, str | None] = {}


def ensure_image(ubuntu: str = "24.04") -> str | None:
    """Build exp-e2e-host:<ubuntu> (None on success, else the reason it cannot be built)."""
    tag = f"exp-e2e-host:{ubuntu}"
    if tag in _image_cache:
        return _image_cache[tag]
    reason: str | None = None
    base = f"exp-agent-systemd:{ubuntu}"
    try:
        if sh(["docker", "image", "inspect", base], timeout=30).returncode != 0:
            r = sh(
                [
                    "docker",
                    "build",
                    "-q",
                    "--build-arg",
                    f"UBUNTU={ubuntu}",
                    "-t",
                    base,
                    str(REPO / "agent" / "tests" / "container"),
                ],
                timeout=900,
            )
            if r.returncode != 0:
                reason = f"cannot build {base}: {(r.stderr or r.stdout).strip()[-300:]}"
        if reason is None:
            r = sh(
                [
                    "docker",
                    "build",
                    "-q",
                    "--build-arg",
                    f"BASE={base}",
                    "-t",
                    tag,
                    "-f",
                    str(HERE / "docker" / "Dockerfile.host"),
                    str(HERE / "docker"),
                ],
                timeout=900,
            )
            if r.returncode != 0:
                reason = f"cannot build {tag}: {(r.stderr or r.stdout).strip()[-300:]}"
    except subprocess.TimeoutExpired:
        reason = f"building {tag} timed out"
    _image_cache[tag] = reason
    return reason


class SystemdUnavailable(Exception):
    """systemd cannot run as PID 1 in this docker environment."""


class ExecResult:
    def __init__(self, rc: int, out: str, err: str) -> None:
        self.rc, self.out, self.err = rc, out, err

    @property
    def text(self) -> str:
        return self.out + self.err

    def __repr__(self) -> str:
        return f"ExecResult(rc={self.rc}, out={self.out[-800:]!r}, err={self.err[-800:]!r})"


class Host:
    """A systemd-as-PID-1 Ubuntu container. `add_hosts` maps names to IPs (or docker's host-gateway)."""

    def __init__(self, label: str, add_hosts: dict[str, str], ca_pem: str, ubuntu: str = "24.04") -> None:
        self.name = f"exp-e2e-{label}-{os.getpid()}-{uuid.uuid4().hex[:5]}"
        argv = ["docker", "run", "-d", "--name", self.name, "--hostname", f"e2e-{label}"]
        for n, ip in add_hosts.items():
            argv += ["--add-host", f"{n}:{ip}"]
        argv += [
            "--privileged",
            "--cgroupns=host",
            "-v",
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            f"exp-e2e-host:{ubuntu}",
        ]
        r = sh(argv, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"docker run failed: {(r.stderr or r.stdout).strip()[:300]}")
        self._wait_booted()
        # systemd builds LoadCredential= directories in a helper mount namespace and MS_MOVEs them into place; that
        # only reaches the service when / is a shared mount, which it is on a VM but not in a container. Without
        # this units start with a missing $CREDENTIALS_DIRECTORY (a property of the container, not of the product).
        r0 = self.run("mount --make-rshared /", timeout=30)
        assert r0.rc == 0, r0
        self.write("/usr/local/share/ca-certificates/exp-e2e-ca.crt", ca_pem)
        r2 = self.run("update-ca-certificates", timeout=60)
        assert r2.rc == 0, r2

    def _wait_booted(self, timeout: float = 90) -> None:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            last = self.run("systemctl is-system-running", timeout=15).text.strip()
            if last in ("running", "degraded"):
                return
            time.sleep(1)
        logs = sh(["docker", "logs", "--tail", "15", self.name], timeout=20)
        self.remove()
        raise SystemdUnavailable(
            f"systemd did not reach running/degraded in {timeout:.0f}s (is-system-running: {last!r}); "
            f"log: {(logs.stdout + logs.stderr).strip()[-400:]}"
        )

    @property
    def ip(self) -> str:
        r = sh(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                self.name,
            ],
            timeout=30,
        )
        return r.stdout.strip()

    def remove(self) -> None:
        sh(["docker", "rm", "-f", self.name], timeout=60)

    def run(self, cmd: str, *, user: str | None = None, timeout: float = 120) -> ExecResult:
        argv = ["docker", "exec", "-i", *(["-u", user] if user else []), self.name, "bash", "-c", cmd]
        try:
            r = sh(argv, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            return ExecResult(124, "", f"timed out after {timeout}s: {exc}")
        return ExecResult(r.returncode, r.stdout, r.stderr)

    def write(self, path: str, text: str) -> None:
        r = sh(["docker", "exec", "-i", self.name, "bash", "-c", f"cat > {path}"], timeout=30, input_=text)
        assert r.returncode == 0, r.stderr

    def read(self, path: str) -> str:
        r = self.run(f"cat {path}")
        assert r.rc == 0, r
        return r.out

    def agent_log(self, n: int = 60) -> str:
        return self.run(f"journalctl -u exp-agent --no-pager -o cat -n {n}", timeout=30).out

    def journal(self, unit: str | None = None, n: int = 60) -> str:
        u = f"-u {unit}" if unit else ""
        return self.run(f"journalctl {u} --no-pager -o cat -n {n}", timeout=30).out

    def diagnostics(self) -> str:
        parts = [
            "== agent ==\n" + self.agent_log(40),
            "== units ==\n" + self.run("systemctl list-units 'exp-*' --all --no-pager | head -30").out,
            "== failed ==\n" + self.run("systemctl --failed --no-pager | head -20").out,
        ]
        for u in ("exp-collector", "exp-victoriametrics", "exp-dashboard", "exp-probe"):
            parts.append(f"== {u} ==\n" + self.journal(u, 20))
        return "\n".join(parts)


def wait_for(
    fn: Callable[[], Any],
    timeout: float,
    interval: float = 2.0,
    what: str = "condition",
    diag: Callable[[], str] | None = None,
) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while True:
        try:
            last = fn()
        except (AssertionError, OSError, ssl.SSLError, ValueError, KeyError) as exc:
            last = exc
        else:
            if last:
                return last
        if time.monotonic() >= deadline:
            extra = ""
            if diag is not None:
                try:
                    extra = "\n--- diagnostics ---\n" + diag()
                except Exception as exc:  # noqa: BLE001 - diagnostics must never mask the real failure
                    extra = f"\n(diagnostics failed: {exc})"
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {what} (last: {last!r}){extra}")
        time.sleep(interval)


# ---- the test LAN for the probe's client port (a DHCP/DNS server in a network namespace)
LAN_GW = "10.99.0.1"
LAN_NAMES = {"host-a.lab.test": "10.99.0.9", "host-b.lab.test": "10.99.0.10"}


def build_lan(host: Host, port_iface: str = "vp0") -> None:
    """veth `port_iface` (root namespace: the probe's client port) <-> `lan0` in netns `lan` (10.99.0.1/24,
    dnsmasq: DHCP 10.99.0.50-80 with router + resolver = the gateway, a few A records)."""
    addrs = " ".join(f"--address=/{n}/{ip}" for n, ip in LAN_NAMES.items())
    script = f"""set -e
ip netns add lan
ip link add {port_iface} type veth peer name lan0
ip link set lan0 netns lan
ip -n lan addr add {LAN_GW}/24 dev lan0
ip -n lan link set lan0 up
ip -n lan link set lo up
ip link set {port_iface} up
systemd-run --quiet --unit=e2e-lan-dnsmasq ip netns exec lan dnsmasq --no-daemon --user=root \\
  --interface=lan0 --bind-interfaces --except-interface=lo --no-hosts --no-resolv \\
  --dhcp-leasefile=/run/e2e-lan.leases --dhcp-range=10.99.0.50,10.99.0.80,10m \\
  --dhcp-option=3,{LAN_GW} --dhcp-option=6,{LAN_GW} --local=/invalid/ {addrs}
sleep 1
systemctl is-active e2e-lan-dnsmasq
"""
    r = host.run(script, timeout=60)
    assert r.rc == 0, f"cannot build the test LAN: {r}"


def fingerprint_of_der(der: bytes) -> str:
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i : i + 2] for i in range(0, 64, 2))


def pinned_request(
    ip: str,
    port: int,
    method: str,
    path: str,
    fingerprint: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, list[str]], bytes]:
    """HTTPS request to a self-signed component, accepting only the certificate with the given SHA-256
    fingerprint (the pin the manager compiles into every consumer). Returns (status, headers (multi), body)."""
    import http.client

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(ip, port, context=ctx, timeout=20)
    try:
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
        got = fingerprint_of_der(der)
        if got != fingerprint.upper():
            raise AssertionError(f"certificate fingerprint {got} != pinned {fingerprint}")
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        hdrs: dict[str, list[str]] = {}
        for k, v in r.getheaders():
            hdrs.setdefault(k.lower(), []).append(v)
        return r.status, hdrs, r.read()
    finally:
        conn.close()


def pinned_get(ip: str, port: int, path: str, fingerprint: str, headers: dict[str, str] | None = None):
    return pinned_request(ip, port, "GET", path, fingerprint, headers)


def jget(*a: Any, **kw: Any) -> Any:
    st, _h, body = pinned_get(*a, **kw)
    assert st == 200, f"{a[2]} -> {st} {body[:200]!r}"
    return json.loads(body)
