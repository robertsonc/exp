"""App experience: scripted transactions scored as Apdex samples.

Each app is a short transaction run from the client namespace through its
DHCP-learned resolver, as a phone would. Step kinds:
  http  curl GET; sample = time to first byte (DNS + TCP + TLS + server)
  tls   TCP connect and TLS handshake to host:port; sample = handshake complete
  tcp   TCP connect to host:port; sample = connected
A multi-step app scores its slowest step. Against the app's T:
  satisfied <= T (ok), tolerating <= 4T (degraded), frustrated > 4T or any error (fail).
A connectivity check that gets the wrong answer is classed `portal`.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time

from . import config as C
from . import events

QUIC_NOTE = "untested: this curl build has no HTTP/3, so QUIC fallback is not measured"


def _http(step, timeout, ua):
    url = step["url"]
    want_body = "expect_body" in step
    fd, body_path = tempfile.mkstemp(prefix="exm-body-")
    os.close(fd)
    try:
        r = subprocess.run(["curl", "-sS", "--compressed", "-A", ua, "--max-time", str(timeout),
                            "-o", body_path, "-w", "%{json}"] + (["-k"] if step.get("insecure") else []) + [url],
                           capture_output=True, text=True, timeout=timeout + 5)
        try:
            j = json.loads(r.stdout) if r.stdout.strip() else {}
        except json.JSONDecodeError:
            j = {}
        body = ""
        if want_body:
            with open(body_path, "rb") as fh:
                body = fh.read(65536).decode("utf-8", "replace")
    finally:
        os.unlink(body_path)

    nl, co, ap = j.get("time_namelookup", 0), j.get("time_connect", 0), j.get("time_appconnect", 0)
    st, tt = j.get("time_starttransfer", 0), j.get("time_total", 0)
    after_handshake = ap or co
    res = {"kind": "http", "target": url, "http_code": j.get("http_code"),
           "http_version": j.get("http_version"), "remote_ip": j.get("remote_ip"),
           "phase_ms": {"dns": events.ms(nl), "connect": events.ms(max(co - nl, 0)),
                        "tls": events.ms(max(ap - co, 0)) if ap else None,
                        "ttfb": events.ms(max(st - after_handshake, 0)) if st else None,
                        "total": events.ms(tt)},
           "sample_ms": events.ms(st) if st else None, "error": None, "portal": False}
    code = j.get("http_code") or 0
    exitcode = j.get("exitcode", r.returncode)
    if exitcode != 0 or not code:
        res["error"] = j.get("errormsg") or (r.stderr.strip()[:200] or f"curl exit {r.returncode}")
    elif code >= 500:
        res["error"] = f"HTTP {code}"
    if "require_status" in step and code and code != int(step["require_status"]) and not res["error"]:
        res["error"] = f"HTTP {code}, need {step['require_status']}"      # an error, not a portal
    if "expect_status" in step and code and code != int(step["expect_status"]):
        res["portal"] = True
        res["error"] = res["error"] or f"expected HTTP {step['expect_status']}, got {code}"
    if want_body and code and step["expect_body"].lower() not in body.lower():
        res["portal"] = True
        res["error"] = res["error"] or f"response did not contain {step['expect_body']!r}"
    return res


def _ping(step, timeout):
    host = step["host"]
    res = {"kind": "ping", "target": host, "phase_ms": {}, "sample_ms": None, "error": None,
           "portal": False, "remote_ip": host}
    r = subprocess.run(["ping", "-n", "-q", "-c", "5", "-i", "0.2", "-W", "1", host],
                       capture_output=True, text=True, timeout=timeout + 5)
    m = re.search(r"([\d.]+)% packet loss", r.stdout)
    loss = float(m.group(1)) if m else 100.0
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", r.stdout)
    res["loss_pct"] = loss
    if m:
        res["phase_ms"] = {"min": float(m.group(1)), "avg": float(m.group(2)), "max": float(m.group(3)),
                           "mdev": float(m.group(4))}
        res["sample_ms"] = float(m.group(2))
    if loss >= 100.0:
        res["error"] = "no ping replies"
    elif loss > 0:
        res["error"] = f"{loss:g}% ping loss"
    return res


def _server_apps(cfg: dict) -> list[dict]:
    """One app per server port, testing exactly what Marvis Minis tests: ping, and HTTP(S) returning 200."""
    t_ms = float(cfg["apps"].get("lab_server_t_ms", 100))
    out = []
    for srv in C.servers(cfg):
        ip = srv["address"].split("/")[0]
        out.append({"name": f"lab-server-{srv['id']}", "t_ms": t_ms, "steps": [
            {"kind": "ping", "host": ip},
            {"kind": "http", "url": f"http://{ip}:{srv.get('http_port', 80)}/", "require_status": 200},
            {"kind": "http", "url": f"https://{ip}:{srv.get('https_port', 443)}/", "require_status": 200,
             "insecure": True},
        ]})
    return out


def _sock(step, timeout, tls):
    host, port = step["host"], int(step["port"])
    res = {"kind": "tls" if tls else "tcp", "target": f"{host}:{port}", "phase_ms": {},
           "sample_ms": None, "error": None, "portal": False, "remote_ip": None}
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        t_dns = time.perf_counter()
        res["phase_ms"]["dns"] = events.ms(t_dns - t0)
        addr = infos[0][4]
        res["remote_ip"] = addr[0]
        s = socket.create_connection(addr, timeout=timeout)
        t_conn = time.perf_counter()
        res["phase_ms"]["connect"] = events.ms(t_conn - t_dns)
        try:
            if tls:
                ctx = ssl.create_default_context()
                ss = ctx.wrap_socket(s, server_hostname=host)
                t_tls = time.perf_counter()
                res["phase_ms"]["tls"] = events.ms(t_tls - t_conn)
                res["tls_version"] = ss.version()
                res["sample_ms"] = events.ms(t_tls - t0)
                ss.close()
            else:
                res["sample_ms"] = events.ms(t_conn - t0)
                s.close()
        finally:
            try:
                s.close()
            except OSError:
                pass
    except Exception as exc:
        res["error"] = f"{type(exc).__name__}: {exc}"
    return res


def run(cfg: dict, client: dict) -> None:
    a = cfg["apps"]
    timeout = float(a.get("timeout_s", 10))
    ua = a.get("user_agent", "exm-probe")
    for app in list(a.get("app", [])) + _server_apps(cfg):
        ev = events.make(cfg, client, "app", target=app["name"])
        t_ms = float(app.get("t_ms", 1000))
        steps = []
        for step in app.get("steps", []):
            kind = step.get("kind", "http")
            if kind == "http":
                steps.append(_http(step, timeout, ua))
            elif kind == "ping":
                steps.append(_ping(step, timeout))
            elif kind in ("tls", "tcp"):
                steps.append(_sock(step, timeout, tls=(kind == "tls")))
            else:
                steps.append({"kind": kind, "target": None, "error": f"unknown step kind {kind}",
                              "phase_ms": {}, "sample_ms": None, "portal": False})
        portal = any(s["portal"] for s in steps)
        errors = [s["error"] for s in steps if s["error"]]
        samples = [s["sample_ms"] for s in steps if s["sample_ms"] is not None]
        sample = max(samples) if samples else None
        if portal:
            cls, outcome = "frustrated", C.PORTAL
        elif errors or sample is None:
            cls, outcome = "frustrated", C.FAIL
        elif sample <= t_ms:
            cls, outcome = "satisfied", C.OK
        elif sample <= 4 * t_ms:
            cls, outcome = "tolerating", C.DEGRADED
        else:
            cls, outcome = "frustrated", C.FAIL
        ev["outcome"] = outcome
        ev["phase_ms"] = {"sample": sample}
        ev["value"] = {"apdex_class": cls, "t_ms": t_ms, "sample_ms": sample, "steps": steps}
        if app.get("quic"):
            ev["value"]["quic"] = QUIC_NOTE
        if errors:
            ev["error"] = "; ".join(errors)[:300]
        events.emit(cfg, ev, f"app {client['id']} {app['name']} outcome={outcome} apdex={cls} "
                             f"sample={sample}ms T={int(t_ms)}ms" + (f" error={ev['error']}" if errors else ""))
