"""`app` (scheduled) -- 02-probe.md 5.7: an HTTP(S) transaction measured like a user's browser sees it.

``curl -w '%{json}'`` (curl >= 7.81) run through the command runner as an argv list INSIDE the port's
namespace (``ip netns exec``; host mode: ``--interface``): redirects followed (max 5), 15 s max, body
discarded after counting bytes. Phase times follow EXM: dns = namelookup, connect = connect - namelookup,
tls = appconnect - connect, ttfb = starttransfer - (appconnect or connect). The TLS version comes from
curl's verbose log (the JSON has none).

Apdex per target (T = `apdex_t_ms`, default 500): satisfied (total <= T) 1.0, tolerating (<= 4T) 0.5,
frustrated 0.0 -- computed on `total_ms`. Outcome: curl error, HTTP >= 500, status 0 or a captive portal
-> fail; HTTP 4xx, ``total_ms > 4T`` or ``apdex < 0.85`` -> degraded (both configurable in
`tests.app.thresholds`: `slow_factor`, `apdex_min`); else ok.

Captive portal detection: a known connectivity-check endpoint (``*/generate_204``, ``*/gen_204``,
captive.apple.com, msftconnecttest.com, detectportal.firefox.com, or a target's own `expect_status` /
`expect_body`) that does not return what it always returns is a portal intercepting the request
(redirect or HTTP 200 with portal content). Also: a plain-http target redirected to another
registrable domain. Recorded as ``detail.captive_portal`` + ``captive_reason`` and the outcome is `fail`.
A lease's RFC 8910 captive-portal URI (DHCP option 114) is carried in ``detail.dhcp_captive_portal_uri``.

Ported from reference/exm/lib/exm/apps.py (`_http`, `run`).
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from exp_common.schema import Measurement

from .. import __version__
from ..scheduler import TestContext, register_test
from .common import clip, error_record, num, port_info, thresholds

log = logging.getLogger(__name__)

CURL_MAX_TIME_S = 15
CURL_CONNECT_S = 10
MAX_REDIRS = 5
BODY_LIMIT = 64 * 1024
DEFAULT_T_MS = 500.0
_URL_OK = re.compile(r"https?://[^\s\x00-\x1f]+\Z")
_TLS_V = re.compile(r"SSL connection using (TLSv[0-9.]+|SSLv[0-9.]+)")
_TLS_V2 = re.compile(r"\b(TLSv1\.[0-3])\b")
# (host suffix, path, expected status, expected body substring)
KNOWN_CHECKS: tuple[tuple[str, str, int, str | None], ...] = (
    ("captive.apple.com", "/hotspot-detect.html", 200, "Success"),
    ("msftconnecttest.com", "/connecttest.txt", 200, "Microsoft Connect Test"),
    ("detectportal.firefox.com", "/success.txt", 200, "success"),
)


@dataclass
class CurlResult:
    ok: bool                       # curl itself succeeded (exit 0)
    exitcode: int = 0
    error: str | None = None
    status: int = 0
    dns_ms: float | None = None
    connect_ms: float | None = None
    tls_ms: float | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None
    bytes: int = 0
    remote_ip: str | None = None
    url_effective: str | None = None
    num_redirects: int = 0
    tls_version: str | None = None
    scheme: str = ""


def _ms(v: Any) -> float | None:
    return round(float(v) * 1000.0, 2) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def curl_argv(url: str, body_path: str, ua: str, iface: str | None) -> list[str]:
    argv = ["curl", "-sS", "-v", "-L", "--max-redirs", str(MAX_REDIRS), "--max-time", str(CURL_MAX_TIME_S),
            "--connect-timeout", str(CURL_CONNECT_S), "--noproxy", "*", "-A", ua, "-o", body_path,
            "-w", "%{json}"]
    if iface:
        argv += ["--interface", iface]
    return argv + ["--url", url]


def parse_curl(stdout: str, stderr: str, rc: int) -> CurlResult:
    """Parse curl's `-w '%{json}'` (+ verbose stderr). Never raises: unparseable output is an error."""
    j: dict[str, Any] = {}
    txt = (stdout or "").strip()
    if txt:
        try:
            doc = json.loads(txt[txt.index("{"):]) if "{" in txt else {}
            j = doc if isinstance(doc, dict) else {}
        except ValueError:
            j = {}
    exitcode = j.get("exitcode", rc)
    exitcode = exitcode if isinstance(exitcode, int) else rc
    status = j.get("response_code", j.get("http_code", 0))
    status = status if isinstance(status, int) and not isinstance(status, bool) else 0
    timed = isinstance(j.get("time_total"), (int, float)) and not isinstance(j.get("time_total"), bool)
    res = CurlResult(ok=exitcode == 0 and timed, exitcode=exitcode, status=status)
    nl, co, ap = (j.get(k) or 0 for k in ("time_namelookup", "time_connect", "time_appconnect"))
    st, tt = j.get("time_starttransfer") or 0, j.get("time_total")
    if all(isinstance(x, (int, float)) for x in (nl, co, ap, st)):
        after = ap or co
        res.dns_ms = _ms(nl)
        res.connect_ms = _ms(max(co - nl, 0)) if co else None
        res.tls_ms = _ms(max(ap - co, 0)) if ap else None
        res.ttfb_ms = _ms(max(st - after, 0)) if st else None
    res.total_ms = _ms(tt)
    size = j.get("size_download")
    res.bytes = size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else 0
    res.remote_ip = clip(j.get("remote_ip"), 64) if j.get("remote_ip") else None
    res.url_effective = clip(j.get("url_effective"), 500) if j.get("url_effective") else None
    nr = j.get("num_redirects")
    res.num_redirects = nr if isinstance(nr, int) and not isinstance(nr, bool) else 0
    res.scheme = str(j.get("scheme") or "").lower()
    m = _TLS_V.search(stderr or "")
    res.tls_version = m.group(1) if m else (m2.group(1) if (m2 := _TLS_V2.search(stderr or "")) else None)
    if not res.ok:
        lines = [ln for ln in (stderr or "").splitlines() if ln.startswith("curl:")]
        msg = j.get("errormsg") or (lines[-1][5:].strip() if lines else "")
        if not msg:
            msg = f"curl exit {exitcode}" if exitcode else "curl produced no result"
        res.error = clip(msg, 300)
    return res


def apdex(total_ms: float | None, t_ms: float) -> float:
    if total_ms is None:
        return 0.0
    return 1.0 if total_ms <= t_ms else (0.5 if total_ms <= 4 * t_ms else 0.0)


def _registrable(host: str) -> str:
    parts = host.lower().rstrip(".").split(".")
    return host if len(parts) <= 2 or all(p.isdigit() for p in parts) else ".".join(parts[-2:])


def expectation(url: str, target: dict[str, Any]) -> tuple[int | None, str | None]:
    """(expected status, expected body substring) for a known connectivity-check URL or an explicit config."""
    exp_status = target.get("expect_status")
    exp_body = target.get("expect_body")
    if isinstance(exp_status, int) or isinstance(exp_body, str):
        return (exp_status if isinstance(exp_status, int) else None,
                exp_body if isinstance(exp_body, str) else None)
    sp = urlsplit(url)
    host, path = (sp.hostname or "").lower(), sp.path
    if path.endswith("/generate_204") or path.endswith("/gen_204"):
        return 204, None
    for suffix, p, status, body in KNOWN_CHECKS:
        if host == suffix or host.endswith("." + suffix):
            if path == p:
                return status, body
    return None, None


def detect_captive(url: str, res: CurlResult, body: str, target: dict[str, Any]) -> str | None:
    """A reason string when the response looks like a captive portal, else None."""
    if not res.status or res.status >= 500 or res.exitcode != 0:
        return None
    sp = urlsplit(url)
    moved = f" (redirected to {clip(res.url_effective, 120)})" if res.num_redirects and res.url_effective else ""
    want_status, want_body = expectation(url, target)
    if want_status is not None and res.status != want_status:
        return f"expected HTTP {want_status}, got {res.status}{moved}"
    if want_status == 204 and res.bytes:
        return f"expected an empty 204, got {res.bytes} bytes{moved}"
    if want_body is not None and want_body.lower() not in body.lower():
        return f"response did not contain {clip(want_body, 40)!r}{moved}"
    if sp.scheme == "http" and res.url_effective and res.num_redirects:
        eff = urlsplit(res.url_effective)
        if eff.hostname and sp.hostname and _registrable(eff.hostname) != _registrable(sp.hostname):
            return f"plain-http request redirected to another site{moved}"
    return None


def run_target(ctx: TestContext, port: Any, target: dict[str, Any], dhcp_portal: str | None) -> Measurement:
    app, url = str(target.get("app", "")), str(target.get("url", ""))
    labels = {"port": port.id, "app": app}
    if not _URL_OK.match(url):
        return error_record(ctx, "app", f"target {clip(app, 40)!r} has an invalid url", labels=labels)
    t_ms = float(target.get("apdex_t_ms") or DEFAULT_T_MS)
    want_status, want_body = expectation(url, target)
    need_body = want_body is not None
    fd, body_path = tempfile.mkstemp(prefix="exp-probe-body-") if need_body else (-1, os.devnull)
    if fd >= 0:
        os.close(fd)
    try:
        argv = curl_argv(url, body_path, f"exp-probe/{__version__}", port.lease_iface if ctx.cfg.mode == "host" else None)
        r = ctx.runner.run(ctx.ns_argv(argv), CURL_MAX_TIME_S + 5)
        if r.rc == 127:
            return error_record(ctx, "app", "curl is not installed", labels=labels)
        if r.timed_out:
            return ctx.measure("app", "fail", labels=labels, metrics={"status_code": 0.0, "apdex": 0.0},
                               detail={"url": clip(url)}, error=f"curl did not finish within {CURL_MAX_TIME_S + 5} s")
        body = ""
        if need_body:
            try:
                with open(body_path, "rb") as fh:
                    body = fh.read(BODY_LIMIT).decode("utf-8", "replace")
            except OSError:
                body = ""
    finally:
        if fd >= 0:
            try:
                os.unlink(body_path)
            except OSError:
                pass
    res = parse_curl(r.stdout, r.stderr, r.rc)
    detail: dict[str, Any] = {"url": clip(url), "apdex_t_ms": t_ms}
    if res.remote_ip:
        detail["ip"] = res.remote_ip
    if res.tls_version:
        detail["tls_version"] = res.tls_version
    if res.num_redirects:
        detail["num_redirects"] = res.num_redirects
        if res.url_effective:
            detail["url_effective"] = res.url_effective
    if dhcp_portal:
        detail["dhcp_captive_portal_uri"] = clip(dhcp_portal, 500)
    metrics: dict[str, float] = {"status_code": float(res.status), "bytes": float(res.bytes)}
    for k in ("dns_ms", "connect_ms", "tls_ms", "ttfb_ms", "total_ms"):
        v = getattr(res, k)
        if v is not None:
            metrics[k] = num(v)  # type: ignore[assignment]
    ap = apdex(res.total_ms if res.ok else None, t_ms)
    metrics["apdex"] = ap
    kw: dict[str, Any] = {}
    if res.total_ms is not None:
        kw["duration_ms"] = num(res.total_ms)
    if not res.ok:
        return ctx.measure("app", "fail", labels=labels, metrics=metrics, detail=detail,
                           error=res.error or "request failed", **kw)
    why = detect_captive(url, res, body, target)
    if why:
        detail["captive_portal"] = True
        detail["captive_reason"] = clip(why, 300)
        return ctx.measure("app", "fail", labels=labels, metrics=metrics, detail=detail,
                           error=clip(f"captive portal suspected: {why}", 500), **kw)
    if res.status >= 500 or res.status == 0:
        return ctx.measure("app", "fail", labels=labels, metrics=metrics, detail=detail, error=f"HTTP {res.status}", **kw)
    factor = thresholds(ctx, "app", "slow_factor", 4.0)
    apdex_min = thresholds(ctx, "app", "apdex_min", 0.85)
    error = None
    outcome = "ok"
    if res.status >= 400 and want_status != res.status:
        outcome, error = "degraded", f"HTTP {res.status}"
    elif (res.total_ms or 0) > factor * t_ms:
        outcome, error = "degraded", f"total {res.total_ms:g} ms exceeds {factor:g}x apdex T ({t_ms:g} ms)"
    elif ap < apdex_min:
        outcome, error = "degraded", f"apdex {ap:g} below {apdex_min:g}"
    if error:
        kw["error"] = error
    return ctx.measure("app", outcome, labels=labels, metrics=metrics, detail=detail, **kw)


@register_test("app", roles=("client", "wifi"))
def app(ctx: TestContext) -> list[Measurement]:
    port = ctx.port
    assert port is not None
    targets = (ctx.cfg.tests.get("app") or {}).get("targets") or []
    if not targets:
        return [error_record(ctx, "app", "no app targets configured (tests.app.targets)")]
    info = port_info(ctx, port)
    if ctx.cfg.mode != "host" and not info.bound:
        return [error_record(ctx, "app", f"port {port.id} has no lease", labels={"app": str(targets[0].get("app", ""))})]
    env = ctx.netenv(port)
    if not env.exists():
        return [error_record(ctx, "app", f"namespace for port {port.id} is missing",
                             labels={"app": str(targets[0].get("app", ""))})]
    return [run_target(ctx, port, t, info.captive_portal_uri) for t in targets]
