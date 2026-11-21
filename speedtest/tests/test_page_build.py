"""The page build: deterministic, hashed for the CSP, within budget, free of unsafe constructs, fonts and library pinned."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import re
from pathlib import Path

from exp_speedtest.static import STATIC_DIR, StaticSite, inline_hashes

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "speedtest" / "page"
spec = importlib.util.spec_from_file_location("exp_page_build", PAGE / "build.py")
build_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_mod)
HTML = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
ENGINE = (STATIC_DIR / "assets" / "cf-engine.js").read_text(encoding="utf-8")
LOCAL = (STATIC_DIR / "assets" / "local-leg.js").read_text(encoding="utf-8")       # the on-network transfer's worker file
FONTS = sorted((STATIC_DIR / "assets").glob("*.woff2"))


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_build_is_deterministic_and_the_committed_output_is_fresh(tmp_path):
    a, b = build_mod.build(), build_mod.build()
    assert a == b and a["index.html"].encode() == (STATIC_DIR / "index.html").read_bytes()
    assert a["csp-hashes.json"].encode() == (STATIC_DIR / "csp-hashes.json").read_bytes()
    build_mod.write(tmp_path / "x")
    build_mod.write(tmp_path / "y")
    assert a["assets/cf-engine.js"].encode() == (STATIC_DIR / "assets" / "cf-engine.js").read_bytes()
    assert a["assets/local-leg.js"].encode() == (STATIC_DIR / "assets" / "local-leg.js").read_bytes()
    for rel in ("index.html", "csp-hashes.json", "assets/cf-engine.js", "assets/local-leg.js", "assets/archivo.woff2", "assets/OFL-inter.txt"):
        assert (tmp_path / "x" / rel).read_bytes() == (tmp_path / "y" / rel).read_bytes()
        assert (tmp_path / "x" / rel).read_bytes() == (STATIC_DIR / rel).read_bytes(), rel


def test_on_network_transfer_has_one_implementation_in_the_worker_file():
    """CR-m6-speedtest-server item 26 follow-up: the transfer (src/local-leg.js) exists once, in assets/local-leg.js, which runs as
    the dedicated worker or, as the fallback, as a classic script on the page; the inline page has no copy of it. The file
    uses only what a dedicated worker has (no document, window, localStorage) and nothing that evaluates strings."""
    src = build_mod.tidy_js((PAGE / "src" / "local-leg.js").read_text(encoding="utf-8"))
    bridge = build_mod.tidy_js((PAGE / "src" / "local-bridge.js").read_text(encoding="utf-8"))
    assert LOCAL == src + "\n" + bridge + "\n" and LOCAL.count("async function transferLeg(") == 1
    for marker in ("transferLeg", "getReader", "XMLHttpRequest", "/st/down", "/st/up", "ExpLocalLeg.transfer(m.dir"):
        assert marker not in HTML, marker                    # the page only hosts it (LocalHost), it never carries a copy
    assert "ExpLocalLeg" in HTML and "'/st/assets/local-leg.js'" in HTML
    code = re.sub(r"/\*.*?\*/", "", LOCAL, flags=re.S)       # comments may name what the file must not touch
    for bad in ("document", "window", "localStorage", "sessionStorage", "innerHTML", "eval(", "new Function", "importScripts",
                "setTimeout('", 'setTimeout("'):
        assert bad not in code, bad
    # the algorithm's fixed points (CR-m6-speedtest-server item 26 follow-up; the browser tests check the behaviour)
    for want in ("lim.streams_start || 4", "Math.min(lim.streams_max || 8, MAX_STREAMS_H1)", "MAX_STREAMS_H1 = 5", "minB = 100000",
                 "Math.min(25000000, lim.ramp_max_bytes || 25000000)", "T.size * 4", "el0 >= 8000", "after >= 8", "percentile(post, 0.9)",
                 "r.status === 413", "'X-Exp-Leg-Token'", "cache: 'no-store', credentials: 'omit'", "}, 250);"):
        assert want in code, want


def test_csp_hashes_match_the_built_inline_blocks():
    doc = json.loads((STATIC_DIR / "csp-hashes.json").read_text())
    scripts, styles = inline_hashes(HTML)
    assert doc == {"schema": "exp.speedtest.csp/1", "script": scripts, "style": styles}
    assert len(scripts) == 1 and len(styles) == 1
    csp = StaticSite(None, "none", STATIC_DIR / "assets").build_csp(scripts, styles)
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_no_inline_handlers_style_attributes_or_third_party_hosts():
    markup = HTML.split("<script>")[0]
    assert not re.search(r"\son[a-z]+\s*=", markup), "inline event handler in markup"
    assert not re.search(r"<[a-z][^>]*\sstyle=", markup, re.I), "style attribute in markup (blocked by CSP)"
    hosts = set(re.findall(r"https?://([a-zA-Z0-9.-]+)", HTML))
    assert hosts <= {"speed.cloudflare.com"}, hosts
    assert "var CFSpeedTest = " not in HTML and "class SpeedTestEngine" not in HTML and "var SpeedTestEngine" not in HTML, \
        "the engine library is in the worker file only, never inlined twice"
    assert "w3.org" not in HTML and "github.com" not in HTML, "no foreign URL, split or not"
    app = build_mod.tidy_js((PAGE / "src" / "app.js").read_text())
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert bad not in app, bad
    assert "logAimApiUrl: null" in app, "results must never be posted to Cloudflare"
    for hdr in ("cf-meta-ip", "cf-meta-city", "cf-meta-latitude"):
        assert hdr not in app
    assert not re.search(r"headers\.(get|has|entries|forEach)\(", app.replace("r.headers.get('Retry-After'", "")), "only Retry-After is read from headers"
    assert "/cdn-cgi/trace" in app and "colo=" in app


def test_page_weight_budget():
    gz = sum(len(gzip.compress(t.encode(), 9)) for t in (HTML, ENGINE, LOCAL))     # the two worker files count
    fonts = sum(p.stat().st_size for p in FONTS)
    assert fonts <= 120 * 1024, fonts
    assert gz + fonts <= 200 * 1024, (gz, fonts)
    assert {p.name for p in FONTS} == {"archivo.woff2", "inter.woff2", "jetbrains-mono.woff2"}
    for name in ("archivo", "inter", "jetbrains-mono"):
        assert "SIL OPEN FONT LICENSE" in (STATIC_DIR / "assets" / f"OFL-{name}.txt").read_text()


def test_vendored_files_match_vendor_lock():
    lock = json.loads((ROOT / "packaging" / "vendor.lock").read_text())
    items = {i["name"]: i for i in lock["committed_sources"]["items"]}
    assert set(items) == {"@cloudflare/speedtest", "archivo-subset", "inter-subset", "jetbrains-mono-subset"}
    for it in items.values():
        assert sha(ROOT / it["file"]) == it["sha256"], it["name"]
        assert (ROOT / it["license_file"]).is_file() and len(it["archive_sha256"]) == 64
    cf = items["@cloudflare/speedtest"]
    assert cf["version"] == "1.16.0" and cf["archive_sha256"] == "08e3c0b4e69a2533dc0f4bca3e88e063c4fbc3c3b4e5c301557c1dcf767e866e"
    assert "Copyright (c) 2023 Cloudflare" in ENGINE
    lib = (ROOT / cf["file"]).read_text(encoding="utf-8").replace("\r\n", "\n")
    body = lib.replace(build_mod.LIB_EXPORT, "return SpeedTestEngine;")
    body = re.sub(r"\n//# sourceMappingURL=\S+\s*\Z", "\n", body).strip()
    assert ENGINE.count(body) == 1, "the vendored library is embedded verbatim, exactly once, in the engine file"


def _lum(h: str) -> float:
    c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4 for v in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def ratio(a: str, b: str) -> float:
    x, y = sorted((_lum(a), _lum(b)), reverse=True)
    return (x + 0.05) / (y + 0.05)


def test_colour_tokens_meet_wcag_aa():
    css = (PAGE / "src" / "style.css").read_text()
    blocks = re.findall(r":root[^{]*\{([^}]*)\}", css)
    themes = [b for b in blocks if "--bg:" in b]
    assert len(themes) >= 3
    for blk in themes:
        t = dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6})", blk))
        if "fg" not in t:
            continue
        for fg in ("fg", "muted", "faint", "down", "down-2", "up", "ok", "warn", "crit"):
            for bg in ("bg", "surface", "surface-2"):
                assert ratio(t[fg], t[bg]) >= 4.5, (fg, bg, ratio(t[fg], t[bg]))


def test_served_page_and_fonts(box):
    r = box.get("/")
    assert r.status == 200 and r.body == HTML.encode()
    scripts, styles = inline_hashes(HTML)
    for h in scripts + styles:
        assert f"'{h}'" in r.h("content-security-policy")
    csp = r.h("content-security-policy")
    assert "worker-src 'self'" in csp and "script-src 'sha256-" in csp and "' 'self';" in csp and "blob:" not in csp and "data:" not in csp.replace("img-src 'self' data:", "")
    page_connect = next(d for d in csp.split("; ") if d.startswith("connect-src "))
    for path, text in (("/st/assets/cf-engine.js", ENGINE), ("/st/assets/local-leg.js", LOCAL)):
        e = box.get(path)
        assert e.status == 200 and e.body == text.encode() and e.h("content-type") == "text/javascript; charset=utf-8", path
        assert e.h("x-content-type-options") == "nosniff" and e.h("cache-control") == "public, max-age=300", path
        assert e.h("cross-origin-resource-policy") == "same-origin" and e.h("referrer-policy") == "no-referrer", path
        ecsp = e.h("content-security-policy")
        assert ecsp == f"default-src 'none'; {page_connect}; frame-ancestors 'none'", (path, ecsp)
    for other in ("app.js", "local-bridge.js", "engine-bridge.js", "x.js"):
        assert box.get(f"/st/assets/{other}").status == 404, other      # an allowlist of worker files, not "any .js"
    for p in FONTS:
        a = box.get(f"/st/assets/{p.name}")
        assert a.status == 200 and a.h("content-type") == "font/woff2" and a.body == p.read_bytes()


def test_page_contacts_only_the_box_and_cloudflare():
    """A6.10 statically, three independent guards (the runtime capture is test_page_browser.py::test_full_test_390):
    1. our code names no host but speed.cloudflare.com; the only other absolute-URL forms are the vendored library's
       own `https://${...}` templates, kept verbatim (never rewritten to dodge a check);
    2. those templates belong to engines the page never runs: the internet plan only has latency/download/upload and
       the library's result/measurement logging is disabled;
    3. the CSP connect-src allows only the box, the DNS-leg names and https://speed.cloudflare.com."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    app = (root / "page" / "src" / "app.js").read_text(encoding="utf-8")
    lib = (root / "page" / "vendor" / "speedtest.js").read_text(encoding="utf-8")
    html = (root / "exp_speedtest" / "static" / "index.html").read_text(encoding="utf-8")
    engine = (root / "exp_speedtest" / "static" / "assets" / "cf-engine.js").read_text(encoding="utf-8")
    brg = (root / "page" / "src" / "engine-bridge.js").read_text(encoding="utf-8")
    local = (root / "exp_speedtest" / "static" / "assets" / "local-leg.js").read_text(encoding="utf-8")

    # 1. concrete hosts
    hosts = {u.split("//", 1)[1] for u in re.findall(r"https?://[A-Za-z0-9][A-Za-z0-9.-]*", html)}
    assert hosts <= {"speed.cloudflare.com"}, sorted(hosts)
    ours = {u.split("//", 1)[1] for u in re.findall(r"https?://[A-Za-z0-9][A-Za-z0-9.-]*", app)}
    assert ours <= {"speed.cloudflare.com"}, sorted(ours)
    wh = {u.split("//", 1)[1] for u in re.findall(r"https?://[A-Za-z0-9][A-Za-z0-9.-]*", engine)}
    assert wh <= {"speed.cloudflare.com"}, sorted(wh)          # the worker asset: same host check (its own code names none)
    assert not re.findall(r"https?://[A-Za-z0-9]", brg), "the bridge names no host"
    assert not re.findall(r"https?://|//[A-Za-z0-9-]+\.[A-Za-z]", re.sub(r"/\*.*?\*/", "", local, flags=re.S)), \
        "the on-network transfer file names no host: it only requests the box's own /st/ping, /st/down, /st/up"
    assert set(re.findall(r"'(/st/[a-z]+)", local)) == {"/st/ping", "/st/down", "/st/up"}
    templates = set(re.findall(r"`https?://\$\{[^}]+\}`", engine))
    assert templates and templates <= set(re.findall(r"`https?://\$\{[^}]+\}`", lib)), \
        "absolute-URL templates may only come from the verbatim vendored library"

    # 2. the engines behind those templates are never planned, and nothing is logged to Cloudflare
    plan_types = set(re.findall(r"type:\s*'([A-Za-z]+)'", app[app.index("function internetPlan"):]))
    plan_types |= set(re.findall(r"fill\('([A-Za-z]+)'", app))
    assert plan_types <= {"latency", "download", "upload"}, plan_types
    assert "logAimApiUrl: null" in app and "logMeasurementApiUrl: null" in app
    assert not re.search(r"measurements\s*[:=]", brg), "the plan is set by the page only"

    # 3. the CSP the box actually serves: connect-src is exactly the box, its DNS-leg names and Cloudflare
    from exp_speedtest.static import StaticSite  # noqa: PLC0415
    zone = "t.speed.summit.example"
    # the worker asset's policy: connect-src identical to the page's, default-src none, nothing else opened
    for tls_mode in ("none", "provided"):
        site = StaticSite(zone, tls_mode, root / "exp_speedtest" / "static" / "assets")
        page_connect = next(d for d in site.build_csp([], []).split("; ") if d.startswith("connect-src "))
        assert site.worker_csp() == f"default-src 'none'; {page_connect}; frame-ancestors 'none'"
    for tls_mode, expected in (
        ("none", {"'self'", f"http://*.{zone}", "https://speed.cloudflare.com"}),
        ("provided", {"'self'", f"http://*.{zone}", f"https://*.{zone}", "https://speed.cloudflare.com"}),
    ):
        csp = StaticSite(zone, tls_mode, root / "exp_speedtest" / "static" / "assets").build_csp([], [])
        connect = next(d for d in csp.split("; ") if d.startswith("connect-src ")).split()[1:]
        assert set(connect) == expected, (tls_mode, connect)
    csp = StaticSite(None, "none", root / "exp_speedtest" / "static" / "assets").build_csp([], [])
    assert next(d for d in csp.split("; ") if d.startswith("connect-src ")).split()[1:] == ["'self'", "https://speed.cloudflare.com"]

