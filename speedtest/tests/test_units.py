"""Unit tests: leg tokens, rate limiters, UA parsing, the core guard, internet slots, the zone resolver, the store."""
from __future__ import annotations

import base64
import ipaddress
from pathlib import Path

import pytest
from exp_common import ids
from stbox import FakeClock, base_config

from exp_speedtest import ua as uamod
from exp_speedtest.config import SpeedtestConfig
from exp_speedtest.guard import CoreGuard, ThroughputMeter, read_proc_net_dev
from exp_speedtest.limits import SlidingWindow, TokenBucket
from exp_speedtest.slots import InternetLeg, RuntimeState
from exp_speedtest.static import StaticSite, csp_hash, inline_hashes
from exp_speedtest.store import SpoolFull, Store
from exp_speedtest.tokens import LegTokens
from exp_speedtest.whereis import ZoneResolver

SID = "st_01M7R3X9G0QWCYM3A3S1DE8MT4"


# --------------------------------------------------------------------------------------------------- tokens
def test_leg_token_shape_and_binding():
    t = LegTokens()
    tok, nonce = t.mint(SID, "10.0.0.5", 2_000_000_000)
    assert ids.is_token(tok, "expt") and len(nonce) == 12
    assert t.verify(tok, SID, "10.0.0.5")
    assert not t.verify(tok, SID, "10.0.0.6"), "bound to the client address"
    assert not t.verify(tok, "st_01M7R3X9G0QWCYM3A3S1DE8MT5", "10.0.0.5"), "bound to the session"
    assert not LegTokens().verify(tok, SID, "10.0.0.5"), "another process key never verifies"
    raw = bytearray(base64.urlsafe_b64decode(tok[5:] + "="))
    raw[0] ^= 1                                                      # tamper with the expiry
    forged = "expt_" + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    assert not t.verify(forged, SID, "10.0.0.5")
    # the last base64 character carries only 4 significant bits: an alternative spelling of the same bytes is refused
    last = tok[-1]
    alt = tok[:-1] + next(c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                          if c != last and base64.urlsafe_b64decode(tok[5:-1] + c + "=") == base64.urlsafe_b64decode(tok[5:] + "="))
    assert alt != tok and LegTokens.parse(alt) is None and not t.verify(alt, SID, "10.0.0.5"), "tokens are not malleable"
    assert LegTokens.parse("expt_short") is None and LegTokens.parse(None) is None and LegTokens.parse("x" * 48) is None


def test_two_tokens_differ():
    t = LegTokens()
    assert t.mint(SID, "10.0.0.5", 2_000_000_000)[0] != t.mint(SID, "10.0.0.5", 2_000_000_000)[0]


# -------------------------------------------------------------------------------------------------- limiters
def test_sliding_window_limits_and_retry_after():
    w = SlidingWindow(3, 600.0)
    for i in range(3):
        assert w.retry_after("a", 100.0 + i) == 0
        w.record("a", 100.0 + i)
    assert w.retry_after("a", 105.0) == pytest.approx(595.0)
    assert w.retry_after("b", 105.0) == 0
    assert w.retry_after("a", 701.0) == 0                            # the oldest left the window


def test_sliding_window_bounded_keys():
    w = SlidingWindow(1, 60.0, max_keys=5)
    for i in range(50):
        w.record(f"k{i}", 1.0)
    assert len(w._d) <= 5


def test_token_bucket():
    b = TokenBucket(rate=2.0, burst=3.0, max_keys=4)
    assert [b.take("x", 0.0) for _ in range(3)] == [0.0, 0.0, 0.0]
    assert b.take("x", 0.0) == pytest.approx(0.5)
    assert b.take("x", 1.0) == 0.0                                   # refilled 2 tokens
    for i in range(20):
        b.take(f"k{i}", 0.0)
    assert len(b._d) <= 4


# -------------------------------------------------------------------------------------------------------- ua
def test_ua_parsing_and_no_raw_ua():
    iphone = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
              "Version/18.1 Mobile/15E148 Safari/604.1")
    d = uamod.parse_ua(iphone)
    assert d == {"os_family": "iOS", "os_version": "18.1", "browser": "Safari", "device_class": "phone"}
    android = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/130.0.0.0 Mobile Safari/537.36"
    assert uamod.parse_ua(android)["os_family"] == "Android" and uamod.parse_ua(android)["device_class"] == "phone"
    win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
    assert uamod.parse_ua(win)["browser"] == "Edge" and uamod.parse_ua(win)["device_class"] == "desktop"
    assert uamod.parse_ua(None) == {"device_class": "other"} and uamod.parse_ua("\x00\x01junk") == {"device_class": "other"}
    for v in uamod.parse_ua(iphone).values():
        assert "Mozilla" not in v and "AppleWebKit" not in v
    assert uamod.parse_ua("A" * 100000)["device_class"] == "other"   # bounded


# ------------------------------------------------------------------------------------------------- guard
def test_core_guard_shrinks_cap_linearly():
    g = CoreGuard("eno2", 70, 200_000_000, 5_000_000)
    assert g.effective_cap() == 200_000_000
    g.set_utilization(70)
    assert g.effective_cap() == 200_000_000
    g.set_utilization(85)
    assert g.effective_cap() == pytest.approx(5_000_000 + 195_000_000 * 0.5, rel=0.001)
    g.set_utilization(100)
    assert g.effective_cap() == 5_000_000
    g.set_utilization(None)
    assert g.effective_cap() == 200_000_000


def test_core_guard_samples_proc_net_dev(tmp_path: Path):
    p = tmp_path / "dev"
    hdr = "Inter-|   Receive    | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets ...\n"
    p.write_text(hdr + "  eno2: 1000 1 0 0 0 0 0 0 5000 1 0 0 0 0 0 0\n    lo: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n")
    assert read_proc_net_dev("eno2", str(p)) == (1000, 5000)
    assert read_proc_net_dev("nope", str(p)) is None
    clock = [0.0]
    counters = [(0, 0)]
    g = CoreGuard("eno2", 70, 100, 10, read_counters=lambda i: counters[0], link_mbps=lambda i: 1000.0, clock=lambda: clock[0])
    g.sample()
    clock[0], counters[0] = 1.0, (0, int(900e6 / 8))                  # 900 Mb/s over a 1 Gb/s link for 1 s
    g.sample()
    assert g.utilization_pct == pytest.approx(90.0)
    assert g.effective_cap() < 100
    counters[0] = None
    g.sample()
    assert g.utilization_pct is None and not g.available


def test_throughput_meter_p95():
    clock = [0.0]
    m = ThroughputMeter(clock=lambda: clock[0])
    m.sample()
    for i in range(1, 21):
        clock[0] = float(i)
        m.add(125_000_000 * (1 if i < 20 else 4))                    # 1 Gb/s per second, one 4 Gb/s spike
        m.sample()
    assert 1.0 <= m.p95_gbps() <= 4.0
    assert ThroughputMeter().p95_gbps() == 0.0


# ------------------------------------------------------------------------------------------------- slots
def _leg(clock: FakeClock, **kw) -> InternetLeg:
    args = dict(enabled=True, config_paused=False, max_concurrent=2, auto_pause_pct=80, clock=clock)
    args.update(kw)
    return InternetLeg(**args)


def test_slots_fifo_queue_and_release():
    clock = FakeClock()
    leg = _leg(clock)
    assert leg.acquire("a")["state"] == "granted" and leg.acquire("b")["state"] == "granted"
    c, d = leg.acquire("c"), leg.acquire("d")
    assert (c["state"], c["queue_position"], d["queue_position"]) == ("queued", 1, 2)
    assert leg.state() == ("queued", "capacity") and leg.queue_depth == 2
    assert leg.acquire("d")["queue_position"] == 2, "polling keeps the place"
    assert leg.release("a")["state"] == "released"
    assert leg.acquire("c")["state"] == "granted", "FIFO: c is promoted first"
    assert leg.acquire("d")["queue_position"] == 1
    assert leg.release("zzz")["state"] == "released"                  # idempotent


def test_slots_expire_and_stale_queue_entries_drop():
    clock = FakeClock()
    leg = _leg(clock, max_concurrent=1)
    leg.acquire("a")
    leg.acquire("b")
    clock.advance(16)                                                 # b stops polling
    assert leg.queue_depth == 0
    clock.advance(60)                                                 # a's slot expires without a release
    assert leg.held == 0 and leg.acquire("c")["state"] == "granted"


def test_slots_pause_sources_and_fail_open():
    clock = FakeClock()
    leg = _leg(clock, auto_pause_pct=80)
    leg.put_wan(95.0, clock(), None)
    assert leg.state() == ("paused", "wan_utilization")
    r = leg.acquire("a")
    assert r["state"] == "paused" and r["reason"] == "wan_utilization"
    leg.put_wan(50.0, clock(), None)
    assert leg.state()[0] == "ok"
    leg.put_wan(95.0, clock(), None)
    clock.advance(91)                                                 # stale runner value is ignored (fail open)
    assert leg.state() == ("ok", None)
    leg.put_wan(10.0, clock(), True)                                  # the runner's explicit verdict wins
    assert leg.state() == ("paused", "wan_utilization")
    leg.put_wan(None, clock(), None)
    assert leg.state()[0] == "ok"


def test_slots_admin_pause_and_disabled(tmp_path: Path):
    clock = FakeClock()
    assert _leg(clock, config_paused=True).state() == ("paused", "admin_pause")
    off = _leg(clock, enabled=False)
    assert off.state() == ("unavailable", "disabled") and off.acquire("a")["state"] == "unavailable"
    rt = RuntimeState(tmp_path / "runtime.json", clock)
    leg = _leg(clock, runtime=rt)
    assert leg.state()[0] == "ok"
    RuntimeState.write(tmp_path / "runtime.json", True)
    clock.advance(2)
    assert leg.state() == ("paused", "admin_pause") and leg.paused
    RuntimeState.write(tmp_path / "runtime.json", False)
    clock.advance(2)
    assert leg.state()[0] == "ok"
    (tmp_path / "runtime.json").write_text("{not json")
    clock.advance(2)
    assert leg.state()[0] == "ok", "an unreadable runtime file never pauses"


# ---------------------------------------------------------------------------------------------- resolver
def _cfg(**over) -> SpeedtestConfig:
    over.setdefault("serve", {"client_subnets": ["10.60.0.0/16", "10.61.0.0/16"], "translated_addresses": ["10.0.0.2"], "port": 8080})
    return SpeedtestConfig(base_config("https://127.0.0.1:8443", "AA:" * 31 + "AA", 8080, 5353, 8480, **over)
                           | {"zone_labels": {"subnets": [{"cidr": "10.60.0.0/16", "zone": "hall-a"},
                                                          {"cidr": "10.60.14.0/24", "zone": "hallb-row12"},
                                                          {"cidr": "10.61.0.0/16", "zone": "hall-b"}]}})


def test_resolver_priority_and_nat_guard():
    clock = FakeClock()
    r = ZoneResolver(_cfg(), clock)
    assert r.resolve("10.60.14.77").zone == "hallb-row12" and r.resolve("10.60.14.77").source == "subnet", "longest prefix"
    assert r.resolve("10.60.99.1").zone == "hall-a"
    w = r.resolve("10.61.0.9", hint="hallb-row12")
    assert (w.zone, w.source, w.zone_hint_conflict) == ("hall-b", "subnet", True)
    assert r.resolve("10.61.0.9", hint="hall-b").zone_hint_conflict is False
    # fails closed: outside every client subnet (require_real_client_ip) and a translated address; a hint never rescues it
    for ip in ("192.168.5.5", "10.0.0.2"):
        w = r.resolve(ip, hint="hall-a")
        assert (w.zone, w.source, w.nat_suspected) == ("unresolved", "unresolved", True), ip
    r.put([{"ip": "10.60.14.77", "zone": "hall-b", "zone_source": "mist", "nat_suspected": False, "ttl_s": 30, "ap_name": "ap-1"}])
    w = r.resolve("10.60.14.77")
    assert (w.zone, w.source, w.ap_name) == ("hall-b", "mist", "ap-1"), "the runner's Mist answer beats the subnet table"
    clock.advance(31)
    assert r.resolve("10.60.14.77").source == "subnet", "cache entries expire"
    r.put([{"ip": "10.60.14.80", "zone": "unresolved", "zone_source": "mist", "nat_suspected": True, "ttl_s": 30}])
    assert r.resolve("10.60.14.80").nat_suspected is True, "the runner's ambiguity verdict fails closed"
    assert r.resolve("10.60.14.81", hint="nonexistent").source == "subnet"


def test_resolver_no_client_subnets_skips_condition_one_and_unresolved_without_anything():
    cfg = SpeedtestConfig({**_cfg().raw, "serve": {"hostname": "x", "listen_ip": "127.0.0.1", "port": 1}, "zone_labels": {"subnets": []}})
    r = ZoneResolver(cfg, FakeClock())
    assert r.resolve("172.16.0.5").zone == "unresolved" and not r.resolve("172.16.0.5").nat_suspected
    assert r.resolve("172.16.0.5", hint="hall-a").source == "qr"
    assert r.nat_suspected("not an ip") is True


def test_resolver_wanted_list_bounded_and_cleared_by_answer():
    clock = FakeClock()
    r = ZoneResolver(_cfg(), clock)
    for i in range(150):
        r.note_asked(f"10.60.{i // 250}.{i % 250 + 1}")
    assert len(r.wanted()) == 100
    ip = r.wanted()[-1][0]
    r.put([{"ip": ip, "zone": "hall-a", "zone_source": "mist", "nat_suspected": False}])
    assert ip not in [i for i, _ in r.wanted()]
    clock.advance(301)
    assert r.wanted() == []


# ----------------------------------------------------------------------------------------------- store
def test_store_sessions_comment_and_spool_bounds(tmp_path: Path):
    s = Store(tmp_path / "x.db", max_rows=3, max_bytes=1000)
    s.add_session(SID, 100.0, "a" * 64, "hall-a")
    assert s.get_session(SID)["state"] == "created"
    assert s.mark_submitted(SID, {"id": SID}) is True and s.mark_submitted(SID, {"id": SID}) is False
    assert s.get_session(SID)["result"] == {"id": SID}
    s.unmark_submitted(SID)
    assert s.get_session(SID)["state"] == "created"
    assert s.set_comment(SID, "<script>x</script>") == 1 and s.get_session(SID)["comment"] == "<script>x</script>"
    for i in range(3):
        s.spool_add("result", f"st_{i}", "{}", 1.0)
    with pytest.raises(SpoolFull):
        s.spool_add("result", "st_9", "{}", 1.0)
    due = s.spool_due(2.0)
    assert [d["sid"] for d in due] == ["st_0", "st_1", "st_2"]
    s.spool_claim(due[0]["seq"], 100.0)
    assert [d["sid"] for d in s.spool_due(2.0)] == ["st_1", "st_2"]
    s.spool_done(due[1]["seq"])
    assert s.spool_stat(5.0)["depth"] == 2
    assert s.prune_sessions(200.0) == 1 and s.get_session(SID) is None
    big = Store(tmp_path / "y.db", max_rows=100, max_bytes=10)
    with pytest.raises(SpoolFull):
        big.spool_add("result", "st_1", "x" * 11, 1.0)
    assert oct((tmp_path / "x.db").stat().st_mode & 0o777) == "0o600"


def test_store_parameterized_sql_survives_hostile_ids(tmp_path: Path):
    s = Store(tmp_path / "x.db")
    hostile = "st_'); DROP TABLE sessions;--"
    assert s.get_session(hostile) is None
    s.add_session(hostile, 1.0, "b" * 64, None)
    assert s.get_session(hostile)["id"] == hostile and s.count_sessions() == 1


# ----------------------------------------------------------------------------------------------- static
def test_csp_hashes_from_inline_blocks(tmp_path: Path):
    html = '<style>a{b:c}</style><script>var x=1;</script><script src="/x.js"></script><script>  </script>'
    scripts, styles = inline_hashes(html)
    assert scripts == [csp_hash("var x=1;")] and styles == [csp_hash("a{b:c}")]
    (tmp_path / "index.html").write_text(html)
    site = StaticSite("t.speed.example", "none", tmp_path / "a", tmp_path)
    body, csp = site.page()
    assert body == html.encode()
    assert f"script-src '{csp_hash('var x=1;')}'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "connect-src 'self' http://*.t.speed.example https://speed.cloudflare.com" in csp
    assert "frame-ancestors 'none'" in csp and "default-src 'self'" in csp and "img-src 'self' data:" in csp


def test_csp_hash_file_overrides_and_invalid_file_is_ignored(tmp_path: Path):
    (tmp_path / "index.html").write_text("<script>a()</script>")
    good = "sha256-" + "A" * 43 + "="
    (tmp_path / "csp-hashes.json").write_text(f'{{"schema":"exp.speedtest.csp/1","script":["{good}"],"style":[]}}')
    site = StaticSite(None, "none", tmp_path / "a", tmp_path)
    assert f"script-src '{good}'" in site.page()[1]
    (tmp_path / "csp-hashes.json").write_text('{"schema":"exp.speedtest.csp/1","script":["not-a-hash"],"style":[]}')
    site2 = StaticSite(None, "none", tmp_path / "a", tmp_path)
    assert csp_hash("a()") in site2.page()[1], "an invalid build file falls back to hashes derived from the page"
    s3 = StaticSite(None, "provided", tmp_path / "a", tmp_path / "nonexistent")
    assert s3.page() == (b"", "")
    assert "https://*." not in site2.build_csp([], [])
    assert "script-src 'self';" in site2.build_csp([], []) and "worker-src 'self'" in site2.build_csp([], [])   # no hash: only the same-origin engine file


def test_csp_tls_provided_allows_https_nonce_hosts(tmp_path: Path):
    site = StaticSite("t.speed.example", "provided", tmp_path, tmp_path)
    assert "https://*.t.speed.example" in site.build_csp([], [])


def test_assets_are_sniffed_bounded_and_not_symlinks(tmp_path: Path):
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "logo").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 100)
    (assets / "evil.png").write_bytes(b"<html><script>alert(1)</script></html>")
    (assets / "huge.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * (1024 * 1024 + 10))
    (assets / "secret").write_text("x")
    (assets / "link.png").symlink_to(assets / "secret")
    (assets / "l.svg").write_bytes(b'<svg xmlns="http://www.w3.org/2000/svg"/>')
    site = StaticSite(None, "none", assets, tmp_path / "static")
    assert site.asset("logo")[1] == "image/png"
    assert site.asset("l.svg")[1] == "image/svg+xml"
    for bad in ("evil.png", "huge.png", "link.png", "../etc/passwd", ".hidden", "LOGO", "a/b", "nonexistent", "secret"):
        assert site.asset(bad) is None, bad


def test_worker_files_are_an_allowlist_served_from_the_packaged_tree_only(tmp_path: Path):
    """/st/assets/cf-engine.js and /st/assets/local-leg.js (static.ENGINE_ASSETS) are JavaScript, read from the packaged
    static/assets only: an operator file of the same name never shadows them, and no other .js is ever served."""
    from exp_speedtest.static import ENGINE_ASSETS, JS_TYPE
    assert ENGINE_ASSETS == {"cf-engine.js", "local-leg.js"}
    ops, static = tmp_path / "ops", tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    ops.mkdir()
    for name in ENGINE_ASSETS:
        (static / "assets" / name).write_text(f"/* packaged {name} */")
        (ops / name).write_text("alert('operator')")
    for name in ("app.js", "other.js", "local-bridge.js"):
        (static / "assets" / name).write_text("var x;")
        (ops / name).write_text("var y;")
    site = StaticSite(None, "none", ops, static)
    for name in ENGINE_ASSETS:
        assert site.asset(name) == (f"/* packaged {name} */".encode(), JS_TYPE), name
    for name in ("app.js", "other.js", "local-bridge.js", "LOCAL-LEG.JS"):
        assert site.asset(name) is None, name
    (static / "assets" / "local-leg.js").unlink()
    assert site.asset("local-leg.js") is None, "missing from the packaged tree: 404, never the operator's copy"


def test_ipv4_helpers_sanity():
    assert ipaddress.ip_address("127.0.0.2") != ipaddress.ip_address("127.0.0.1")


def test_systemd_unit_is_least_privilege_and_names_the_credentials_the_code_reads():
    from exp_speedtest import config as cfgmod
    unit = (Path(__file__).resolve().parents[1] / "systemd" / "exp-speedtest.service").read_text()
    assert "ExecStart=@PREFIX@/bin/exp-speedtest run --config @CONFIG@" in unit and "User=exp-speedtest" in unit
    assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in unit and "AmbientCapabilities=CAP_NET_BIND_SERVICE" in unit
    assert "NET_RAW" not in unit.replace("no CAP_NET_RAW", ""), "no raw sockets"
    for name in (cfgmod.CRED_COLLECTOR_TOKEN, cfgmod.CRED_CHANNEL_SHA, cfgmod.CRED_TLS_CRT, cfgmod.CRED_TLS_KEY):
        assert f"LoadCredential={name}:@CREDS@/{name}" in unit
    for hardening in ("NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateTmp=yes", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
                      "StateDirectory=exp/speedtest", "RuntimeDirectory=exp/speedtest", "MemoryDenyWriteExecute=yes"):
        assert hardening in unit, hardening
    assert (Path(__file__).resolve().parents[1] / "requirements.apt").read_text().split() == ["iputils-ping"]
