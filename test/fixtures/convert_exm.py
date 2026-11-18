#!/usr/bin/env python3
"""Convert the real EXM outage fixture into exp.measurement/1 NDJSON (gzip, reproducible).

    convert_exm.py [--src SRC.jsonl.gz] [--out OUT.ndjson.gz]

Defaults: SRC = reference/exm/test/fixtures/outage-2026-10-27.jsonl.gz (read as DATA only; nothing from reference/
is imported), OUT = test/fixtures/exm/outage-2026-10-27.ndjson.gz.

Mapping rules, the outage timeline and the expected "where" per phase are documented in exm/README.md.
Output is deterministic: ULIDs derive from (ts, input line, sub-index), records are ordered by (ts, line, sub), and the
gzip header carries mtime=0 and no file name.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import io
import json
import logging
import os
import re
import sys
from typing import Any, Iterable, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixture_util import iso_to_ms, ulid  # noqa: E402

log = logging.getLogger("convert_exm")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_SRC = os.path.join(ROOT, "reference", "exm", "test", "fixtures", "outage-2026-10-27.jsonl.gz")
DEFAULT_OUT = os.path.join(HERE, "exm", "outage-2026-10-27.ndjson.gz")

SITE = "lab"
WIFI_PORT = "wifi"
LAPTOP_PROBE = "corey-mac"          # the Wi-Fi laptop attached to the board; folded into the main probe as port "wifi"
MAX_DETAIL_BYTES = 8192
MAX_LABEL = 128
ALT_RESOLVER = "1.1.1.1"            # EXM dns_hb default `dns_alt`: the "alternate" resolver; everything else is the DHCP one
APDEX = {"satisfied": 1.0, "tolerating": 0.5, "frustrated": 0.0}
RCODES = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5}
OUTCOMES = {"ok": "ok", "degraded": "degraded", "fail": "fail", "portal": "fail", "harness_error": "error", "error": "error"}
_SLUG_BAD = re.compile(r"[^a-z0-9-]+")


def slug(s: str) -> str:
    out = _SLUG_BAD.sub("-", str(s).lower()).strip("-")[:64]
    return out or "unknown"


def num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return round(float(v), 3) if isinstance(v, float) else float(v)


def metrics_of(**kw: Any) -> dict[str, float]:
    out: dict[str, float] = {}
    for k, v in kw.items():
        n = num(v)
        if n is not None:
            out[k] = int(n) if n == int(n) and abs(n) < 1e15 else n
    return out


def clean(v: Any, depth: int = 1) -> Any:
    """Make a value fit the detail bounds: keys sanitized, strings <= 1024 chars and control-free, arrays <= 256, depth <= 4."""
    if isinstance(v, dict):
        if depth >= 4:
            return json.dumps(v, separators=(",", ":"))[:1024]
        out = {}
        for k, x in list(v.items())[:256]:
            key = re.sub(r"[^A-Za-z0-9_]", "_", str(k))
            if not re.match(r"[A-Za-z_]", key):
                key = "k_" + key
            out[key[:64]] = clean(x, depth + 1)
        return out
    if isinstance(v, (list, tuple)):
        if depth >= 4:
            return json.dumps(v, separators=(",", ":"))[:1024]
        return [clean(x, depth + 1) for x in list(v)[:256]]
    if isinstance(v, str):
        return re.sub(r"[\x00-\x1f\x7f]", " ", v)[:1024]
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return round(v, 3) if isinstance(v, float) else v
    return str(v)[:1024]


def fit_detail(d: dict) -> dict:
    """Cleaned detail, dropping the largest keys until the serialized size is within 8 KiB."""
    d = {k: clean(v) for k, v in d.items() if v is not None}
    while len(json.dumps(d, separators=(",", ":")).encode()) > MAX_DETAIL_BYTES:
        biggest = max(d, key=lambda k: len(json.dumps(d[k])))
        log.warning("detail too large, dropping %s", biggest)
        del d[biggest]
    return d


def lab(v: Any, default: str = "none") -> str:
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(v)) if v not in (None, "") else default
    return s[:MAX_LABEL]


class Converter:
    def __init__(self, recs: list[dict]) -> None:
        cnt = collections.Counter(r["probe_id"] for r in recs if r["probe_id"] != LAPTOP_PROBE)
        self.probe = slug(cnt.most_common(1)[0][0])
        self.iface = {r["client_id"]: r["iface"] for r in recs if r.get("client_id") and r.get("iface") and r["probe_id"] != LAPTOP_PROBE}
        self.dropped: collections.Counter = collections.Counter()
        self.out: list[tuple[str, int, int, dict]] = []

    def emit(self, r: dict, lineno: int, sub: int, test: str, outcome: str, **kw: Any) -> None:
        d: dict[str, Any] = {"schema": "exp.measurement/1", "id": ulid(iso_to_ms(r["ts"]), "%d:%d" % (lineno, sub)), "ts": r["ts"],
                             "probe": self.probe, "site": SITE, "test": test, "outcome": outcome}
        err = kw.pop("error", None)
        detail = kw.pop("detail", None)
        d.update({k: v for k, v in kw.items() if v not in (None, {}, "")})
        if detail:
            d["detail"] = fit_detail(detail)
        if err:
            d["error"] = re.sub(r"[\x00-\x1f\x7f]", " ", str(err))[:512]
        d["agent_ver"] = str(r.get("agent_ver") or "0.1.0")[:64]
        self.out.append((r["ts"], lineno, sub, d))

    def iface_of(self, port: str) -> str:
        return self.iface.get(port) or "eth-" + port

    # --- per-test mappers; each returns nothing and calls emit
    def gateway(self, r: dict, n: int) -> None:
        ports = r["value"].get("ports") or {}
        for sub, (pid, p) in enumerate(ports.items()):
            carrier = p.get("carrier", True) is not False
            ok = bool(p.get("ok")) and carrier
            rtt = num(p.get("rtt_ms"))
            self.emit(r, n, sub, "gateway", "ok" if ok else "fail", target=None,
                      duration_ms=rtt, labels={"port": pid, "iface": self.iface_of(pid)},
                      metrics=metrics_of(link_up=1 if carrier else 0, rtt_ms=rtt, loss_pct=0 if ok else 100, carrier_changes=p.get("carrier_changes")),
                      detail={"gateway_ip": p.get("gateway")}, error=p.get("error") if not ok else None)

    def dhcp_hb(self, r: dict, n: int) -> None:
        v = r["value"]
        self.emit(r, n, 0, "dhcp_hb", OUTCOMES[r["outcome"]], labels={"port": lab(r["client_id"]), "server": lab(v.get("server_id"))},
                  duration_ms=num(r["phase_ms"].get("offer")), metrics=metrics_of(offer_ms=r["phase_ms"].get("offer"), offers=1 if v.get("ok") else 0),
                  detail={"offered_ip": v.get("offered_ip"), "mac": v.get("mac"), "resent": v.get("resent")}, error=r.get("error"))

    def dns_hb(self, r: dict, n: int) -> None:
        v = r["value"]
        server = v.get("server")
        kind = "alternate" if server == ALT_RESOLVER else "dhcp"
        self.emit(r, n, 0, "dns_hb", OUTCOMES[r["outcome"]], labels={"port": lab(r["client_id"], "host"), "resolver": lab(server), "resolver_kind": kind},
                  duration_ms=num(r["phase_ms"].get("rtt")),
                  metrics=metrics_of(rtt_ms=r["phase_ms"].get("rtt"), rcode=v.get("rcode"), answers=v.get("answers"), ping_rtt_ms=v.get("ping_ms")),
                  detail={"name": r.get("target")}, error=r.get("error"))

    def trace(self, r: dict, n: int) -> None:
        v = r["value"]
        hops = v.get("hops") or []
        self.emit(r, n, 0, "trace", OUTCOMES[r["outcome"]], labels={"port": lab(r["client_id"]), "path": "test"},
                  duration_ms=num(r["phase_ms"].get("rtt")),
                  metrics=metrics_of(reached=1 if v.get("reached") else 0, hops=len(hops), last_ttl=v.get("last_ttl"), rtt_ms=r["phase_ms"].get("rtt")),
                  detail={"hops": hops, "last_ip": v.get("last_ip"), "target": r.get("target"), "dest_ttl": v.get("dest_ttl")}, error=r.get("error"))

    def dhcp(self, r: dict, n: int) -> None:
        v, ph = r["value"], r["phase_ms"]
        opts = {k: x for k, x in (v.get("options") or {}).items() if not isinstance(x, (list, dict))}
        self.emit(r, n, 0, "dhcp", OUTCOMES[r["outcome"]], labels={"port": lab(r["client_id"]), "server": lab(v.get("server_id") or r.get("target"))},
                  duration_ms=num(ph.get("total")),
                  metrics=metrics_of(discover_offer_ms=ph.get("discover_offer"), request_ack_ms=ph.get("request_reply"), total_ms=ph.get("total"),
                                     lease_s=v.get("lease_s"), offers=len(v.get("offers") or [])),
                  detail={"ip": v.get("ack_ip") or v.get("held_ip"), "router": v.get("router"), "dns": v.get("dns"), "options": opts, "mode": v.get("mode"),
                          "retries": v.get("retries"), "gateway_mac": v.get("gateway_mac"), "gateway_arp_ms": ph.get("gateway_arp"), "first_dns_ms": ph.get("first_dns"),
                          "flags": v.get("flags")}, error=r.get("error"))

    def dns(self, r: dict, n: int) -> None:
        v, ph = r["value"], r["phase_ms"]
        rc = None
        codes = {k: c for k, c in (v.get("rcodes") or {}).items() if k != "NOERROR"}
        if codes:
            rc = RCODES.get(max(codes, key=codes.get), 2)
        elif v.get("answered"):
            rc = 0
        self.emit(r, n, 0, "dns", OUTCOMES[r["outcome"]], labels={"port": lab(r["client_id"]), "resolver": lab(r.get("target"))},
                  duration_ms=num(ph.get("p50")), metrics=metrics_of(rtt_ms=ph.get("p50"), rcode=rc, answers=v.get("answered")),
                  detail={"resolver_name": r.get("resolver"), "queries": v.get("queries"), "answered": v.get("answered"), "timeouts": v.get("timeouts"),
                          "errors": v.get("errors"), "p95_ms": ph.get("p95"), "max_ms": ph.get("max"), "rcodes": v.get("rcodes"), "ad_set": v.get("ad_set"),
                          "per_type": v.get("per_type"), "rows": v.get("detail")}, error=r.get("error"))

    def app(self, r: dict, n: int) -> None:
        v = r["value"]
        steps = v.get("steps") or []
        okst = [s for s in steps if not s.get("error") and s.get("http_code")]
        main = max(okst, key=lambda s: (s.get("phase_ms") or {}).get("total") or 0) if okst else (steps[0] if steps else {})
        ph = main.get("phase_ms") or {}
        self.emit(r, n, 0, "app", OUTCOMES[r["outcome"]], labels={"port": lab(r["client_id"]), "app": lab(r.get("target"))},
                  duration_ms=num(v.get("sample_ms")),
                  metrics=metrics_of(dns_ms=ph.get("dns"), connect_ms=ph.get("connect"), tls_ms=ph.get("tls"), ttfb_ms=ph.get("ttfb"), total_ms=ph.get("total"),
                                     status_code=main.get("http_code"), apdex=APDEX.get(v.get("apdex_class"))),
                  detail={"url": main.get("target"), "ip": main.get("remote_ip"), "http_version": main.get("http_version"), "apdex_t_ms": v.get("t_ms"),
                          "apdex_class": v.get("apdex_class"), "quic": v.get("quic"),
                          "steps": [{"target": s.get("target"), "http_code": s.get("http_code"), "error": s.get("error")} for s in steps]}, error=r.get("error"))

    def speedtest(self, r: dict, n: int) -> None:
        if r.get("target") != "cloudflare":
            self.dropped["speedtest/" + str(r.get("target"))] += 1      # provider not in the exp catalog (cloudflare|iperf3)
            return
        v, ph = r["value"], r["phase_ms"]
        self.emit(r, n, 0, "throughput", OUTCOMES[r["outcome"]], labels={"port": lab(r["client_id"]), "provider": "cloudflare"},
                  metrics=metrics_of(down_mbps=v.get("down_mbps"), up_mbps=v.get("up_mbps"), latency_idle_ms=ph.get("idle_rtt"),
                                     latency_loaded_ms=ph.get("loaded_rtt_down"), jitter_ms=ph.get("idle_jitter")),
                  detail={"server": v.get("remote_ip"), "streams": v.get("streams"), "bufferbloat_ms": v.get("bufferbloat_ms"),
                          "down_bytes": v.get("down_bytes"), "up_bytes": v.get("up_bytes")}, error=r.get("error"))

    def wifi_hb(self, r: dict, n: int) -> None:
        v, ph = r["value"], r["phase_ms"]
        ch_raw = str(v.get("channel") or "")
        try:
            ch = int(ch_raw.split(",")[0])
        except ValueError:
            ch = None
        band = "none" if ch is None else ("2.4" if ch <= 14 else "5")
        tgt = v.get("target_ssid")
        self.emit(r, n, 0, "wifi_hb", OUTCOMES[r["outcome"]], labels={"port": WIFI_PORT, "ssid": lab(v.get("ssid")), "band": band},
                  metrics=metrics_of(link_up=1, rssi_dbm=v.get("rssi"), noise_dbm=v.get("noise"), snr_db=v.get("snr"), tx_rate_mbps=v.get("tx_rate"),
                                     channel=ch, gw_rtt_ms=ph.get("gateway")),
                  detail={"security": v.get("security"), "target_ssid": tgt, "on_target": (not tgt) or tgt == v.get("ssid"), "channel_raw": ch_raw, "max_rate_mbps": v.get("max_rate"),
                          "ip": v.get("ip"), "gateway": v.get("gateway"), "dns_server": v.get("dns_server"), "dhcp_server": v.get("dhcp_server"),
                          "lease_s": v.get("lease_s"), "dns_ms": ph.get("dns"), "check_target": r.get("target"), "laptop": LAPTOP_PROBE}, error=r.get("error"))

    def run(self, lines: Iterable[str]) -> list[dict]:
        table = {"gateway": self.gateway, "dhcp_hb": self.dhcp_hb, "dns_hb": self.dns_hb, "trace": self.trace, "dhcp": self.dhcp, "dns": self.dns,
                 "app": self.app, "speedtest": self.speedtest, "wifi_hb": self.wifi_hb}
        for n, line in enumerate(lines):
            if not line.strip():
                continue
            r = json.loads(line)
            fn = table.get(r.get("test"))
            if fn is None:
                self.dropped["test/" + str(r.get("test"))] += 1
                continue
            fn(r, n)
        self.out.sort(key=lambda t: (t[0], t[1], t[2]))
        for k, c in sorted(self.dropped.items()):
            log.info("dropped %d record(s): %s", c, k)
        return [t[3] for t in self.out]


def convert(src: str, out: str) -> int:
    with gzip.open(src, "rt", encoding="utf-8") as f:
        recs = [json.loads(ln) for ln in f if ln.strip()]
    with gzip.open(src, "rt", encoding="utf-8") as f:
        docs = Converter(recs).run(f)
    body = ("\n".join(json.dumps(d, separators=(",", ":"), ensure_ascii=False) for d in docs) + "\n").encode("utf-8")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0) as gz:
        gz.write(body)
    with open(out, "wb") as f:
        f.write(buf.getvalue())
    return len(docs)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--src", default=DEFAULT_SRC)
    ap.add_argument("--out", default=DEFAULT_OUT)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    n = convert(a.src, a.out)
    print("wrote %d records to %s" % (n, a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
