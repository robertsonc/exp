#!/usr/bin/python3
"""EXM Wi-Fi agent for a Mac: a real wireless client next to the wired probe.

Runs as a LaunchAgent (no admin rights) and writes EXM-format events, one JSON
object per line, to ~/exm-wifi/results/current.jsonl. The wired probe's host
streams that file over SSH with a key that may do nothing else.

  wifi_hb     every 10 s  association, signal, noise, link rate; one gateway ping
                          and one DNS query, both forced out of the Wi-Fi interface
  wifi_app    every 60 s  a few app checks with curl --interface <wifi>
  wifi_speed  every 30 min  networkQuality -I <wifi>

Every test is pinned to the Wi-Fi interface, so a wired management link that
happens to be first in the service order never carries the test traffic.

The network to monitor is set on the wired probe host ([[remote]] ssid) and
passed in by stream.sh each time that host connects. While the Mac is on any
other network (or none) the heartbeat fails with "not on <ssid>", app and
speed tests pause rather than measure the wrong network, and the agent asks
macOS to rejoin the right one every 60 s. The network must already be saved on
this Mac (joined once by hand). With no ssid set, whatever network the Mac is
on is monitored.

Python 3.8 standard library only (the version Xcode ships on macOS 12).
"""
import datetime
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time

AGENT_VER = "0.2.0"
PROBE = os.environ.get("EXM_WIFI_PROBE", socket.gethostname().split(".")[0].lower())
IFACE = os.environ.get("EXM_WIFI_IFACE", "en0")
HOME = os.path.expanduser("~/exm-wifi")
RESULTS = os.path.join(HOME, "results")
CURRENT = os.path.join(RESULTS, "current.jsonl")
TARGET_FILE = os.path.join(HOME, "target-ssid.hex")   # written by stream.sh; hex so any SSID survives intact
REJOIN_EVERY_S = 60
KEEP_DAYS = 7
AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
IP_BOUND_IF = 25                       # macOS: bind a socket to one interface
NAMES = ["google.com", "apple.com", "microsoft.com", "cloudflare.com", "amazon.com", "wikipedia.org"]
APPS = [  # name, url, expected status, Apdex T in ms
    ("phone-connectivity", "http://connectivitycheck.gstatic.com/generate_204", 204, 300),
    ("apple-captive", "http://captive.apple.com/hotspot-detect.html", 200, 300),
    ("google-search", "https://www.google.com/", 200, 800),
    ("youtube", "https://www.youtube.com/", 200, 1000),
]
# Thresholds for a Wi-Fi client: a weak signal or a slow gateway is degraded, not failed.
RSSI_WEAK, SNR_WEAK, GW_SLOW_MS, DNS_SLOW_MS = -70, 20, 150, 250

_lock = threading.Lock()
_speed_running = threading.Event()     # set while our own speed test loads the link
_on_target = threading.Event()         # clear while the Mac is not on the network being monitored
_on_target.set()
_rejoin = {"at": 0.0, "busy": False, "said": None}


def iso(t=None):
    return datetime.datetime.fromtimestamp(time.time() if t is None else t, datetime.timezone.utc) \
        .isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make(test, target=None, resolver=None):
    # "ts" must stay the first key: the receiving side reads the timestamp from the line's start.
    return {"ts": iso(), "probe_id": PROBE, "client_id": "wifi", "iface": IFACE, "vlan": "", "zone": "",
            "test": test, "target": target, "resolver": resolver, "outcome": None, "phase_ms": {},
            "value": {}, "error": None, "agent_ver": AGENT_VER, "config_ver": "mac", "hw_class": "mac-wifi"}


def _rotate_if_needed(day):
    if not os.path.exists(CURRENT):
        return
    try:
        with open(CURRENT) as fh:
            first = fh.readline()
        first_day = json.loads(first)["ts"][:10] if first.strip() else day
    except (OSError, ValueError, KeyError):
        first_day = day
    if first_day != day:
        os.replace(CURRENT, os.path.join(RESULTS, first_day + ".jsonl"))
        cutoff = (datetime.date.fromisoformat(day) - datetime.timedelta(days=KEEP_DAYS)).isoformat()
        for f in os.listdir(RESULTS):
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.jsonl", f) and f[:10] < cutoff:
                os.unlink(os.path.join(RESULTS, f))


def emit(ev):
    with _lock:                    # stamp inside the lock: lines must be in "emitted" order for the receiver
        ev["emitted"] = iso()
        line = json.dumps(ev, separators=(",", ":")) + "\n"
        os.makedirs(RESULTS, exist_ok=True)
        _rotate_if_needed(ev["ts"][:10])
        with open(CURRENT, "a") as fh:
            fh.write(line)


def run(argv, timeout):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        return -1, str(exc)


def wifi_link():
    _, out = run([AIRPORT, "-I"], 5)
    info = {}
    for line in out.splitlines():
        k, _, v = line.strip().partition(": ")
        info[k.strip()] = v.strip()
    if "AirPort: Off" in out or not info.get("SSID"):
        return None
    num = lambda k: int(info[k]) if re.fullmatch(r"-?\d+", info.get(k, "")) else None
    rssi, noise = num("agrCtlRSSI"), num("agrCtlNoise")
    return {"ssid": info.get("SSID"), "channel": info.get("channel"), "security": info.get("link auth"),
            "rssi": rssi, "noise": noise, "snr": (rssi - noise) if rssi is not None and noise is not None else None,
            "tx_rate": num("lastTxRate"), "max_rate": num("maxRate")}


def target_ssid():
    """The network to monitor, or None for whatever the Mac is on."""
    try:
        with open(TARGET_FILE) as fh:
            h = fh.read().strip()
        return bytes.fromhex(h).decode("utf-8") if h else None
    except (OSError, ValueError):
        return None


def _join(ssid):
    try:
        r = subprocess.run(["/usr/sbin/networksetup", "-setairportnetwork", IFACE, ssid],
                           capture_output=True, text=True, timeout=45)
        said = (r.stdout + r.stderr).strip()      # it exits 0 even when it fails; what it prints is the answer
    except (subprocess.TimeoutExpired, OSError) as exc:
        said = str(exc)
    _rejoin.update(said=said[:120] or None, busy=False)


def rejoin(ssid):
    """Ask macOS to join the monitored network, at most every REJOIN_EVERY_S, never blocking a heartbeat."""
    if _rejoin["busy"] or time.time() - _rejoin["at"] < REJOIN_EVERY_S:
        return
    _rejoin.update(at=time.time(), busy=True)
    threading.Thread(target=_join, args=(ssid,), daemon=True).start()


def dhcp_packet():
    _, out = run(["ipconfig", "getpacket", IFACE], 5)
    # Lines look like "router (ip_mult): {10.1.0.1}" or "yiaddr = 10.1.0.26".
    pick = lambda key: (re.search(r"(?m)^" + re.escape(key) + r"\b[^:=\n]*[:=]\s*\{?([\d., ]+)", out) or [None, ""])[1]
    first = lambda s: s.replace(",", " ").split()[0] if s and s.split() else None
    lease = re.search(r"(?m)^lease_time\b[^:=\n]*[:=]\s*0x([0-9a-f]+)", out)
    return {"router": first(pick("router")), "dns": first(pick("domain_name_server")),
            "server": first(pick("server_identifier")), "lease_s": int(lease.group(1), 16) if lease else None}


def ping(gw):
    _, out = run(["/sbin/ping", "-n", "-c", "1", "-t", "2", "-b", IFACE, gw], 5)
    m = re.search(r"time=([\d.]+) ms", out)
    return float(m.group(1)) if m else None


def dns(server, name, timeout=2.0):
    qid = random.getrandbits(16)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(IFACE))
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.sendto(q, (server, 53))
        while True:
            data, _ = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == qid:
                break
        ms = round((time.perf_counter() - t0) * 1000, 2)
        flags, _, ancount = struct.unpack("!HHH", data[2:8])
        if flags & 0x0F:
            return ms, "rcode %d from %s" % (flags & 0x0F, server)
        if not ancount:
            return ms, "no records for %s from %s" % (name, server)
        return ms, None
    except socket.timeout:
        return None, "no DNS answer from %s within %g s" % (server, timeout)
    except OSError as exc:
        return None, "DNS error: %s" % exc
    finally:
        s.close()


def heartbeat(n):
    ev = make("wifi_hb")
    want = target_ssid()
    ev["value"]["target_ssid"] = want
    link = wifi_link()
    _, ip = run(["ipconfig", "getifaddr", IFACE], 5)
    ip = ip.strip() or None
    if link:
        ev["value"].update(link, ip=ip)
    if want and (not link or link["ssid"] != want):
        _on_target.clear()
        rejoin(want)
        where = "on %s" % link["ssid"] if link else "not associated"
        tried = "; rejoin: %s" % _rejoin["said"] if _rejoin["said"] else ""
        ev["outcome"], ev["error"] = "fail", "not on %s (%s)%s" % (want, where, tried)
        return emit(ev)
    _on_target.set()
    _rejoin["said"] = None
    if not link:
        ev["outcome"], ev["error"] = "fail", "Wi-Fi is not associated"
        return emit(ev)
    if not ip:
        ev["outcome"], ev["error"] = "fail", "associated to %s but no IP address" % link["ssid"]
        return emit(ev)
    pkt = dhcp_packet()
    ev["value"].update(gateway=pkt["router"], dns_server=pkt["dns"], dhcp_server=pkt["server"], lease_s=pkt["lease_s"])
    problems, soft = [], []
    rtt = ping(pkt["router"]) if pkt["router"] else None
    if rtt is None:
        problems.append("no reply from gateway %s over Wi-Fi" % pkt["router"])
    else:
        ev["phase_ms"]["gateway"] = rtt
        if rtt > GW_SLOW_MS:
            soft.append("gateway %.0f ms over Wi-Fi" % rtt)
    if pkt["dns"]:
        name = NAMES[n % len(NAMES)]
        ms, err = dns(pkt["dns"], name)
        ev["target"], ev["resolver"] = name, "dhcp"
        if ms is not None:
            ev["phase_ms"]["dns"] = ms
        if err:
            soft.append(err)                     # DNS over Wi-Fi failing is shown, but the Wi-Fi link itself is up
        elif ms > DNS_SLOW_MS:
            soft.append("DNS %.0f ms over Wi-Fi" % ms)
    if link["rssi"] is not None and link["rssi"] < RSSI_WEAK:
        soft.append("signal %d dBm" % link["rssi"])
    if link["snr"] is not None and link["snr"] < SNR_WEAK:
        soft.append("SNR %d dB" % link["snr"])
    # Measurement must not report its own load as a fault: while our speed test runs, slow
    # gateway or DNS replies are recorded but do not degrade the result. Weak signal still does.
    if _speed_running.is_set():
        ev["value"]["during_speedtest"] = True
        load_only = [s for s in soft if s.startswith(("gateway ", "DNS "))]
        if load_only:
            ev["value"]["slow_under_own_load"] = load_only
            soft = [s for s in soft if s not in load_only]
    ev["outcome"] = "fail" if problems else ("degraded" if soft else "ok")
    if problems or soft:
        ev["error"] = "; ".join(problems + soft)
    emit(ev)


def apps():
    if not _on_target.is_set():           # on the wrong network: measuring it would mislead
        return
    for name, url, want, t_ms in APPS:
        ev = make("wifi_app", target=name)
        code, out = run(["curl", "-sS", "--interface", IFACE, "--max-time", "10", "-o", "/dev/null",
                         "-A", "exm-wifi/" + AGENT_VER, "-w", "%{json}", url], 15)
        try:
            j = json.loads(out) if out.strip().startswith("{") else {}
        except ValueError:
            j = {}
        status, ttfb = j.get("http_code") or 0, j.get("time_starttransfer")
        sample = round(ttfb * 1000, 2) if ttfb else None
        ev["value"] = {"url": url, "http_code": status, "t_ms": t_ms, "sample_ms": sample,
                       "remote_ip": j.get("remote_ip"), "http_version": j.get("http_version")}
        ev["phase_ms"] = {"sample": sample}
        if code != 0 or not status:
            ev["outcome"], ev["error"] = "fail", (j.get("errormsg") or "curl failed (%s)" % code)[:200]
        elif status != want:
            ev["outcome"], ev["error"] = "fail", "HTTP %s, expected %s" % (status, want)
        elif sample <= t_ms:
            ev["outcome"] = "ok"
        elif sample <= 4 * t_ms:
            ev["outcome"] = "degraded"
        else:
            ev["outcome"], ev["error"] = "fail", "took %.0f ms (T %d ms)" % (sample, t_ms)
        emit(ev)


def speed():
    if not _on_target.is_set():
        return
    ev = make("wifi_speed", target="networkQuality")
    _speed_running.set()
    try:
        code, out = run(["networkQuality", "-I", IFACE, "-c"], 120)
    finally:
        time.sleep(5)                  # let queues drain before heartbeats count slowness again
        _speed_running.clear()
    try:
        j = json.loads(out)
    except ValueError:
        j = {}
    dl, ul = j.get("dl_throughput"), j.get("ul_throughput")
    ev["value"] = {"down_mbps": round(dl / 1e6, 1) if dl else None, "up_mbps": round(ul / 1e6, 1) if ul else None,
                   "responsiveness_rpm": j.get("responsiveness"), "base_rtt_ms": j.get("base_rtt"),
                   "interface": j.get("interface_name")}
    if dl:
        ev["outcome"] = "ok"
    else:
        ev["outcome"], ev["error"] = "fail", (j.get("error_description") or out.strip()[-200:] or "networkQuality failed")
    emit(ev)


def every(seconds, fn, first_delay):
    def loop():
        time.sleep(first_delay)
        while True:
            t0 = time.time()
            try:
                fn()
            except Exception as exc:                      # one bad run must not stop the agent
                print("%s %s failed: %s" % (iso(), fn.__name__, exc), file=sys.stderr, flush=True)
            time.sleep(max(1.0, seconds - (time.time() - t0)))
    threading.Thread(target=loop, daemon=True).start()


def main():
    print("%s exm-wifi %s starting: probe %s, interface %s, results %s" % (iso(), AGENT_VER, PROBE, IFACE, CURRENT),
          file=sys.stderr, flush=True)
    every(60, apps, 15)
    every(1800, speed, 300)
    n = 0
    while True:
        time.sleep(10 - (time.time() % 10))            # on the 10 s grid, like the wired heartbeat
        try:
            heartbeat(n)
        except Exception as exc:
            print("%s heartbeat failed: %s" % (iso(), exc), file=sys.stderr, flush=True)
        n += 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--once", "--apps", "--speed"):
        {"--once": lambda: heartbeat(0), "--apps": apps, "--speed": speed}[sys.argv[1]]()
        print(open(CURRENT).read().splitlines()[-1])
    else:
        main()
