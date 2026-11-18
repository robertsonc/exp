"""Public speed tests. Heavy: one client at a time, chosen by `speedtest-next`.

Every provider records idle and loaded latency, because bufferbloat (loaded
minus idle) hurts attendees more than raw Mbps. Latency is the TCP connect time
of fresh connections to the test host, sampled before and during each transfer.

  cloudflare  speed.cloudflare.com __down / __up endpoints (unofficial, no key)
  fastcom     Netflix fast.com: token scraped from the page's JS, then OCA
              downloads. No supported API, so anything failing before bytes
              move is a harness_error, never a network failure.
  ndt7        M-Lab, only if an `ndt7-client` binary is installed and enabled.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.parse

from . import config as C
from . import events

CF_HOST = "https://speed.cloudflare.com"


def _connect_ms(url, timeout=5):
    r = subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", str(timeout), "-w", "%{time_connect}", url],
                       capture_output=True, text=True)
    try:
        v = float(r.stdout.strip())
        return events.ms(v) if v > 0 else None
    except ValueError:
        return None


class _LoadedProbe(threading.Thread):
    """Samples connect latency while a transfer runs."""

    def __init__(self, url):
        super().__init__(daemon=True)
        self.url, self.samples, self._halt = url, [], threading.Event()

    def run(self):
        time.sleep(0.5)                      # let the transfer ramp first
        while not self._halt.is_set():
            v = _connect_ms(self.url, timeout=3)
            if v is not None:
                self.samples.append(v)
            self._halt.wait(0.3)

    def stop(self):
        self._halt.set()
        self.join(timeout=6)
        return self.samples


def _upload_file(nbytes: int) -> str:
    """A cached file of random bytes to upload, kept in /run (RAM), rebuilt if the size changes."""
    os.makedirs(C.RUN_DIR, exist_ok=True)
    path = os.path.join(C.RUN_DIR, f"upload-{nbytes}.bin")
    if not os.path.exists(path) or os.path.getsize(path) != nbytes:
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            left, chunk = nbytes, os.urandom(1 << 20)
            while left > 0:
                fh.write(chunk[:min(left, len(chunk))])
                left -= len(chunk)
        os.replace(tmp, path)
    return path


def _curl_json(args, timeout):
    r = subprocess.run(["curl", "-sS", "-w", "%{json}", "--max-time", str(timeout)] + args,
                       capture_output=True, text=True, timeout=timeout + 10)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1]), r.stderr.strip()
    except (json.JSONDecodeError, IndexError):
        return {}, r.stderr.strip()


def _parallel(jobs):
    """Run curl jobs concurrently; returns (results, wall seconds)."""
    results = [None] * len(jobs)

    def go(i, fn):
        results[i] = fn()
    threads = [threading.Thread(target=go, args=(i, fn)) for i, fn in enumerate(jobs)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results, time.perf_counter() - t0


def _transfer(latency_url, jobs):
    probe = _LoadedProbe(latency_url)
    probe.start()
    results, wall = _parallel(jobs)
    return results, wall, probe.stop()


def _finish(cfg, client, ev, idle, loaded_down, loaded_up):
    s = cfg["speedtest"]
    ev["phase_ms"]["idle_rtt"] = events.median(idle)
    ev["phase_ms"]["loaded_rtt_down"] = events.median(loaded_down)
    ev["phase_ms"]["loaded_rtt_up"] = events.median(loaded_up)
    if len(idle) > 1:
        ev["phase_ms"]["idle_jitter"] = round(sum(abs(a - b) for a, b in zip(idle, idle[1:])) / (len(idle) - 1), 2)
    worst_loaded = max([x for x in (ev["phase_ms"]["loaded_rtt_down"], ev["phase_ms"]["loaded_rtt_up"]) if x is not None],
                       default=None)
    bloat = round(worst_loaded - ev["phase_ms"]["idle_rtt"], 2) if worst_loaded is not None and ev["phase_ms"]["idle_rtt"] is not None else None
    ev["value"]["bufferbloat_ms"] = bloat
    if ev["outcome"] is None:
        ev["outcome"] = C.DEGRADED if bloat is not None and bloat > float(s.get("loaded_latency_degraded_ms", 100)) else C.OK
    v = ev["value"]
    summary = (f"speedtest {client['id']} {ev['target']} outcome={ev['outcome']} down={v.get('down_mbps')}Mbps "
               f"up={v.get('up_mbps')}Mbps idle={ev['phase_ms']['idle_rtt']}ms bloat={bloat}ms")
    if ev.get("error"):
        summary += f" error={ev['error']}"
    events.emit(cfg, ev, summary)


def cloudflare(cfg, client):
    s = cfg["speedtest"]
    ev = events.make(cfg, client, "speedtest", target="cloudflare")
    timeout = int(s.get("timeout_s", 60))
    streams = max(1, int(s.get("streams", 1)))
    lat_url = f"{CF_HOST}/__down?bytes=0"
    idle = [x for x in (_connect_ms(lat_url) for _ in range(int(s.get("latency_probes", 6)))) if x is not None]
    if not idle:
        ev["outcome"], ev["error"] = C.FAIL, "speed.cloudflare.com unreachable"
        events.emit(cfg, ev)
        return

    down_each = max(1, int(s.get("download_bytes", 50_000_000)) // streams)
    jobs = [lambda: _curl_json(["-o", "/dev/null", f"{CF_HOST}/__down?bytes={down_each}"], timeout) for _ in range(streams)]
    res, wall, loaded_down = _transfer(lat_url, jobs)
    got = sum(int(j.get("size_download") or 0) for j, _ in res)
    errs = [e or j.get("errormsg") for j, e in res if (j.get("exitcode") or 0) != 0]
    ev["value"].update({"down_bytes": got, "down_s": round(wall, 3), "streams": streams,
                        "down_mbps": round(got * 8 / wall / 1e6, 2) if wall and got else None})

    up_each = max(1, int(s.get("upload_bytes", 10_000_000)) // streams)
    up_file = _upload_file(up_each)
    jobs = [lambda: _curl_json(["-o", "/dev/null", "-X", "POST", "-H", "Content-Type: application/octet-stream",
                                "--data-binary", f"@{up_file}", f"{CF_HOST}/__up"], timeout)
            for _ in range(streams)]
    res, wall, loaded_up = _transfer(lat_url, jobs)
    sent = sum(int(j.get("size_upload") or 0) for j, _ in res)
    errs += [e or j.get("errormsg") for j, e in res if (j.get("exitcode") or 0) != 0]
    ev["value"].update({"up_bytes": sent, "up_s": round(wall, 3),
                        "up_mbps": round(sent * 8 / wall / 1e6, 2) if wall and sent else None,
                        "remote_ip": (res[0][0] or {}).get("remote_ip") if res else None})
    if not got or not sent:
        ev["outcome"] = C.FAIL
        ev["error"] = "; ".join(e for e in errs if e)[:300] or "transfer moved no bytes"
    elif errs:
        ev["outcome"] = C.DEGRADED
        ev["error"] = "; ".join(e for e in errs if e)[:300]
    _finish(cfg, client, ev, idle, loaded_down, loaded_up)


def fastcom(cfg, client):
    s = cfg["speedtest"]
    ev = events.make(cfg, client, "speedtest", target="fastcom")
    timeout = int(s.get("timeout_s", 60))
    try:
        html = subprocess.run(["curl", "-sS", "--max-time", "10", "https://fast.com/"], capture_output=True, text=True).stdout
        js = re.search(r'src="(/app-[^"]+\.js)"', html).group(1)
        script = subprocess.run(["curl", "-sS", "--max-time", "10", "https://fast.com" + js], capture_output=True, text=True).stdout
        token = re.search(r'token:"([A-Za-z0-9]+)"', script).group(1)
        api = subprocess.run(["curl", "-sS", "--max-time", "10",
                              f"https://api.fast.com/netflix/speedtest/v2?https=true&token={token}&urlCount=3"],
                             capture_output=True, text=True).stdout
        targets = [t["url"] for t in json.loads(api)["targets"]]
        if not targets:
            raise ValueError("API returned no targets")
    except Exception as exc:
        ev["outcome"] = C.HARNESS
        ev["error"] = f"fast.com bootstrap failed (no supported API, page may have changed): {type(exc).__name__}: {exc}"
        events.emit(cfg, ev)
        return

    host = urllib.parse.urlsplit(targets[0])
    lat_url = f"{host.scheme}://{host.netloc}/"
    idle = [x for x in (_connect_ms(lat_url) for _ in range(int(s.get("latency_probes", 6)))) if x is not None]
    each = max(1, int(s.get("download_bytes", 50_000_000)) // len(targets))
    # fast.com's own client asks each OCA for a byte range by path.
    urls = [u.replace("/speedtest", f"/speedtest/range/0-{each - 1}", 1) for u in targets]
    jobs = [lambda u=u: _curl_json(["-o", "/dev/null", u], timeout) for u in urls]
    res, wall, loaded = _transfer(lat_url, jobs)
    got = sum(int(j.get("size_download") or 0) for j, _ in res)
    ev["value"].update({"down_bytes": got, "down_s": round(wall, 3), "targets": len(urls),
                        "oca_host": host.netloc,
                        "down_mbps": round(got * 8 / wall / 1e6, 2) if wall and got else None})
    if not got:
        ev["outcome"] = C.FAIL
        ev["error"] = "; ".join(filter(None, (e or j.get("errormsg") for j, e in res)))[:300] or "no bytes from Netflix OCA"
    _finish(cfg, client, ev, idle, loaded, [])


def ndt7(cfg, client):
    ev = events.make(cfg, client, "speedtest", target="ndt7")
    binary = shutil.which("ndt7-client")
    if not binary:
        ev["outcome"], ev["error"] = C.HARNESS, "ndt7-client not installed"
        events.emit(cfg, ev)
        return
    r = subprocess.run([binary, "-format", "json", "-quiet"], capture_output=True, text=True,
                       timeout=int(cfg["speedtest"].get("timeout_s", 60)) * 2)
    summary = {}
    for line in r.stdout.splitlines():
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "Download" in j and isinstance(j["Download"], dict):
            summary = j
    if not summary:
        ev["outcome"], ev["error"] = C.FAIL, (r.stderr.strip() or "no ndt7 summary")[:300]
        events.emit(cfg, ev)
        return
    dl, ul = summary.get("Download", {}), summary.get("Upload", {})
    ev["value"].update({"server": summary.get("ServerFQDN"),
                        "down_mbps": round(dl.get("Throughput", {}).get("Value", 0), 2),
                        "up_mbps": round(ul.get("Throughput", {}).get("Value", 0), 2),
                        "retrans_pct": dl.get("Retransmission", {}).get("Value")})
    ev["phase_ms"]["min_rtt"] = dl.get("Latency", {}).get("Value")
    ev["outcome"] = C.OK
    events.emit(cfg, ev)


PROVIDERS = {"cloudflare": cloudflare, "fastcom": fastcom, "ndt7": ndt7}


def run(cfg: dict, client: dict, provider: str) -> None:
    fn = PROVIDERS.get(provider)
    if fn is None:
        ev = events.make(cfg, client, "speedtest", target=provider)
        ev["outcome"], ev["error"] = C.HARNESS, f"unknown provider {provider}"
        events.emit(cfg, ev)
        return
    fn(cfg, client)
