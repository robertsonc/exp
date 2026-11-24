"""A6.2: the on-network leg sustains >= 2 Gb/s aggregate download over loopback on this 4-core box using <= 1 core per Gb/s,
and the server's byte counters agree with the clients' totals within 5 %.

The server runs as its own process (``bin/exp-speedtest run``) so its CPU is measured from /proc/<pid>/stat, not polluted
by the load generator. ``pytest speedtest -m bench`` runs the full benchmark (6 s, 4 streams); a 1.5 s smoke runs in the
normal suite and checks the counter agreement and a sane floor.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from exp_common import ids
from exp_common import speedtest as st
from stbox import SENTINEL_ID, base_config, free_port, wait_for

BIN = Path(__file__).resolve().parents[1] / "bin" / "exp-speedtest"
CHUNK = 25_000_000
STOPS: list[str] = []          # why a download stream ended early (budget), for the assertions' messages
TICKS = os.sysconf("SC_CLK_TCK")


class Server:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.run_dir, self.state, creds = tmp / "run", tmp / "state", tmp / "creds"
        creds.mkdir()
        (creds / "collector_token").write_text(ids.new_token("exps"))
        (creds / "runner_channel_token_sha256").write_text("0" * 64)
        why = ""
        for attempt in range(5):
            self.port = free_port()
            doc = base_config("https://127.0.0.1:9", "AA:" * 31 + "AA", self.port, free_port(udp_too=True), free_port(),
                              limits={"tests_per_10min_per_ip": 1000, "max_concurrent_per_ip": 100, "max_concurrent_tests": 100,
                                      "bytes_local": 10_000_000_000, "leg_token_ttl_s": 300},
                              dns_leg={"enabled": False})
            (tmp / "config.json").write_text(json.dumps(doc))
            log = tmp / f"server-{attempt}.log"
            with log.open("wb") as fh:
                self.proc = subprocess.Popen([sys.executable, str(BIN), "run", "--config", str(tmp / "config.json"),  # noqa: S603
                                              "--creds-dir", str(creds), "--state-dir", str(self.state), "--run-dir",
                                              str(self.run_dir), "--assets-dir", str(tmp / "a")],
                                             stdout=fh, stderr=subprocess.STDOUT, env={**os.environ, "PYTHONPATH": ""})
            # Ready = OUR process reports it is listening on OUR port. A bare connect() is not enough: if this port was
            # taken in the meantime, the server exits on bind and whatever holds the port would answer the benchmark.
            if wait_for(self._up, 20) and self.proc.poll() is None:
                return
            why = log.read_text(errors="replace")[-400:]
            self.stop()
        raise AssertionError(f"server did not start after 5 attempts; last log: {why}")

    def _up(self) -> bool:
        if self.proc.poll() is not None:
            return True                                     # exited: stop waiting, the caller sees it is not ours
        try:
            doc = json.loads((self.run_dir / "status.json").read_text())
        except (OSError, ValueError):
            return False
        return bool((doc.get("listening") or {}).get("http")) and (doc.get("listening") or {}).get("port") == self.port

    def cpu_s(self) -> float:
        f = Path(f"/proc/{self.proc.pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / TICKS             # utime + stime (fields 14, 15 of the full line)

    def server_bytes(self, after: float) -> int:
        """The byte counter from a status snapshot written after `after` (wall clock, the daemon's `ts`). The file refreshes
        every 2 s, later when the host is loaded (a whole test suite in parallel), so a fixed sleep can read a stale counter."""
        deadline = time.monotonic() + 20
        while True:
            try:
                doc = json.loads((self.run_dir / "status.json").read_text())
                if float(doc.get("ts", 0)) >= after:
                    return int(doc["counters"]["local_bytes_total"])
            except (OSError, ValueError, KeyError):
                pass                                          # not written yet / caught mid-write: read again
            if time.monotonic() > deadline:
                raise AssertionError(f"no status snapshot newer than {after:.1f} within 20 s")
            time.sleep(0.2)

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def new_session(port: int) -> str:
    import http.client
    key = st.new_view_key()
    proof = st.view_proof(key, SENTINEL_ID)
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", "/st/api/v1/sessions", body=json.dumps({"consent": {"text_version": 3}, "view_verifier": st.view_verifier(proof)}))
    r = c.getresponse()
    doc = json.loads(r.read())
    c.close()
    assert r.status == 201, doc
    return doc["leg_token"]


def download(port: int, token: str, stop_at: float, out: list[int]) -> None:
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    buf = bytearray(1 << 20)
    mv = memoryview(buf)
    total = 0
    req = f"GET /st/down?bytes={CHUNK} HTTP/1.1\r\nHost: x\r\nX-Exp-Leg-Token: {token}\r\n\r\n".encode()
    try:
        while time.monotonic() < stop_at:
            s.sendall(req)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = s.recv(4096)
                if not chunk:
                    raise RuntimeError(f"server closed the connection after {total} bytes")
                head += chunk
            head, _, rest = head.partition(b"\r\n\r\n")
            if not head.startswith(b"HTTP/1.1 200"):
                # The session's byte budget running out ends this stream (on a fast runner 10 GB, the schema maximum,
                # goes in seconds); keep what moved and record the server's answer so a wrong cap stays visible.
                m = re.search(rb"content-length: *(\d+)", head, re.I)
                body = rest
                while m and len(body) < int(m.group(1)):
                    more = s.recv(4096)
                    if not more:
                        break
                    body += more
                status = head.split(b"\r\n", 1)[0].decode(errors="replace")
                STOPS.append(f"{status} after {total} bytes: {body[:200].decode(errors='replace')}")
                break
            got = len(rest)
            while got < CHUNK:
                n = s.recv_into(mv)
                if n == 0:
                    raise RuntimeError("short body")
                got += n
            total += CHUNK
    finally:
        s.close()
        out.append(total)


def measure(seconds: float, streams: int, tmp: Path) -> dict[str, Any]:
    STOPS.clear()
    srv = Server(tmp)
    try:
        tokens = [new_session(srv.port) for _ in range(streams)]
        out: list[int] = []
        cpu0, t0 = srv.cpu_s(), time.monotonic()
        stop_at = t0 + seconds
        threads = [threading.Thread(target=download, args=(srv.port, tok, stop_at, out)) for tok in tokens]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall = time.monotonic() - t0
        cpu = srv.cpu_s() - cpu0
        client_bytes = sum(out)
        server_bytes = srv.server_bytes(after=time.time() + 0.5)   # + the server's last in-flight segments
        gbps = client_bytes * 8 / wall / 1e9
        return {"gbps": gbps, "cpu_cores": cpu / wall, "cores_per_gbps": (cpu / wall) / gbps if gbps else 99.0,
                "client_bytes": client_bytes, "server_bytes": server_bytes,
                "disagreement": abs(client_bytes - server_bytes) / max(client_bytes, 1), "wall": wall,
                "stops": list(STOPS)}
    finally:
        srv.stop()


def test_smoke_counters_agree_and_the_server_moves_bytes(tmp_path: Path):
    r = measure(1.5, 2, tmp_path)
    assert r["client_bytes"] > 50_000_000 and r["gbps"] > 0.2, r
    assert r["disagreement"] < 0.05, r


@pytest.mark.bench
def test_bench_local_leg_throughput_and_cpu(tmp_path: Path):
    r = measure(6.0, 4, tmp_path)
    print("\nBENCH", json.dumps({k: round(v, 3) for k, v in r.items()}))
    assert r["gbps"] >= 2.0, r
    assert r["cores_per_gbps"] <= 1.0, r
    assert r["disagreement"] < 0.05, r
