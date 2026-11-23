"""Multigig ceiling of the real exp-speedtest server, without a browser.

N raw-socket clients run /st/down and /st/up against a private exp-speedtest process (bench limits);
the server's CPU comes from /proc.

    python3 lab/cr-lab/bench/box_bench.py [--secs 3] [--streams 1,4,8] [--dirs down,up]

Run it from a repository checkout with the speedtest dev environment (as for `pytest speedtest`). Loopback
numbers show the server's CPU cost per Gb/s; a real NIC run needs the clients on another machine.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(REPO / "test" / "fakes"), str(REPO / "speedtest" / "tests"), str(REPO / "speedtest"),
                str(REPO / "shared" / "python")]
from test_bench import Server, download, new_session  # noqa: E402  (bench reuses the A6.2 harness)

UP_CHUNK = 100_000_000          # the server's per-request upload cap


def upload(port: int, token: str, stop_at: float, out: list[int]) -> None:
    """Back-to-back 100 MB uploads; reconnects whenever the server answers with ``Connection: close``."""
    block = memoryview(bytes(1 << 20))
    head = (f"POST /st/up HTTP/1.1\r\nHost: x\r\nX-Exp-Leg-Token: {token}\r\n"
            f"Content-Type: application/octet-stream\r\nContent-Length: {UP_CHUNK}\r\n\r\n").encode()
    total, s = 0, None
    while time.monotonic() < stop_at:
        if s is None:
            s = socket.create_connection(("127.0.0.1", port), timeout=20)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        s.sendall(head)
        left = UP_CHUNK
        try:
            while left:
                n = min(left, len(block))
                s.sendall(block[:n])
                left -= n
        except OSError as e:  # refused mid-body (e.g. 413 budget): report the answer, stop this stream
            s.settimeout(2)
            try:
                why = s.recv(300).decode(errors="replace").replace("\r\n", " | ")
            except OSError:
                why = ""
            print(json.dumps({"stream_stopped": str(e), "after_bytes": total, "server_said": why[:300]}),
                  file=sys.stderr)
            break
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                raise RuntimeError("server closed before answering")
            resp += chunk
        if not resp.startswith(b"HTTP/1.1 204"):
            raise RuntimeError(resp[:120].decode(errors="replace"))
        total += UP_CHUNK
        if b"connection: close" in resp.lower():
            s.close()
            s = None
    if s is not None:
        s.close()
    out.append(total)


def run(direction: str, streams: int, secs: float) -> dict[str, float | int | str]:
    with tempfile.TemporaryDirectory() as td:
        srv = Server(Path(td))
        try:
            tokens = [new_session(srv.port) for _ in range(streams)]
            out: list[int] = []
            fn = download if direction == "down" else upload
            cpu0, t0 = srv.cpu_s(), time.monotonic()
            threads = [threading.Thread(target=fn, args=(srv.port, t, t0 + secs, out)) for t in tokens]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            wall = time.monotonic() - t0
            gbps = sum(out) * 8 / wall / 1e9
            cores = (srv.cpu_s() - cpu0) / wall
            return {"dir": direction, "streams": streams, "gbps": round(gbps, 2),
                    "server_cores": round(cores, 2),
                    "cores_per_gbps": round(cores / gbps, 3) if gbps else None}
        finally:
            srv.stop()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    # each session has a 10 GB bench budget: 3 s fits one fast stream
    ap.add_argument("--secs", type=float, default=3)
    ap.add_argument("--streams", default="1,4,8")
    ap.add_argument("--dirs", default="down,up")
    a = ap.parse_args()
    for d in a.dirs.split(","):
        for n in (int(x) for x in a.streams.split(",")):
            print(json.dumps(run(d, n, a.secs)), flush=True)


if __name__ == "__main__":
    main()
