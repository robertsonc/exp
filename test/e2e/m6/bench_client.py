"""Load generator for A6.2, run INSIDE the core box with its own python3 (stdlib only): N keep-alive streams of
GET /st/down?bytes=<chunk> against the installed exp-speedtest, each stream with its own session and leg token (renewed on
budget/expiry). Prints one JSON line {bytes, seconds, gbps, requests, errors}."""
import http.client
import json
import sys
import threading
import time

host, port, streams, seconds, chunk = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
totals = {"bytes": 0, "requests": 0, "errors": 0}
lock = threading.Lock()
stop_at = time.monotonic() + seconds
VERIFIER = "0" * 64


def session(conn: http.client.HTTPConnection) -> str:
    body = json.dumps({"consent": {"text_version": 1}, "view_verifier": VERIFIER})
    conn.request("POST", "/st/api/v1/sessions", body, {"Content-Type": "application/json"})
    r = conn.getresponse()
    doc = json.loads(r.read())
    if r.status != 201:
        raise RuntimeError(f"session refused {r.status} {doc}")
    return doc["leg_token"]


def worker() -> None:
    buf = bytearray(1 << 20)
    mv = memoryview(buf)
    conn = http.client.HTTPConnection(host, port, timeout=30)
    token = session(conn)
    got = reqs = errs = 0
    while time.monotonic() < stop_at:
        try:
            conn.request("GET", f"/st/down?bytes={chunk}", headers={"X-Exp-Leg-Token": token})
            r = conn.getresponse()
            if r.status != 200:
                r.read()
                if r.status != 413:                 # 413 budget_exceeded = this session's byte budget is spent: renew, not an error
                    errs += 1
                token = session(conn)
                continue
            n = 0
            while True:
                k = r.readinto(mv)
                if not k:
                    break
                n += k
            got += n
            reqs += 1
        except Exception:  # noqa: BLE001
            errs += 1
            conn.close()
            conn = http.client.HTTPConnection(host, port, timeout=30)
            token = session(conn)
    with lock:
        totals["bytes"] += got
        totals["requests"] += reqs
        totals["errors"] += errs


t0 = time.monotonic()
ts = [threading.Thread(target=worker) for _ in range(streams)]
for t in ts:
    t.start()
for t in ts:
    t.join()
dt = time.monotonic() - t0
print(json.dumps({**totals, "seconds": round(dt, 3), "gbps": round(totals["bytes"] * 8 / dt / 1e9, 3)}))
