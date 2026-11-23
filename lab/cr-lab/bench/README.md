# Multigig bench (measure before building /mgig/)

Two separate ceilings, measured separately, so neither hides the other:

| Tool | Measures | Needs |
|---|---|---|
| `page/` + `nginx.conf` + `run-matrix.js` | what a **browser** can move over plain HTTP/1.1 (streams x host names x direction) against a known-fast reference server | nginx, a browser (or Playwright) |
| `box_bench.py` | what the **real exp-speedtest** server can move and at what CPU cost, with raw-socket clients (no browser) | a repo checkout with the dev venv (`.venv`) |

## Run

```bash
# reference server (port 8081) on the machine with the fast NIC
lab/cr-lab/bench/ref-server.sh start
# a real laptop: open http://<that machine>:8081/ and run down/up with 1, 4, 6 streams, then with 2 host names
#   (add m1/m2 names for the server to the laptop's hosts file or DNS; Chrome allows 6 connections per name)
# headless sweep from a Linux client:
node lab/cr-lab/bench/run-matrix.js --base http://<server ip>:8081 --secs 8
lab/cr-lab/bench/ref-server.sh stop

# exp-speedtest itself (loopback, on the box)
.venv/bin/python3 lab/cr-lab/bench/box_bench.py --streams 1,4,8
```

## First results (sandbox, loopback, 4 vCPU shared by client and server; indicative only)

| | 1 stream | 4 streams | 8+ streams |
|---|---|---|---|
| Browser download (headless Chromium -> nginx) | 6.3 Gb/s | 7.8-8.2 Gb/s | 7.8 Gb/s |
| Browser upload, Blob body (as the exp page sends) | 5.2 Gb/s | 5.7 Gb/s | 5.7 Gb/s |
| Browser upload, Uint8Array body | 0.2 Gb/s | 0.2 Gb/s | 0.1 Gb/s |
| exp-speedtest download (raw sockets) | 18 Gb/s, 1.0 core | 61 Gb/s, 1.6 cores | 62 Gb/s, 1.8 cores |
| exp-speedtest upload (raw sockets) | 31 Gb/s, 0.5 core | 77 Gb/s, 1.5 cores | 67 Gb/s, 1.4 cores |

Reading:

* The **server is not the limit**: about 0.02-0.06 core per Gb/s, so 10 Gb/s costs well under one core. No new upload
  receive path is needed for 10 G.
* The **browser saturates at 2-4 streams** here; extra host names added nothing because the run is CPU-bound with
  client and server on the same 4 cores. Whether a real NIC needs more than the 5 streams one host name allows is the
  open question for the laptop run.
* Chromium uploads an ArrayBuffer body ~25x slower than a Blob. The exp page already uses Blob bodies
  (`speedtest/page/src/local-leg.js` `uploadBlob`); any new upload code must too.
* The real blocker for multigig in exp today is the **per-test budget** (`limits.bytes_local`, 200 MB: ~0.2 s at 8 Gb/s)
  and the 8 s cap per direction, not throughput.

Loopback skips the NIC, the driver, RSS/flow pinning and the client's own NIC path, and the page's work on a phone or
laptop CPU. The numbers that decide the build come from a laptop with a >= 10 GbE NIC against the box over a real switch.
