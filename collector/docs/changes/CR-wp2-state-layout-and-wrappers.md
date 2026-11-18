# CR-wp2-state-layout-and-wrappers

**From:** WP-2 (collector) - **Affects:** WP-6 (agent), WP-7 (packaging) - **Status:** proposed

## 1. State directory ownership
`01-contracts.md` section 11 says `/var/lib/exp/<component>/` is a root-owned directory with service-owned
subdirectories only, while `03-collector.md` section 4 puts the SQLite database at
`/var/lib/exp/collector/records.db`. SQLite (WAL) must create `-wal`/`-shm` files next to the database, so
the directory that holds `records.db` must be writable by `exp-collector`.

**Choice made (most conservative that works):** `exp-collector.service` uses `StateDirectory=exp/collector`
(systemd creates/chowns it to `exp-collector`), the database stays at `<state>/records.db` (mode 0600), TLS
material at `<state>/tls/{key,cert}.pem`, VM data at `<state>/vm`.

**Agent obligations before the first start (root, never following symlinks):**
- `@STATE@/tls/` owned `exp-collector:exp-collector` 0700 with `key.pem` 0600 and `cert.pem` 0644.
  The collector refuses a key readable by "other".
- `@STATE@/vm/` owned `exp-vm:exp-vm` 0700 (VictoriaMetrics data; the collector never reads it - VM size and
  series count come from VM's HTTP API on loopback).

## 2. VictoriaMetrics and iperf3 launch wrappers
The spec lists `ExecStart=@PREFIX@/vendor/victoria-metrics -retentionPeriod=...` and `iperf3 -s -p 5201`, but
also forbids interpolating config values into units. Shipped instead:
- `exp-victoriametrics.service`: `ExecStart=@PREFIX@/bin/exp-collector vm-exec --config @CONFIG@ --state-dir @STATE@`
  which validates the config and `execv`s `vendor/victoria-metrics` with an argv list (no shell, no env
  file, no word splitting). The resulting flags are exactly those of 03 section 1
  (`-httpListenAddr=127.0.0.1:8428 -retentionPeriod=<metrics_days>d -storageDataPath=<state>/vm
  -memory.allowedPercent=<pct> -search.maxQueryDuration=10s -search.maxSeries=500`);
  `exp-collector vm-args` prints them for inspection.
- `exp-iperf3.service`: `exp-collector iperf3-exec` -> `iperf3 -s -p <iperf3.port> -B <listen ip>` (so iperf3
  honours the table in 01 section 11, "collector mgmt IP", and the configured port; default 5201). Exits 0
  when `iperf3.enabled` is false.

## Compatibility
No contract change; unit file contents differ from the literal `ExecStart` lines in the spec. WP-7 must ship
`vendor/victoria-metrics` (sha256-pinned) at `<root>/vendor/victoria-metrics`.
