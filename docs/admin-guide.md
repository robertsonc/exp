# exp admin guide

Day-1 and day-2 operation of an exp deployment. This file currently holds the **manual install** (milestone M1,
no manager); the manager-driven sections (deploy, add hosts, upgrades, rotation) are written with M2.
Specs: `SPEC.md` section 9, `docs/spec/01-contracts.md` sections 9-11, `docs/spec/08-operations.md`.

## Manual install (M1, no manager)

Install the data spine (probe, collector, dashboard) on Ubuntu 22.04/24.04 or Debian 12 (incl. 64-bit Raspberry Pi OS) hosts from the signed release tarballs and
config files you write yourself. `test/harness/install-manual.sh` does exactly what `exp-agent` would do (and the
M1 acceptance suite, `test/e2e/m1/`, runs it against the container LAN in `test/harness/`), so a manual install
and a managed one end up with the same layout.

### What you need

* The release directory: `exp-<version>-manifest.json`, `exp-<version>-manifest.json.sig` and the
  `exp-<component>-<version>-<arch>.tar.gz` files, plus the release public key `release-pub.pem`
  (`packaging/keys/release-pub.pem` in the repository; compare its fingerprint with the one the project publishes).
* Root on each host; `python3` and `openssl` (both are in a stock Ubuntu install). The installer installs the apt
  packages a component lists in its `requirements.apt` (`busybox iproute2 iputils-ping curl openssl iperf3`), and only
  packages on the agent allowlist.
* **Probe host:** one management NIC (it holds the default route; the probe talks to the collector over it) and one
  or more test NICs, **not** bridged, bonded or carrying an address; the probe refuses anything else and changes
  nothing. Every test port must be plugged into the event network.
* **Collector host:** a management IP that the probes and the dashboard can reach on TCP 8443.
* **Dashboard host:** TCP 443 (and 80, redirect only) reachable by operators; it may be the collector host.
* Time must be synchronised (NTP) on every host; skew over 5 s is flagged.

Shapes can share a host (all-in-one) or sit on different hosts (the collector and the probe on separate hosts is the
second layout the acceptance suite covers). Install in this order: **collector, dashboard, probe**, because the
dashboard and the probe pin the collector's TLS certificate by fingerprint.

### 1. Plan the identities

| Name | Example | Rules |
|---|---|---|
| site | `hall-b` | slug `[a-z0-9-]` |
| probe id | `probe-a1` | slug; one per probe host; also the identity of its ingest token |
| collector id | `col-hallb` | slug |
| dashboard id | `dash-main` | slug |

### 2. Create the credentials (on any trusted machine)

Tokens are `expi_` (probe ingest) and `expd_` (dashboard to collector) followed by 32 random bytes in URL-safe base64.
Servers store only the SHA-256 of a token; the client holds the token itself.

```bash
tok() { python3 -c 'import base64,secrets,sys; print(sys.argv[1] + "_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode())' "$1"; }
INGEST=$(tok expi)        # goes to the probe host   -> creds/ingest_token
DASHTOK=$(tok expd)       # goes to the dashboard    -> creds/collector_tokens.json
printf '%s' "$INGEST"  | sha256sum | cut -d' ' -f1     # goes to the collector -> ingest_tokens.json
printf '%s' "$DASHTOK" | sha256sum | cut -d' ' -f1     # goes to the collector -> dashboard_tokens.json
head -c 32 /dev/urandom | base64                         # dashboard sso_secret (unused until the manager exists)
# a local operator account for the dashboard (PBKDF2-SHA256, 600k iterations):
python3 -c 'import base64,getpass,hashlib,os; s=os.urandom(16); p=getpass.getpass(); print("pbkdf2_sha256$600000$%s$%s" % (base64.b64encode(s).decode(), base64.b64encode(hashlib.pbkdf2_hmac("sha256", p.encode(), s, 600000)).decode()))'
```

Keep the tokens and the password out of shell history and the repository.

### 3. Write the local config directory

One directory per host, `<conf>/<shape>/config.json` and `<conf>/<shape>/creds/<file>`. The files are the
`exp.<component>.config/1` documents of `docs/spec/01-contracts.md` section 9 (validated at install and at every
start; an invalid config makes the service refuse to start and print every problem). Minimal examples:

`collector/config.json` (the collector binds a **management IP**, never a wildcard):

```json
{"schema": "exp.collector.config/1", "collector_id": "col-hallb", "site": "hall-b", "listen": "10.32.98.25:8443",
 "probes": [{"probe_id": "probe-a1", "site": "hall-b", "label": "Hall B east"}],
 "dashboards": ["dash-main"],
 "retention": {"metrics_days": 30, "records_days": 7},
 "vm": {"listen": "127.0.0.1:8428", "memory_allowed_pct": 40},
 "rules": {"edge_label": "EC", "lines": ["network", "dhcp", "dns", "internet", "apps"]},
 "alerts": {"enabled": true, "board_url": "https://10.32.98.30", "timezone": "UTC", "voice": "sysadmin",
            "hold_down_s": 20, "hold_back_s": 60, "reopen_s": 300, "calm_s": 600},
 "reflector": {"enabled": false, "port": 8862}, "iperf3": {"enabled": false, "port": 5201},
 "ingest": {"max_body_mb": 4, "max_records": 1000}}
```
`collector/creds/ingest_tokens.json` = `{"probe-a1": "<sha256 of the ingest token>"}`,
`dashboard_tokens.json` = `{"dash-main": "<sha256 of the dashboard token>"}`, `webhooks.json` = `[]`.

`dashboard/config.json` (fill `tls_fingerprint_sha256` from step 4):

```json
{"schema": "exp.dashboard.config/1", "dashboard_id": "dash-main", "title": "HPE EXP - Hall B", "url": "https://10.32.98.30",
 "listen": {"https": "0.0.0.0:443", "http_redirect": "0.0.0.0:80"},
 "collectors": [{"collector_id": "col-hallb", "site": "hall-b", "url": "https://10.32.98.25:8443",
                 "tls_fingerprint_sha256": "AB:CD:..."}],
 "voice": "sysadmin", "timezone": "UTC",
 "auth": {"sso": {"manager_url": "https://exp-manager.invalid", "issuer": "exp-manager:default"},
          "session_hours": 12, "local_users": true, "noc_tokens": true},
 "tls": {"mode": "self_signed"}}
```
`dashboard/creds/`: `collector_tokens.json` = `{"col-hallb": "<the expd_ token>"}`, `sso_secret`,
`local_users.json` = `[{"username": "ops", "role": "operator", "hash": "<pbkdf2 line>"}]`, `noc_tokens.json` = `[]`.

`probe/config.json` (see `probe/README.md`; one `client` port per test NIC, `mgmt_iface` is the management NIC):

```json
{"schema": "exp.probe.config/1", "probe_id": "probe-a1", "site": "hall-b",
 "collector": {"url": "https://10.32.98.25:8443", "tls_fingerprint_sha256": "AB:CD:...", "fallback": []},
 "mode": "netns", "mgmt_iface": "eno1",
 "ports": [{"id": "c01", "iface": "enp10s0f0", "role": "client"}, {"id": "c02", "iface": "enp10s0f1", "role": "client"}],
 "tests": {"app": {"interval_s": 60, "targets": [{"app": "web", "url": "https://www.example.com/", "apdex_t_ms": 500}]}}}
```
`probe/creds/ingest_token` = the `expi_` token. Everything else (10 s heartbeat, ping 1.1.1.1/8.8.8.8, trace to 8.8.8.8
with the control path, the DNS names, spool 500 MB / 7 days) has defaults.

### 4. Install, in order

Copy the release directory, the public key, `test/harness/install-manual.sh` and the config directory to each host,
then as root:

```bash
install -d /etc/exp && install -m 0644 release-pub.pem /etc/exp/release-pub.pem
./install-manual.sh --conf /root/exp-conf /root/dist collector
#   ... prints:  FINGERPRINT collector AB:CD:EF:...   (also kept in /etc/exp/collector/tls_fingerprint)
# put that fingerprint into dashboard/config.json and probe/config.json, then:
./install-manual.sh --conf /root/exp-conf /root/dist dashboard
./install-manual.sh --conf /root/exp-conf /root/dist probe        # add --no-start to install without starting
```
`--pubkey FILE` names another public key. Several shapes can be given at once (`collector dashboard`); the installer
always processes them collector first. Re-running it upgrades or repairs in place (an unpacked version is reused,
units are rewritten, services restarted).

What it does, and refuses to do:

1. Verifies the manifest signature with `openssl pkeyutl -verify -rawin` against the public key, then every
   artifact's size and sha256 against the manifest. **A bad signature or hash is a refusal, never a warning.**
2. Unpacks safely (absolute paths, `..`, links, devices and oversized archives are refused) into a staging
   directory, renames it to `/opt/exp/<component>/<version>/`, flips `/opt/exp/<component>/current`, and links
   `/usr/local/bin/exp-<component>`.
3. Installs the component's `requirements.apt` packages (allowlist only) and creates the service users
   (`exp-collector`, `exp-vm`, `exp-dashboard`; the probe runs as root with systemd hardening).
4. Writes `/etc/exp/<component>/config.json` (0644) and `/etc/exp/<component>/creds/*` (root, 0600, directory 0700),
   plus an empty file for every `LoadCredential=` a unit names.
5. Prepares `/var/lib/exp/collector/{tls,vm}` and `/var/lib/exp/dashboard/tls` as in
   `docs/spec/changes/CR-wp2-state-layout-and-wrappers.md` and generates the self-signed P-256 certificates **on the
   host** (the key never leaves it).
6. Renders the unit templates (`@VERSION@ @PREFIX@ @CONFIG@ @CREDS@ @STATE@ @RUN@` only), `daemon-reload`, enables
   and starts: collector shape `exp-victoriametrics`, `exp-collector`, `exp-reflector`, `exp-iperf3`; dashboard shape
   `exp-dashboard`; probe shape `exp-probe-netns`, `exp-probe-lease@<port>` per client port, `exp-probe`.
7. Waits up to 60 s for `exp-<component> health --json` to pass.

### 5. Check it

```bash
systemctl status exp-collector exp-dashboard exp-probe             # all active
exp-collector health --json | python3 -m json.tool | head -30      # status ok, tls_fingerprint_sha256
exp-probe health --json; exp-probe spool stat                      # the shipper is draining the spool
```
Open `https://<dashboard>/`, accept the self-signed certificate after comparing its fingerprint with
`/etc/exp/dashboard/tls_fingerprint`, and sign in with the local account. All lines are green within 30 s of the probe
starting; the board updates every 10 s. If a line is unknown, wait one beat; if it stays so, read
`journalctl -u exp-probe -u exp-collector`.

### Troubleshooting the manual install

| Symptom | Likely cause |
|---|---|
| `manifest signature does not verify` | wrong `--pubkey`, or the release directory was modified; fetch it again |
| probe `netns up` exits 1, `REFUSED c01 (...)` | the reason is the fix (port has an address, is enslaved, is the management NIC); nothing was changed |
| probe health `tls_pin_mismatch` | the fingerprint in `probe/config.json` is not the collector's current one |
| probe health `auth_failed` | the sha256 in `ingest_tokens.json` does not match the token in `creds/ingest_token`, or the probe id differs |
| collector refuses to start: `credentials directory ... is not usable` | in a container, `/` is not a shared mount (`mount --make-rshared /`); never on a VM |
| dashboard shows "collector unreachable" | TCP 8443 blocked, wrong fingerprint in the dashboard config, or the `expd_` token and `dashboard_tokens.json` disagree |

### Running the same thing in containers (CI and development)

`make -C test/harness up` builds the simulated event LAN (bridge with a pinned MAC, gateway, edge and ISP routers,
dnsmasq DHCP+DNS, local HTTP(S) apps, answering 1.1.1.1 / 8.8.8.8; nothing needs the internet) and a systemd host with
three test ports; `make -C test/harness ci` runs the M1 acceptance suite. See `test/harness/README.md`.
