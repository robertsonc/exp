# 07 — Security

exp runs root-level software on hosts, sits on a network full of strangers (attendees), holds
credentials that can reconfigure production SD-WAN appliances (drills), and is administered from
the internet. Security requirements here are **acceptance criteria**, not advice: each `SR-n` has a
test.

## 1. Assets

| Asset | Where | Impact if lost |
|---|---|---|
| Release signing key (Ed25519 private) | offline / CI secret with environment protection | arbitrary code on every host |
| `EXP_MASTER_KEY` | Worker secret (+ offline backup) | all stored secrets readable |
| Admin identities | Cloudflare Access + IdP | full control of the platform |
| Integration credentials (EC Orchestrator API key, Mist token) | manager (encrypted), runner creds | network outage caused on purpose |
| Agent secrets | host `/etc/exp/agent.json`, manager (hash) | that host's desired state + creds |
| Ingest / API / NOC tokens, `sso_secret` | component creds, manager (encrypted/hash) | data injection or read access for one component |
| Webhook URLs | manager (encrypted), collector creds | spam into NOC channels |
| Telemetry (IPs, SSIDs, topology, outage history) | collectors (on-prem) | reconnaissance of the event network |

## 2. Trust boundaries

1. **Internet ↔ Cloudflare** — admins (Access) and agents (bearer secrets).
2. **Event network (hostile: attendees) ↔ probe test ports.** Test ports are deliberately on it.
   They expose nothing except target-server ports, which are intended to be reached.
3. **Test-port namespaces ↔ management network.** No routing between them: namespaces have no
   route to the mgmt network, and the host never forwards between test ports and mgmt.
4. **Management network ↔ collector/dashboard.** Collectors and dashboards bind to mgmt addresses
   only — never to test ports.
5. **Runner ↔ Orchestrator / Mist APIs** — the most dangerous credentials in the system.

## 3. Threats and required mitigations

| # | Threat | Mitigations (requirements) |
|---|---|---|
| T1 | Forged or abusive measurements (compromised probe, LAN attacker) | **SR-1** per-probe tokens; **SR-2** identity binding (`probe`/`site` must match the token); **SR-3** schema bounds and reserved labels (`shared/SCHEMA.md`); **SR-4** ingest size, line, rate limits; zip-bomb guard. |
| T2 | Attendee reaching collector/dashboard | **SR-5** collector/dashboard listen on mgmt IPs only; auth on every route except `/healthz`; TLS everywhere. |
| T3 | Stolen agent secret | **SR-6** the secret only unlocks that host's desired state and artifacts referenced by it; it cannot enrol hosts or read other hosts; revocable and rotatable; rate-limited. |
| T4 | Leaked enrol token | **SR-7** single-use, 1-hour TTL, bound to one pre-created host record, sent only in a POST body, atomic consumption; the UI shows the enrolled host's facts (hostname, machine-id, IP) so a wrong enrolment is obvious and revocable. Optional `require_enrol_approval` setting holds new hosts until an admin approves. |
| T5 | Manager compromise | **SR-8** hosts install only artifacts signed by the offline release key (a compromised manager cannot push code); the manager cannot run commands on hosts (declarative agent, fixed operations); all changes audited. Residual risk (config redirection of telemetry) accepted and documented. |
| T6 | Admin account takeover | **SR-9** Access + Worker-side JWT verification on every admin request (fail closed); IdP MFA recommended in the deploy guide; two-person approval available for drills; audit log. |
| T7 | Release key theft | **SR-10** key never in the repo or on the manager; CI uses an environment-protected secret; documented rotation: a new public key ships inside a release signed by the current key, and agents accept the new key only from such a release. |
| T8 | Supply chain | **SR-11** vendored dependencies pinned by version **and** sha256; VictoriaMetrics verified against upstream checksums at build time; reproducible tarballs; CI tokens least-privilege; dependency and secret scanning in CI. |
| T9 | Drill misuse or runaway drill | **SR-12** all guardrails in `10-drills-integrations.md` §4 (off by default, allowlist, time box, revert-intent persisted before the fault, kill switch ≤ 5 s, preconditions, one external drill per site, audit). |
| T10 | XSS/CSRF via probe-supplied text | **SR-13** UIs insert untrusted text with `textContent` only; strict CSP without inline script; CSRF token + Origin check on state-changing requests; secure cookies (`__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`). |
| T11 | Secret leakage via logs/argv/status | **SR-14** secrets never in logs, argv, status reports, diagnostics, error messages, or API responses; token prefixes enable scanning; CI and acceptance tests scan journals/logs/D1 dumps for `exp[aeidnsrlktv]_` patterns (all eleven token prefixes, M6) and webhook URLs. |
| T12 | SSRF via configured URLs | **SR-15** webhook and integration URLs must be `https`; webhooks to private, loopback, or link-local addresses are refused unless explicitly allowlisted; redirects not followed for webhooks. (Probe app tests fetching configured URLs on the event network are the feature, not SSRF.) |
| T13 | DoS of the manager | **SR-16** rate limits on enrol/agent/admin routes; `304` hot path is one indexed read; bounded request sizes. |
| T14 | Privilege escalation on hosts | **SR-17** dedicated service users; systemd hardening per unit; safe unpack (tar slip, symlinks, setuid); no recursive or symlink-following `chown`; paths confined to allowed roots; no `shell=True`. |
| T15 | Address theft / network harm by probes | **SR-18** target ports claim an address only after an RFC 5227 probe gets no reply (fail closed); DHCP heartbeat is DISCOVER-only; traceroute pacing; throughput tests serialized and rate-bounded; preflight never touches the mgmt interface. |
| T16 | Clock manipulation | **SR-19** ingest time window; skew metric; NTP status in facts. |
| T17 | Privacy | **SR-20** telemetry stays on-prem; the manager stores host facts only; probe DHCP hostnames carry no personal data; Wi-Fi credentials are secrets. |
| T18 | Public speedtest abuse (bandwidth sink, DoS of the event WAN, injected text) — M6 | **SR-21** strict validation and rate/size limits on the unauthenticated page; **SR-22** local-leg endpoints need short-lived session tokens with byte budgets, the path timer probes only configured hops, the DNS-leg server answers only its zone; **SR-23** user text is untrusted, `textContent` only. (`12-speedtest-analytics.md` §10) |
| T19 | Personal data in speedtest evidence (IP, MAC, username, flows, security logs) — M6 | **SR-24** syslog receiver allowlisted, rate-limited, bounded, 60-min expiry unless attached; **SR-25** no name/email anywhere, device/network metadata kept for the configured window (default 30 d, no automatic raw-identifier scrub; optional `scrub_after_diagnosis`), keyed `device_key` (per-org `expk_` secret, never on the manager's results path), purge tooling, exports and the dashboard without raw identifiers unless the admin role asks (`identifiers=true`). (`12-speedtest-analytics.md` §9–10, `01-contracts.md` §14, `changes/CR-m6-spec-resolutions.md`) |
| T20 | Page integrity and session theft over plain HTTP; wrong-device binding behind NAT — M6 | **SR-26** plain HTTP is the default (D15): the page carries no credentials, the leg token (`expt_`) is 60 s / single-session / byte-budgeted / memory-only, results are bound server-side to the observed client IP and never trusted from the wire, the result key travels only in the URL fragment and as an `expv_` proof header (`01-contracts.md` §14.2), servers never log headers; page integrity is a residual risk accepted for the event LAN (`tls.mode = provided` removes it). Identity resolution **fails closed** on NAT (outside client subnets, translated address, 0 or > 1 Mist MACs). |
| T21 | Unauthenticated read of the manager from a trusted network (`/kiosk`) widened beyond its purpose | **SR-27** the kiosk is a separate surface, not an Access bypass of the admin app: GET `/kiosk` and `/kiosk/api/devices` only, device **counts** and the devices that are **down** by name, type, site and down-since only (≤ 200 per platform; no serials, MACs, IPs, vendor errors or connector state; owner decision 2026-11-28, CR-kiosk-down-devices); gated by an Access bypass app for exactly the configured CIDRs AND by the Worker on `CF-Connecting-IP` against `KIOSK_ALLOW_CIDRS` (empty or unparsable = no kiosk, 404); prefixes no wider than IPv4 /16 or IPv6 /32; the admin API still requires a verified Access JWT from every source. Residual risk: everyone behind an allowed egress address sees the counts and the names and sites of down devices, so the allowlist must be an egress used only by the management network. |
| T22 | Probe on an untrusted public Wi-Fi network (other clients, a captive portal, a rogue AP with the same SSID) — M4 | **SR-28** the Wi-Fi radio lives in its own namespace and only originates traffic: no service listens there (the kernel still answers ICMP echo; the DHCP client is the only socket), and measurements ship over the management interface, never over Wi-Fi. Open / OWE only, so no credential exists to leak; the supplicant config lists only the target SSID (hex-encoded, no config injection) and is root `0600` under `/run`. A captive portal is reported, never clicked through. Residual risk: an open SSID can be spoofed by a rogue AP (OWE does not authenticate the AP); the probe then measures the rogue network, which `bssid` in every beat makes visible. |

## 4. Lessons carried in as requirements

From EXM, the SASE TestDrive assessment, and lab work:
- **Verify enforcement, not configuration.** Every control (Access JWT check, rate limits, token
  binding, drill guardrails) has a test that proves a bad request is refused. A Conditional Access
  policy once sat in *report-only* mode and looked "configured" for weeks.
- **Provisioning endpoints are attack surface.** An unauthenticated, unthrottled account-minting
  endpoint accepted 170 anonymous requests in testing. Enrolment here is token-gated, single-use,
  rate-limited, and audited.
- **Least-privilege defaults.** Ship with drills off, registration/consent-style capabilities off,
  public read-only off.
- **Fail closed, never destructively.** Guards refuse and explain; they never power off or wipe
  (a guard that powered a host off once masqueraded as hardware failure).
- **Untrusted input everywhere a remote party writes.** Schema hardening went through two review
  rounds (`shared/SCHEMA.md`); keep its tests green.
- **Fixtures come from specs or recordings, not from the code under test** (Orchestrator field names).

## 5. Security testing (in CI and at milestone gates)

- Static analysis: `ruff` with security rules (bandit set) for Python; `eslint` + TypeScript strict
  for the Worker/UI; no `eval`/`innerHTML` with untrusted data (lint rule).
- Secret scanning (`gitleaks`) on every PR; dependency audit (`npm audit`, pinned-hash check for
  vendored Python).
- Fuzz/property tests for the ingest parser and `Measurement.validate()` (dev dependency
  `hypothesis`).
- Enforcement tests listed with each `SR-n` (component acceptance suites reference them).
- A manual penetration-test checklist before accepting M2 and M5: admin auth bypass attempts,
  enrol token reuse/race, agent secret scope, artifact authz, dashboard auth/CSRF/XSS, drill
  guardrail bypass, webhook SSRF.

### M6 speedtest requirements (SR-21 … SR-26) — confirmed

`12-speedtest-analytics.md` §10 defines SR-21…SR-26; they are accepted unchanged except as qualified by
`changes/CR-m6-spec-resolutions.md` (retention default 30 d with no automatic scrub; plain HTTP default; fail-closed NAT
guard). Each has its enforcement test, owned by the implementing WP and run at the M6 gate:

| SR | Enforcement (test that proves the bad request is refused) |
|---|---|
| SR-21 | oversized/malformed bodies, unknown keys, out-of-range numbers on every public route → 400/413; rate limits → 429 + `Retry-After`; a wrong or missing view proof → 404 (no enumeration); no internal address reflected to anyone but the key holder |
| SR-22 | `/st/ping|down|up` without, with expired or over-budget `expt_` → 401/413; the path timer refuses any target not configured or not the requesting client; the DNS-leg server refuses recursion, other zones, zone transfer; rate-limited |
| SR-23 | comment with HTML/control characters/over-length → refused or stored as text and rendered with `textContent` (XSS test on the result page and the dashboard); parameterized SQL only |
| SR-24 | syslog from a non-allowlisted source, over-rate, over-length lines → dropped and counted; ring rows expire at 60 min unless attached; nothing from a line is executed or followed |
| SR-25 | no name/email property in any wire schema (`test/fixtures` + `shared` tests) and none in any table (query); retention purge and `speedtest purge` leave no rows (end state); with `scrub_after_diagnosis` no raw IP/MAC/username/hostname remains after the final diagnosis (A6.6); VM aggregates carry no per-device labels (cardinality test); exports exclude raw identifiers without `identifiers=true` |
| SR-26 | the fragment key never appears in server logs/URLs; the leg token expires at 60 s and is refused for another session; a result from another source IP → 403; behind a translated source IP the test is `unresolved` + `nat_suspected` (A6.12) |
| SR-27 | `/kiosk*` from a source outside `KIOSK_ALLOW_CIDRS` → 403 (X-Forwarded-For / True-Client-IP ignored); with the variable empty → 404; the response has exactly `{kind, label, state, total, online, offline, by_type, counts_at, down, down_more}` per platform, each `down` entry exactly `{name, type, site, since}` (≤ 200), and no MAC / serial / address in the response or in `ops_device_status.down_json` (`kiosk.test.ts`, `ops-down.test.ts`); `/api/admin/v1/*` from a kiosk source without a JWT → 401; `deploy.sh --kiosk-allow-ip` plans an `ip` include per CIDR and never `everyone` (`kiosk.test.ts`, `test-deploy-dryrun.sh`) |
| SR-28 | the generated `wpa_supplicant.conf` is `0600`, has a hex SSID, `key_mgmt` only `OWE`/`NONE`, no `psk`/`password`, and a hostile SSID cannot add a `network=` block; the manager refuses a Wi-Fi port carrying `psk`/`password` or an unknown `security`; preflight refuses a radio shared with another interface (named when it is mgmt), rfkill, NetworkManager, or a foreign `wpa_supplicant` (`test_wifi_port.py`, `admin-api.test.ts`) |

## 6. Incident response procedures (documented in the admin guide)

- **Host compromised:** decommission or revoke its agent secret; rotate the site's ingest and API
  tokens (one action in the UI); review the audit log.
- **Manager suspected compromised:** rotate Access policy/admins, rotate `EXP_MASTER_KEY`
  (re-encrypt all secrets; supported by `deploy.sh rotate-master-key`), rotate all component tokens,
  review audit; hosts keep running and cannot receive unsigned code.
- **Release key suspected compromised:** stop importing releases, publish a key-rollover release
  signed with the old key if still trusted, otherwise re-enrol hosts with a new key.
- **Drill went wrong:** kill switch; runner reverts persisted intents; audit and run report.
