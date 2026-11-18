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
| T11 | Secret leakage via logs/argv/status | **SR-14** secrets never in logs, argv, status reports, diagnostics, error messages, or API responses; token prefixes enable scanning; CI and acceptance tests scan journals/logs/D1 dumps for `exp[aeidn]_` patterns and webhook URLs. |
| T12 | SSRF via configured URLs | **SR-15** webhook and integration URLs must be `https`; webhooks to private, loopback, or link-local addresses are refused unless explicitly allowlisted; redirects not followed for webhooks. (Probe app tests fetching configured URLs on the event network are the feature, not SSRF.) |
| T13 | DoS of the manager | **SR-16** rate limits on enrol/agent/admin routes; `304` hot path is one indexed read; bounded request sizes. |
| T14 | Privilege escalation on hosts | **SR-17** dedicated service users; systemd hardening per unit; safe unpack (tar slip, symlinks, setuid); no recursive or symlink-following `chown`; paths confined to allowed roots; no `shell=True`. |
| T15 | Address theft / network harm by probes | **SR-18** target ports claim an address only after an RFC 5227 probe gets no reply (fail closed); DHCP heartbeat is DISCOVER-only; traceroute pacing; throughput tests serialized and rate-bounded; preflight never touches the mgmt interface. |
| T16 | Clock manipulation | **SR-19** ingest time window; skew metric; NTP status in facts. |
| T17 | Privacy | **SR-20** telemetry stays on-prem; the manager stores host facts only; probe DHCP hostnames carry no personal data; Wi-Fi credentials are secrets. |

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

## 6. Incident response procedures (documented in the admin guide)

- **Host compromised:** decommission or revoke its agent secret; rotate the site's ingest and API
  tokens (one action in the UI); review the audit log.
- **Manager suspected compromised:** rotate Access policy/admins, rotate `EXP_MASTER_KEY`
  (re-encrypt all secrets; supported by `deploy.sh rotate-master-key`), rotate all component tokens,
  review audit; hosts keep running and cannot receive unsigned code.
- **Release key suspected compromised:** stop importing releases, publish a key-rollover release
  signed with the old key if still trusted, otherwise re-enrol hosts with a new key.
- **Drill went wrong:** kill switch; runner reverts persisted intents; audit and run report.
