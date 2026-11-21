# CR-m6-dashboard - dashboard speedtest analytics (M6 step a2, WP-11)

**From:** M6 step a2. **Affects:** `dashboard/` only (server routes, federation helpers, static views, tests, README).
**Decision:** accepted; applied by the step. No shared contract changed.

## Decisions later steps must know

1. Views live in `dashboard/exp_dashboard/static/speedtest/` (the tree is `exp_dashboard/static`, not `dashboard/static`).
   Routes `/speedtests`, `/speedtests/breakdowns`, `/speedtests/support`, `/speedtests/test/<st_id>`, `/st/r/<st_id>`
   (redirects client-side to the detail and drops the `#k=` fragment) are SPA routes; `SPA_ROUTES` in `server.py`.
2. Only an `admin` session (SSO) gets raw identifiers or the purge; local accounts cap at `operator` and NOC sessions are
   viewers, so both behave as viewers here (the spec says "admin role"). The browser flag `identifiers=1` is honoured only
   for admin; the response carries `identifiers: bool` and non-admin payloads are sanitized again in the dashboard.
3. Purge goes to **every** collector (`Federation.post_all`, 10 s timeout) and reports `partial` when one did not answer;
   a non-dry-run needs `confirm: true`. Dashboard log line: `speedtest purge by=<kind> subject=sha256:<12> actor=... `.
4. No `speedtests/stream` federation: views poll (30 s). Adding it needs a per-collector SSE hub like the probe one.
5. "Users vs probes" uses the probe the operator selects (default: first probe of the site filter) and `beats` for at most the
   last 24 h (the collector caps one call at 6 h, the view chunks). The per-test nearest probe is in each test's `baseline` evidence.
6. Federated medians are count-weighted means of the collectors' medians (flagged `approximate`); exact with one collector.
7. Defect found while testing: `sanitize` collected AP MACs as client MACs and masked them; fixed (only `client`/`data` `mac`).
