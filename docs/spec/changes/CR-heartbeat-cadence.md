# CR-heartbeat-cadence — state windows, staleness and beats follow the probe's real heartbeat

**Decision (owner, 2026-11-24).** The probe heartbeat stays **10 s by default**. A site can opt into **5 s ("fast
detection")** where finding a fault sooner is worth about twice the probe traffic and records. Boards animate only on
real results, and every state change comes from the collector's time-based rules, so no board looks faster than its
data.

**Problem.** `heartbeat.interval_s` is 5–60 s per probe (`probe.config.schema.json`), but three places assumed 10 s:

| Where | Assumption | Effect at a slow heartbeat (e.g. 60 s) |
|---|---|---|
| `collector/exp_collector/rules.py` `LINE_SPECS` | network, DHCP, DNS and Wi-Fi state windows fixed at 30 s | a healthy probe reads **unknown** on every heartbeat line between beats (reproduced: 45 s after a beat) |
| `dashboard/.../board.js`, `overview.js` | `STALE_S = 30` | "No result from the probe" between every beat |
| `dashboard/.../trace.js` | `BEAT_MS = 10000` | beat marks drawn at 10 s width whatever the spacing; arrow keys step 10 s |

**What changed.**

1. **Collector: measured cadence.** `rules.cadence_ms()` is the median gap between a line's newest distinct beat times
   (up to 9 gaps; gaps over 120 s are outages or restarts and are ignored; fewer than 3 gaps = unknown).
   `rules.window_for()` widens a line's state window to **2.5 beats** of that cadence, capped at 180 s and never below
   the spec window. At 10 s and 5 s the windows are unchanged (30 s). At 60 s they become 150 s. App and path lines,
   which run on their own multi-minute intervals, keep their spec windows. `evaluate()` judges each line on its
   effective window. `LineEval.window_ms` and `LineEval.cadence_ms` carry it. `Evaluation.cadence_ms` is the fastest
   heartbeat line. Every text that quotes a window ("2 of 3 checks failed in the last 30 s"), and the incident engine's
   hold, now use the effective window, so words and state never disagree. Nothing is configured: the cadence is what
   the probe actually does.
2. **Contracts (additive, optional).**
   - `exp.state/1`: `cadence_s` (number or null), and `lines[].window_s` (integer).
   - Collector `ProbeSummary` (`GET /api/v1/probes`): `cadence_s`.
   - Admin API: `POST /sites/{site}/probe-heartbeat {interval_s: 5..60}` returns `{site, interval_s, updated}`. It needs
     admin, is audited (`site.probe_heartbeat`, one entry), sets `heartbeat.interval_s` on every probe component of
     the site in one batch (other settings and other component types untouched; probes already at the value are
     skipped), then recompiles the site.
3. **Dashboard.** `util.js` `beatMs(cadence_s)` and `staleAfterS(cadence_s)` = max(30 s, 3 beats). The Pulse board
   sizes beats and steps the playhead by the probe's cadence. Board and Overview mark a probe stale after three
   missed beats, never sooner than spec 04 §4's 30 s. Defaults are unchanged when the cadence is unknown.
4. **Manager UI.** Site page → **Probe heartbeat**: Standard 10 s / Fast detection 5 s → *Apply to all probes*. A
   single probe stays editable on its own page (5–60 s).

**Rules for the site lines board (EGC), binding when it is built.**

- **Trains move on real results only.** A train is launched when a probe port's result arrives (SSE). Motion between
  results is interpolation of that result, never a fabricated check. With a 10 s heartbeat a train leaves every 10 s,
  not every 2 s as in the prototype.
- **Every state comes from the collector**, decision D3. The prototype's hollow / confirming / stopped / verifying
  ladder counts checks (2, 4 and 12 at 2 s, i.e. 4 s, 8 s and 24 s). EXP maps it onto the collector's time-based states
  and incidents (warn → confirming, fail/down → stopped, `back` until `calm_s` → verifying). The board never runs its
  own state machine, so live, replay and alerts tell the same story at any cadence.
- `prefers-reduced-motion` stops the trains; states and text are unaffected.

**Cost of fast detection (estimate, not measured).** A 26-port site with about 5 checks per heartbeat sends about
13 records/s at 10 s (~1.1 M/day) and about 26/s at 5 s (~2.2 M/day). The probe test traffic on the venue network
doubles too. The cr-lab can measure the real per-heartbeat record count.

**Tests.**
- `collector/tests/test_rules_cadence.py`: 7 tests covering default and fast windows unchanged, a 60 s heartbeat not
  unknown between beats (fails with fixed windows), a failure still seen at 60 s, an outage gap not taken as the
  cadence, too few beats, the cap and floor, and the state doc validating against the schema.
- `manager/worker/test/workers/site-heartbeat.test.ts`: the batch update (scope, other settings kept, single audit,
  idempotent) and the refusals (range, non-integer, extra field, unknown site, non-admin).
- `shared/openapi`: the new admin endpoint is in the contract list.
