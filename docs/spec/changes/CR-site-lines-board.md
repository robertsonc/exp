# CR-site-lines-board — the site lines board ("Event Grand Central")

**Decision (owner, 2026-11-25).** Build the EGC design (the "Event Grand Central" artifact) as a site-level view of the
dashboard: one **line** per network, one **station** per check in order of distance from the client, one **train** per
probe port. Timing and state rules are those of CR-heartbeat-cadence: trains move on real results only, and every state
comes from the collector (decision D3). The prototype's JavaScript is the reference behaviour, not code to ship.

## Mapping

| EGC | EXP |
|---|---|
| line (Event, Vendor, Admin, ...) | `network` label of a probe port (new, see Contracts) |
| Control (out-of-band reference) | ports with `reference: true`; a network is a reference network if any of its ports is |
| station order | `wifi` (wireless ports only) → `dhcp` → `network` (gateway) → `dns` → `internet` → `apps` |
| train | one probe port; `client` role = wired (square), `wifi` role = wireless (round) |
| hollow / confirming / stopped / verifying | the port's line state from the rules engine at the port's own cadence: one failed beat in a still-ok window = hollow; `warn` = confirming; `fail` = stopped; ok again within `calm_s` of a fail = verifying |
| untestable behind a stop | a station whose **dependency** is stopped is `untestable`, never `fail`. Dependencies: Wi-Fi → DHCP → network → {DNS, internet}; apps needs DNS and internet. The internet line is measured by IP, so it stays measured when DNS stops; that is the by-IP evidence |
| by-IP vs by-name evidence | `internet` (ping/trace by IP) vs `apps` (HTTPS by name) |
| service alerts (ring, multi, arc, spoke) | collector site findings: every network / several networks / one network or one medium of it / one port; reference status attached |
| 15-minute ribbon and replay | per network, the share of its ports not passing, per beat; replay re-evaluates records (same records in, same board out) |
| Inject / auto script | fake-collector scenarios for demos and tests (drills, M5, later) |

## Contracts

1. **Manager-stored probe ports** gain optional `network` (slug) and `reference` (boolean). The manager validates them,
   **strips them from the probe's config** (the probe does not use them; probe contract unchanged), and compiles them
   into the collector config.
2. **Collector config** `probes[].ports[]`: `{id, network, media: wired|wireless, reference}` (optional, at most 64 per
   probe). A probe port without a network is not on the board.
3. **Collector API** `GET /api/v1/sites/{site}/lines?at=` returns `exp.lines/1`: networks with their ports' per-station
   states, station aggregates, findings with headline/sub/why, reference status, cadence. No new SSE kind: the
   dashboard launches trains on the existing `beat` events of the board's probes (a probe measures its ports
   together, so one beat is one real result per port) and re-fetches the document on `beat`/`state` (debounced).
4. **Collector API** `GET /api/v1/sites/{site}/lines/timeline?from=&to=&step_s=` (at most 60 min) gives, per network and
   step, the worst station state and the share of ports affected, for the ribbon.
5. **Dashboard** relays both to the collector that serves the site (`/api/v1/sites/{site}/lines[/timeline]`), its own
   site first; a collector that does not know the site answers 404 and the next is tried.

## Rules for the board (binding)

- A train is launched when a port's result arrives; the motion between results is interpolation, never a fabricated
  check. `prefers-reduced-motion` stops trains, never states.
- The board renders `exp.lines/1` only. It does not run a state machine, group findings or write headlines.
- A coverage gap (a network with no wired or no wireless port reporting) is a finding, not decoration.
- The dashboard's CSP holds: no external fonts or scripts; system font stack; light and dark themes.

## Build order

1. Contracts and plumbing (this CR, items 1–2).
2. Collector: per-port line states, `untestable`, site findings and narrative, `exp.lines/1`, timeline, SSE.
3. Dashboard: `/site/<id>/lines` view (line map, trains, service alerts, ribbon with replay), kiosk rotation.
4. Fake-collector scenarios matching the prototype's inject buttons.

## Built in this change (v1) and left for later

Built: contracts 1–5, the collector module `exp_collector/lines.py` (per-port stations, findings, words, timeline),
the manager's port picker fields (**Network**, **Out-of-band reference**), the dashboard view `/site/<id>/lines` with
the line map, trains on real beats, service-alert cards, the ribbon with click-to-look-back (auto-return after two idle
minutes), a **Lines board** link per site on the Overview, kiosk support, light and dark themes.

Not yet: animated replay of the ribbon (step through changes, play), the plain voice (the board speaks the sysadmin
voice), stickiness between scopes (the board is pure: a ring and a multi can alternate while the share hovers at 80 %),
wireless trains (Wi-Fi ports are M4), and the fake-collector inject scenarios as a demo mode.
