# CR-wp2-incident-line-probe

**From:** WP-2 (collector) - **Affects:** WP-0 (`incident.schema.json`, `collector.yaml`), WP-3 (dashboard) - **Status:** proposed

## What
`03-collector.md` section 6 requires a "probe silent" incident (no records for 90 s: "Nothing on this screen
is current"). `01-contracts.md` section 5 / `incident.schema.json` types `Incident.line` as `line_key`
(`network|dhcp|dns|internet|apps|wifi|path`), which cannot name "the probe itself".

## Why
The silent-probe incident is not about a network line. Labelling it `network` would blame the wrong thing and
fold it wrongly; leaving it out of the incident log loses the record an RCA starts from.

## Proposed change
Allow `probe` as an additional value of `Incident.line` (only there: `line_key` stays as it is for State and
Beats). `kind` stays `down|back` for it (`again` after a re-failure).

## Compatibility
Additive for readers that treat unknown enum values as "other"; a dashboard that validates `line` against the
old enum would reject the item, so WP-3 must render `probe` as "Probe". Until this lands the collector
**stores** `line = "probe"` in SQLite (`incidents.line` is free text) and `exp_collector.incidents.incident_doc`
emits it as is; every other incident validates against the current schema (tested).

## Work-around inside WP-2
None needed to run; the API step (3) may filter `line=probe` rows out of `GET incidents` if the change is
declined, and the page text/webhook message still goes out.
