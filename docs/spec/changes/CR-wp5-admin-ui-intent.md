# CR-wp5-admin-ui-intent: component intent keys and wizard sequencing used by the admin UI

Raised by: WP-5 (manager UI), step 2. Affects: WP-4 (manager Worker: compiler, admin API), WP-3 (dashboard `/noc`), docs/spec/05-manager.md, 11-manager-ui.md.

## What

1. **Add-host wizard creates components before the host enrols.** `POST hosts {name, site, shapes}` is followed immediately by one
   `POST hosts/{id}/components {type, id, config}` per shape, with a minimal intent (no `schema`, no wiring, no secrets). A probe's
   ports are assigned *after* enrolment with `PUT components/{id}/ports`, once the host's interface facts exist (the mgmt interface is
   refused by the API and disabled in the picker). Reason: the mock (and the contract text "the host's first desired state") treats a
   component created on a pending host as healthy on enrolment, and the wizard's step 4 waits for every component to report `ok`.
   **Compiler requirement:** a probe component with no ports yet must compile to "not started" (or be left out of desired state), never to an
   invalid `exp.probe.config/1`.
2. **Dashboard collectors are an intent list of ids.** The dashboard editor writes `config.collector_ids: ["col-hallb", ...]`
   (05 section 7: "its configured collector ids"). If the stored config is a full document with `collectors: [{collector_id, url, ...}]`, the editor
   also drops entries of deselected collectors but never invents `url`/`tls_fingerprint_sha256` for new ones; the compiler fills those.
3. **NOC URL fragment is `#t=`.** 04-dashboard.md section 3 says `https://<dash>/noc#t=expn_...`; `NocTokenCreated.url` from the mock is
   `.../noc#token=...`. The UI builds the URL itself as `<origin of the dashboard url>/noc#t=<token>` and ignores the server's `url` except as a
   fallback origin. The Worker and the mock should return `#t=` too.
4. **Probe "thresholds"** (05 section 10) have no dedicated keys in `exp.probe.config/1`; the editor exposes the ones that exist: per-app `apdex_t_ms`
   and the heartbeat/test intervals. A real threshold block would be a schema change (WP-0).
5. **Settings `admins` PATCH.** `SettingsPatch.admins` is documented as an upsert but the mock replaces the list. The UI always sends the complete list
   with one entry changed, which is correct under both readings.
6. **Dashboard `tls.mode = provided`.** Certificate and key are write-only secrets (05 section 6) but `admin.yaml` has no endpoint to upload them. The
   editor only switches the mode and says so.

## Why

The UI must implement the flows in 05 section 10 against `admin.yaml`; these are the places where the contract is silent or inconsistent, and the choices
above are the most forward-compatible ones that need no change to the frozen contracts.

## Compatibility

No frozen file is changed. Items 1 and 2 need the compiler to accept the intent shapes described; items 3, 5 and 6 are clarifications for the Worker.
