# CR-wp4-admin-api-clarifications: choices WP-4 made where admin.yaml / 05-manager.md are silent or differ

**From:** WP-4 (manager backend, step 2) **Affects:** WP-5 (UI), WP-6 (agent install.sh), WP-8 **Status:** informational, additive

1. **Enrol one-liner.** `admin.yaml` (`EnrolToken.command`) shows `... | sudo bash -s -- --token <token>`; the real
   `agent/install/install.sh` takes the token positionally. The manager returns
   `curl -fsSL https://<manager>/install.sh | sudo bash -s -- expe_...` (what install.sh documents). The description
   example in admin.yaml should be corrected.
2. **Host metric keys** (answers `CR-wp5-fleet-api-gaps` items 3 and 4): `/fleet/hosts/{id}/metrics` serves
   `cpu_pct mem_pct disk_pct load1 net_rx_pps net_tx_pps net_rx_bps net_tx_bps net_errors net_drops disk_write_kbps`
   (management interface for `net_*`; `net_*` points carry `max: null`, the others a real max). `t` is epoch **seconds**
   (answers `CR-wp5-metric-t-units`). Component keys are exactly the chartable keys of 05-manager.md section 13.
3. **Latest figures in component `facts`** (answers gaps 1 and 2 in part): `GET .../components` returns the last
   reported numeric health metrics (`facts.metrics`: `days_to_full`, `storage_free_gb`, `vm_storage_gb`, ...) and
   `facts.process`. Non-numeric metrics (`ports[]`, per-probe arrays) are only in `GET hosts/{id}/status`.
   Per-interface history for host-namespace interfaces is stored (`fleet_iface_5m`, 48 h) but has no endpoint yet.
4. **`Issue.component_type`** (gap 6) is not added; `component_id` is present. `GET issues` hides snoozed and
   host_offline-suppressed issues; `include_snoozed=true` returns snoozed ones with `snoozed_until`.
5. **`Site.canary_state`** maps the internal state to the contract enum: `pending` (canary compiled, not yet healthy),
   `healthy_waiting` (inside the 10-minute hold), `promoted`, `failed`, or `null`.
6. **Platform webhook resolve** fires only for crit issues that were announced (a warn issue never notifies, so its
   resolution does not either).
7. **`PUT sites/{site}/alerts`** replaces the whole webhook list: entries with `id` keep their URL when `url` is
   omitted, entries without `id` need a `url`, webhooks missing from the list are deleted.
8. **Upload size.** `POST releases/upload` is parsed in memory and capped at 64 MiB; the GitHub import streams and has
   no such cap (only 250 MiB per artifact).
9. **`PATCH settings.owner`** promotes the given e-mail to role `owner` (additional owner); the configured
   `EXP_OWNER_EMAIL` and the caller cannot be demoted or disabled (409).
