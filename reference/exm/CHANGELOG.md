# Changelog

## 0.9.1 (2026-10-28)

**HPE EXM (Event network eXperience Monitor)**: UXM is now EXM. No behaviour changes.

- **Renamed everywhere.** Packages `exm-probe`, `exm-collector`, `exm-mac-probe`; commands `exm`, `exm-collector`; units `exm-*`; paths `/etc/exm`, `/opt/exm`, `/opt/exm-collector`, `/var/lib/exm`, `/var/lib/exm-collector`; users `exm-stream`, `exm-collector`; namespaces `exm-<id>`; environment `EXM_*`; Mac `~/exm-wifi`, `com.exm.wifi`. New configs default to `hostname_prefix = "exm"` and vendor class `exm-probe`.
- **In-place upgrade from 0.9.0.** The installers migrate a UXM install: config (with its paths), results, the collector's stored streams, cursors and incident log, probe keys, the webhook, and the two service users (renamed, same uid). Old units and code are removed. Each step checks for the old state first, so re-running an installer is safe. Upgrade both ends; on one host, the probe first. `test/upgrade.sh` checks this against the real 0.9.0 tarballs.
- **Uninstallers** no longer look for units from before 0.9.0.
- The migrated probe config keeps your `hostname_prefix` and `vendor_class`, with a note if they still say uxm. Lease holders read them at start: after changing them, `sudo systemctl restart 'exm-dhcp@*'` (`exm apply` doesn't restart running ones).

## 0.9.0 (2026-10-27)

First packaged release: the probe and the collector are separate packages.

- **Collector (new package).** Dashboard, alerts and the probes' streams move off the probe onto a collector VM. One Pulse board per probe, an overview of them all (`/`), `/?probe=NAME` per board. `uxm-collector probe add|trust|list|remove`, `apply`, `status`, `prune`. Followers resume from the last stored line after an outage on either side (up to `backfill_hours`).
- **Probe.** `uxm stream`: the only thing a collector's key can run (`uxm authorize-collector`, user `uxm-stream`, `restrict,command=`). Results are stamped `emitted` under the file lock, so each file is in order. The dashboard's details tables are published every minute as a `summary` result. The DNS heartbeat pings both resolvers. Old `[web]`, `[alerts]` and `[[remote]]` sections are ignored with a note; the probe installer removes the old probe-hosted dashboard units.
- **Mac Wi-Fi probe: beta.** Attaches to a board as its Wi-Fi row (`--kind mac --attach-to`); the collector passes the network to monitor.
- **Dashboard (since the lab builds of 2026-10-26/27):** Pulse board with five lines, drag-to-rewind, "where" (control-path traceroute, alternate resolver, Wi-Fi as a second view), "What's failing", "just recovered", sysadmin or plain voice, webhook alerts with folding of consequences into causes and flap handling.
- **Releases.** `scripts/build-release.sh` builds reproducible tarballs and `SHA256SUMS`; GitHub Actions runs the unit tests on every push and publishes a release for each `v*` tag.
