# CR-kiosk-down-devices: the ops board and the kiosk list the devices that are down

**Decision (owner, 2026-11-28).** The kiosk's purpose is that when something goes down, the NOC knows *what* is down and can
go and investigate. Counts alone do not do that. The ops board (`/ops`) and the read-only kiosk (`/kiosk`) therefore list
the devices that are down.

| Choice | Decided |
|---|---|
| Which devices | Only devices that are down; never the whole inventory |
| Fields | Name, type, site, down since. No serial, MAC or address (the kiosk has no sign-in) |
| Size | Stored and shown on `/ops`: up to 500 per platform, longest down first. Kiosk: up to 200, the rest as "+N more" |

## Rules

- Stored per platform in `ops_device_status.down_json` (migration 0007). A device's identity (MAC / serial / id) is stored
  only as a keyed hash, which exists so "down since" survives from poll to poll.
- "Down since" is the first poll that saw the device down, or Mist's `last_seen` when that is earlier. A device that comes
  back leaves the list; when it goes down again its clock restarts.
- Vendor labels are text only: control characters flattened, at most 64 characters. Both pages render them with
  `textContent`; the kiosk CSP stays hash-pinned.
- A failed poll keeps the last good list (shown as stale); a connector change empties it.
- Mist site names: one extra read-only `GET /api/v1/orgs/{org_id}/sites` per poll, only when a device is down. A failure
  there leaves the site blank and never fails the poll.
- Central: the name and site fields are read as `deviceName` | `name` and `siteName` | `site_name`. **Not verified** against
  the `GET /network-monitoring/v1/devices` reference (the page was unreachable on 2026-11-28); confirm against a live
  response. A device without them is listed as "(unnamed)", never dropped.

## Security (SR-27, T21)

The kiosk stays a separate surface with the same two gates (Access bypass for exactly the configured CIDRs; the Worker's
own `CF-Connecting-IP` check). What it shows widens from counts to the names and sites of down devices. The residual risk
grows accordingly: everyone behind the allowed egress address sees which devices are down and where, so the allowlist must
be an egress used only by the management network.
