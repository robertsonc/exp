# CR-wifi-open-owe: Wi-Fi probe ports on open / Enhanced Open networks (M4)

**Status:** implemented. **Touches:** `02-probe.md` §5.11, `01-contracts.md` §3 (`wifi_hb`, `wifi_join`),
`probe.config.schema.json` (wifi port `security`, `country`; `tests.wifi.portal_url`), `07-security.md` (T22, SR-28),
agent unit instances, manager port picker.

## Why
The probe sits on the event's **public** Wi-Fi to measure it like an attendee. That network is open (or OWE, Enhanced
Open), so there is no credential to store or deliver. The original §5.11 assumed PSK / 802.1X from `creds/wifi.json`;
that path is dropped for now, not built.

## What
- **Namespace.** A Wi-Fi port's radio moves as a whole: `iw phy <phy> set netns name exp-<port>` in, `iw phy <phy> set
  netns 1` out (`ip link set netns` is refused for cfg80211 interfaces). A stale namespace tries `ip` first, then the
  radio. Preflight refuses: a non-Wi-Fi interface with `role: wifi`; no readable phy; a phy carrying any other interface
  (the move would take it, e.g. a Wi-Fi management link); rfkill (soft or hard); NetworkManager managing it; another
  `wpa_supplicant` driving it.
- **Supplicant.** `exp-probe wifi <port>` (unit `exp-probe-wifi@<port>`, started by the agent with
  `exp-probe-lease@<port>` for every wifi port, only when the artifact ships the template) writes
  `/run/exp/probe/<port>/wpa_supplicant.conf` (0600) and execs `wpa_supplicant -D nl80211` in the namespace. The config
  lists only the target SSID, hex-encoded: `security: auto` = an OWE block (PMF required) at priority 2 and an open block
  at priority 1; `open` / `owe` keep one. `band` → `freq_list`; `country` → `country=`. `mac_addr=0` and
  `preassoc_mac_addr=0` keep the permanent MAC (allowlistable). `bgscan="simple:30:-70:3600"` for roaming in a venue.
- **Control.** The daemon talks to the control socket directly (datagram UNIX socket in `/run`; `wpa_cli` would bind
  its reply socket in the daemon's private `/tmp`, which the supplicant cannot reach).
- **`wifi_hb`** every beat on every Wi-Fi port (added to the parallel beat set). `ssid` label = the SSID actually joined
  (`none` when not associated), `detail.target_ssid` = the configured one (the collector already reads both). Captive
  portal: `curl` to `tests.wifi.portal_url` inside the namespace on a new lease and every 60 s (a roam inside the same
  network keeps the verdict); a portal is `degraded` with `detail.portal: true` and the collector says "Wi-Fi is
  degraded" with the reason. The DHCP option 114 URI, when the network sends one, rides along.
- **`wifi_join`** (only with `tests.wifi`): DISCONNECT / RECONNECT, then association, key exchange and a DHCP renew
  (udhcpc SIGUSR1), sampled every 50 ms. `gateway`, `wifi_hb` and the rotating heartbeats skip a port while its join runs.
- **Manager.** The Wi-Fi role is selectable; SSID is required; band, security and country are optional. A port with any
  credential field is refused (strict schema).

## Not in this change (verify on hardware)
- PSK / 802.1X / EAP-TLS.
- Real-radio behaviour was **not** exercised here: no CI runner has a Wi-Fi card, and `mac80211_hwsim` + `hostapd`
  end-to-end tests are a follow-up. To check on the first lab box: the `iw phy … set netns name` move and return, OWE
  join on an OWE-transition SSID (two network blocks with the same SSID), `bgscan` support in the distro's
  `wpa_supplicant`, `SIGNAL_POLL` noise (many drivers report none: the probe then reads `iw survey dump`), and 6 GHz
  with and without `country`.
