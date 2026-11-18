# HPE EXM Mac Wi-Fi probe (beta)

A Mac on the event Wi-Fi is a real wireless client next to the wired ports. `mac/exm-wifi.py` runs on it as a LaunchAgent, needs no admin rights, and pins every test to the Wi-Fi interface. That matters because a wired management link can sit first in the service order.

| Test | Cadence | Measures |
|---|---|---|
| `wifi_hb` | 10 s | association, signal, noise, SNR, link rate (`airport -I`), one gateway ping and one DNS query over Wi-Fi |
| `wifi_app` | 60 s | four app checks with `curl --interface en0`, scored like the wired apps |
| `wifi_speed` | 30 min | `networkQuality -I en0` |

While its own speed test runs, slow gateway or DNS replies are recorded but do not degrade the heartbeat. Measurement must not report its own load as a fault.

**Which network it monitors** is set on the collector, as `ssid` in the laptop's probe file (`/etc/exm/probes.d/<name>.toml`, or `--ssid` on `probe add`). Run `sudo exm-collector apply` after changing it. The setting reaches the Mac each time the collector connects.

While the Mac is on any other network, or on none:
- the Wi-Fi line fails with "not on ACME_CORP (on MistiFi)";
- the app and speed tests pause rather than measure the wrong network;
- the agent asks macOS to rejoin every 60 s, and the dashboard shows what macOS replied.

macOS can roam to another saved network when an AP goes down, and it does not always come back on its own. The network must already be saved on the Mac (joined once by hand). Without `ssid`, the Mac monitors whatever network it is on. The details card shows which network is being monitored.

Results go to `~/exm-wifi/results/current.jsonl` on the Mac (rotated daily, 7 days kept). The collector streams them in and shows them as the Wi-Fi row of the board the laptop is attached to.

## Install

1. On the collector: `sudo exm-collector probe add NAME --kind mac --host <Mac address> --user <Mac login> --attach-to <board> --ssid <network> --trust`. It prints the path of the key it made for this laptop.
2. From any machine that can already SSH to the Mac with a key, with this bundle unpacked: `./install.sh <login>@<Mac address> NAME /path/to/NAME_ed25519.pub [en0]`. It installs the agent as a LaunchAgent (runs at login, restarts if it dies) and authorizes the collector's key with a forced command. Re-running updates it.
3. On the collector: `sudo exm-collector apply`.

Upgrading from 0.9.0 (UXM): run step 2 again with the new bundle (the key argument can be left out). It moves `~/uxm-wifi` to `~/exm-wifi` with its results, replaces the `com.uxm.wifi` LaunchAgent with `com.exm.wifi`, and repoints the collector key's forced command; the collector reconnects by itself.

The Mac needs Remote Login (System Settings > Sharing) for step 2 and for the collector, the network joined once by hand, and Python 3.8+ (`/usr/bin/python3`, from the Xcode command line tools). Keep it awake and on power during an event.

The collector's key is authorized on the Mac with a forced command (`stream.sh`, a `tail -F` of the results file), plus no-pty and no port forwarding. It cannot run anything else there. The only input it accepts is the network to monitor, sent hex-encoded and checked; `stream.sh` refuses any other command. The collector treats every line as untrusted: only `wifi_*` tests are accepted, rebuilt from a fixed schema, with `probe_id` overwritten and duplicates dropped.

## Status: beta

Tested on one MacBook Pro (macOS 12.7.6, Intel) for a day, including an AP outage it rode through by reporting "not on ACME_CORP (on MistiFi)" and rejoining when the AP came back. Not yet tested: Apple silicon, macOS 13+ (where `airport -I` is deprecated and may need `wdutil`), more than one laptop per board, sleep and lid-close behaviour. The event deployment uses Linux probes; treat the laptop as an extra vantage point.
