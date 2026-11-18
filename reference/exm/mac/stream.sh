#!/bin/sh
# Forced command for the wired probe host's key (authorized_keys "command=").
# That key can stream this Mac's EXM results and do nothing else. The one thing
# it may pass is the network to monitor, as hex ("stream ssid-hex=41434d45"),
# which is checked here and stored for the agent; anything else is refused.
# The last 600 lines are replayed on each connection so a short disconnect
# leaves no gap; the receiver drops lines it already has.
want=""
case "${SSH_ORIGINAL_COMMAND:-}" in
  "" | stream) ;;
  "stream ssid-hex="*)
    want=${SSH_ORIGINAL_COMMAND#stream ssid-hex=}
    case "$want" in
      "" | *[!0123456789abcdef]*) echo "exm-wifi: ssid-hex must be lower-case hex" >&2; exit 2 ;;
    esac
    if [ ${#want} -gt 64 ] || [ $(( ${#want} % 2 )) -ne 0 ]; then
      echo "exm-wifi: ssid-hex must be 1-32 bytes" >&2; exit 2
    fi
    ;;
  *) echo "exm-wifi: this key may only stream results" >&2; exit 2 ;;
esac
dir="$HOME/exm-wifi"
printf '%s\n' "$want" > "$dir/target-ssid.hex.tmp" && mv -f "$dir/target-ssid.hex.tmp" "$dir/target-ssid.hex"
exec /usr/bin/tail -n 600 -F "$dir/results/current.jsonl"
