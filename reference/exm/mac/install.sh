#!/usr/bin/env bash
# BETA. Install (or update) the EXM Wi-Fi agent on a Mac over SSH, from any host that
# can log in to it with a key. No admin rights are needed on the Mac. Idempotent.
#
#   ./install.sh SSH_HOST PROBE_NAME [STREAM_PUBKEY] [IFACE]
#
#   SSH_HOST       e.g. mac (an ~/.ssh/config entry) or noc@192.0.2.20
#   PROBE_NAME     the name results carry; the collector's probe name for this laptop
#   STREAM_PUBKEY  the collector's public key for it (`exm-collector probe add ... --kind mac`
#                  prints the path). It is added with a forced command, so that key can
#                  only stream the results file.
#   IFACE          the Wi-Fi interface, default en0
set -euo pipefail
HOST="$1"; NAME="$2"; PUB="${3:-}"; IFACE="${4:-en0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || { echo "probe name must be lower-case letters, digits and dashes" >&2; exit 2; }
[[ "$IFACE" =~ ^[a-z0-9]{1,15}$ ]] || { echo "bad interface name" >&2; exit 2; }

RHOME=$(ssh -o BatchMode=yes "$HOST" 'printf %s "$HOME"')
# 0.9.0 was called UXM: its results move to ~/exm-wifi, the LaunchAgent is swapped below, and the
# collector's forced command follows. A stream still tailing the old path is ended (it would go
# silent, not drop); the collector reconnects and resumes. A re-run finds nothing to do.
ssh -o BatchMode=yes "$HOST" 'set -e
    if [ -d ~/uxm-wifi ] && [ ! -e ~/exm-wifi ]; then
        launchctl bootout gui/$(id -u)/com.uxm.wifi 2>/dev/null || true
        rm -f ~/Library/LaunchAgents/com.uxm.wifi.plist
        mv ~/uxm-wifi ~/exm-wifi
        rm -f ~/exm-wifi/uxm-wifi.py
        echo "migrated ~/uxm-wifi to ~/exm-wifi (results kept)"
    fi
    if [ -f ~/.ssh/authorized_keys ] && grep -q "/uxm-wifi/stream.sh\"" ~/.ssh/authorized_keys; then
        sed -i "" "s#/uxm-wifi/stream.sh\"#/exm-wifi/stream.sh\"#" ~/.ssh/authorized_keys
        echo "collector key now runs ~/exm-wifi/stream.sh"
    fi
    pkill -f "[u]xm-wifi/results/current.jsonl" 2>/dev/null || true'
ssh -o BatchMode=yes "$HOST" 'mkdir -p ~/exm-wifi/results ~/Library/LaunchAgents ~/.ssh && chmod 700 ~/.ssh'
scp -q "$HERE/exm-wifi.py" "$HERE/stream.sh" "$HOST:exm-wifi/"
sed -e "s#__HOME__#$RHOME#g" -e "s#__PROBE__#$NAME#g" -e "s#__IFACE__#$IFACE#g" "$HERE/com.exm.wifi.plist" \
    | ssh -o BatchMode=yes "$HOST" 'cat > ~/Library/LaunchAgents/com.exm.wifi.plist'
ssh -o BatchMode=yes "$HOST" 'chmod 755 ~/exm-wifi/exm-wifi.py ~/exm-wifi/stream.sh
    plutil -lint -s ~/Library/LaunchAgents/com.exm.wifi.plist
    uid=$(id -u)
    launchctl bootout gui/$uid/com.exm.wifi 2>/dev/null || true
    launchctl bootstrap gui/$uid ~/Library/LaunchAgents/com.exm.wifi.plist
    sleep 2; launchctl print gui/$uid/com.exm.wifi | grep -E "^\s*(state|pid) =" || true'

if [ -n "$PUB" ]; then
    key=$(head -1 "$PUB")
    [[ "$key" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ [A-Za-z0-9@._:-]+)?$ ]] || { echo "$PUB is not an ed25519 public key" >&2; exit 2; }
    blob=$(awk '{print $2}' <<<"$key")          # base64 only: safe inside the quotes below
    line="command=\"$RHOME/exm-wifi/stream.sh\",no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc $key"
    printf '%s\n' "$line" | ssh -o BatchMode=yes "$HOST" "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
        if grep -qF '$blob' ~/.ssh/authorized_keys; then echo 'stream key already authorized'
        else cat >> ~/.ssh/authorized_keys && echo 'stream key authorized (forced command: stream.sh)'; fi"
fi
echo "agent installed on $HOST as $NAME, results in $RHOME/exm-wifi/results/current.jsonl"
