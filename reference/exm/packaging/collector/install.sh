#!/usr/bin/env bash
# Install or upgrade the EXM collector (exm-collector package):   sudo ./install.sh
# Idempotent: re-running converges to the same state. It keeps /etc/exm/collector.toml,
# /etc/exm/probes.d, the probes' SSH keys, the alert webhook and all streamed results.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VERSION="$(cat "$HERE/VERSION")"
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo $0" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }
echo "exm-collector $VERSION"

say "Preflight"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "python 3.11 or newer is required (tomllib)" >&2; exit 1; }
need=""
command -v ssh >/dev/null && command -v ssh-keygen >/dev/null && command -v ssh-keyscan >/dev/null || need="$need openssh-client"
[ -d /usr/share/zoneinfo ] || need="$need tzdata"
if [ -n "$need" ]; then
    command -v apt-get >/dev/null || { echo "install:$need" >&2; exit 1; }
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $need >/dev/null
fi
echo "  python3 $(python3 -c 'import platform; print(platform.python_version())'), openssh-client, tzdata present"

say "Upgrade from UXM"
# 0.9.0 was called UXM. Its config, probe keys, webhook, streamed results and incident log move to the
# EXM names in place. The service user is renamed, not recreated: same uid and gid, so what it owns stays
# its own. Every step checks for the old thing first, so a re-run finishes a run that stopped part way.
migrated=0
old_units="uxm-web.service uxm-alert.service uxm-follow@.service uxm-collector-prune.service uxm-collector-prune.timer"
if [ -f /etc/systemd/system/uxm-follow@.service ] || [ -f /etc/systemd/system/uxm-collector-prune.timer ]; then
    systemctl disable --now uxm-collector-prune.timer 2>/dev/null || true
    for u in $(systemctl list-units --all --plain --no-legend 'uxm-follow@*' | awk '{print $1}'); do
        systemctl disable --now "$u" 2>/dev/null || true
    done
    systemctl disable --now uxm-web.service uxm-alert.service 2>/dev/null || true
    for u in $old_units; do rm -f "/etc/systemd/system/$u"; done
    find /etc/systemd/system -path '*.wants/uxm-follow@*' -type l -delete       # instances enabled but not loaded
    systemctl daemon-reload
    echo "  stopped and removed the uxm-* collector units"
    migrated=1
fi
install -d -m 0755 -o root -g root /etc/exm
moved() { [ -e "$1" ] && [ ! -L "$1" ] && [ ! -e "$2" ] && mv "$1" "$2" && echo "  $1 -> $2" && migrated=1; }
# Paths in the files follow the move, probes are reached as exm-stream (the probe's upgrade renames it),
# and the package's comments say EXM. Nothing else in the values changes.
repath() { sed -i -e 's#/etc/uxm/#/etc/exm/#g' -e 's#/var/lib/uxm-collector#/var/lib/exm-collector#g' \
                  -e 's#/var/lib/uxm/#/var/lib/exm/#g' -e 's#^\(\s*user\s*=\s*\)"uxm-stream"#\1"exm-stream"#' \
                  -e '/^\s*#/{s/UXM Platform Spec/@SPEC@/g;s/uxm/exm/g;s/UXM/EXM/g;s/@SPEC@/UXM Platform Spec/g}' "$1"; }
if moved /etc/uxm/collector.toml /etc/exm/collector.toml; then repath /etc/exm/collector.toml; fi
moved /etc/uxm/alert-webhook /etc/exm/alert-webhook || true
moved /etc/uxm/collector /etc/exm/collector || true
if [ -d /etc/uxm/probes.d ] && [ ! -L /etc/uxm/probes.d ]; then
    install -d -m 0755 -o root -g root /etc/exm/probes.d
    for f in /etc/uxm/probes.d/*.toml; do
        [ -f "$f" ] && [ ! -L "$f" ] || continue
        if [ -e "/etc/exm/probes.d/${f##*/}" ]; then echo "  NOTE: kept /etc/exm/probes.d/${f##*/}; the UXM one is still in /etc/uxm/probes.d"; continue; fi
        mv "$f" /etc/exm/probes.d/ && repath "/etc/exm/probes.d/${f##*/}" && echo "  probe ${f##*/} -> /etc/exm/probes.d"
        migrated=1
    done
    rm -f /etc/uxm/probes.d/*.example                 # the package's own examples: the EXM ones replace them
    rmdir /etc/uxm/probes.d 2>/dev/null || true
fi
if getent passwd uxm-collector >/dev/null && ! getent passwd exm-collector >/dev/null; then
    pkill -u uxm-collector 2>/dev/null || true; sleep 1   # its services are stopped above; nothing else should run as it
    usermod -l exm-collector -d /var/lib/exm-collector -c "EXM collector (followers, alerts)" uxm-collector
    getent group uxm-collector >/dev/null && groupmod -n exm-collector uxm-collector
    echo "  user uxm-collector -> exm-collector (uid $(id -u exm-collector) kept)"
    migrated=1
fi
moved /var/lib/uxm-collector /var/lib/exm-collector || true
# The probe's upgrade may have left this link for the UXM collector; the EXM collector reads /var/lib/exm.
if [ -L /var/lib/uxm ] && [ "$(readlink /var/lib/uxm)" = /var/lib/exm ]; then rm -f /var/lib/uxm; echo "  removed the /var/lib/uxm link"; fi
if [ -e /opt/uxm-collector ] || [ -L /usr/local/bin/uxm-collector ]; then
    rm -rf /opt/uxm-collector; rm -f /usr/local/bin/uxm-collector
    echo "  removed /opt/uxm-collector and /usr/local/bin/uxm-collector"
fi
rmdir /etc/uxm 2>/dev/null || true                   # kept while a UXM probe still uses it
[ "$migrated" -eq 1 ] || echo "  nothing to migrate"

say "User and directories"
if ! getent passwd exm-collector >/dev/null; then
    useradd --system --home-dir /var/lib/exm-collector --no-create-home --shell /usr/sbin/nologin \
        --comment "EXM collector (followers, alerts)" exm-collector
    echo "  created system user exm-collector"
fi
# Root owns the keys and the data directory itself; the service may read the keys (group) and write only
# its three subdirectories, so it can never swap a path root later acts on for a link.
install -d -m 0755 -o root -g root /etc/exm /etc/exm/probes.d /etc/exm/collector /var/lib/exm-collector
install -d -m 0750 -o root -g exm-collector /etc/exm/collector/keys
install -d -m 0755 -o exm-collector -g exm-collector /var/lib/exm-collector/probes \
    /var/lib/exm-collector/state /var/lib/exm-collector/incidents
for f in /etc/exm/collector/keys/*; do                     # keys from an older layout: root's, group-readable
    [ -f "$f" ] && [ ! -L "$f" ] && chown root:exm-collector "$f" && case "$f" in *.pub|*/known_hosts) chmod 0644 "$f";; *) chmod 0640 "$f";; esac
done
echo "  /etc/exm/probes.d, keys in /etc/exm/collector/keys (root, group-readable), data in /var/lib/exm-collector"

say "Files"
rm -rf /opt/exm-collector.new
mkdir -p /opt/exm-collector.new
cp -r "$HERE/bin" "$HERE/lib" "$HERE/examples" "$HERE/README.md" "$HERE/VERSION" /opt/exm-collector.new/
find /opt/exm-collector.new -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root /opt/exm-collector.new          # services run this code: no user may be able to edit it
chmod -R go-w /opt/exm-collector.new
rm -rf /opt/exm-collector.old
[ -d /opt/exm-collector ] && mv /opt/exm-collector /opt/exm-collector.old
mv /opt/exm-collector.new /opt/exm-collector
rm -rf /opt/exm-collector.old
ln -sf /opt/exm-collector/bin/exm-collector /usr/local/bin/exm-collector
if [ -f /etc/exm/collector.toml ]; then
    echo "  keeping existing /etc/exm/collector.toml"
else
    install -m 0644 "$HERE/examples/collector.toml" /etc/exm/collector.toml
    echo "  /etc/exm/collector.toml installed from the example: set board_url and timezone under [alerts]"
fi
# The alert webhook URL lives here (secret, root only). Empty means: log incidents, send nothing.
[ -e /etc/exm/alert-webhook ] || install -m 0600 /dev/null /etc/exm/alert-webhook
for f in "$HERE"/examples/probes.d/*.example; do
    [ -e "/etc/exm/probes.d/$(basename "$f")" ] || install -m 0644 "$f" /etc/exm/probes.d/
done
install -m 0644 "$HERE"/systemd/* /etc/systemd/system/
systemctl daemon-reload
echo "  /opt/exm-collector, /usr/local/bin/exm-collector, units in /etc/systemd/system"

say "Configuration check"
/opt/exm-collector/bin/exm-collector probe list || { echo "fix the configuration above, then re-run this installer" >&2; exit 1; }

say "Services"
/opt/exm-collector/bin/exm-collector apply
PORT=$(python3 -c 'import tomllib; print(tomllib.load(open("/etc/exm/collector.toml", "rb")).get("web", {}).get("port", 80))')
cat <<MSG

exm-collector $VERSION installed.

  dashboard  http://$(hostname -I | awk '{print $1}'):$PORT/
  add probe  sudo exm-collector probe add NAME --host <probe mgmt address> [--label "Hall B"]
             then on the probe: sudo exm authorize-collector '<the key it prints>'; here: sudo exm-collector apply
  same host  sudo exm-collector probe add NAME --local     (an exm-probe on this machine)
  alerts     put the webhook URL in /etc/exm/alert-webhook (mode 0600), sudo exm-collector alert-test, apply
  status     exm-collector status      exm-collector probe list
  logs       journalctl -u exm-web -u exm-alert -u 'exm-follow@*' -f
  config     /etc/exm/collector.toml and /etc/exm/probes.d/, then: sudo exm-collector apply
  remove     sudo ./uninstall.sh
MSG
