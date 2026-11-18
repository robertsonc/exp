#!/usr/bin/env bash
# Remove the EXM collector (exm-collector package):   sudo ./uninstall.sh [--purge]
# --purge also deletes its config, probe keys, the alert webhook, streamed results and the service user.
# A probe on the same host (exm-probe package) is left alone.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo $0" >&2; exit 1; }
systemctl disable --now exm-collector-prune.timer 2>/dev/null
for u in $(systemctl list-units --all --plain --no-legend 'exm-follow@*' | awk '{print $1}'); do systemctl disable --now "$u"; done
systemctl disable --now exm-web.service exm-alert.service 2>/dev/null
rm -f /etc/systemd/system/exm-web.service /etc/systemd/system/exm-alert.service /etc/systemd/system/exm-follow@.service \
      /etc/systemd/system/exm-collector-prune.service /etc/systemd/system/exm-collector-prune.timer
systemctl daemon-reload
rm -f /usr/local/bin/exm-collector
rm -rf /opt/exm-collector
if [ "${1:-}" = "--purge" ]; then
    rm -rf /etc/exm/collector.toml /etc/exm/probes.d /etc/exm/collector /etc/exm/alert-webhook /var/lib/exm-collector
    getent passwd exm-collector >/dev/null && userdel exm-collector
    rmdir /etc/exm 2>/dev/null || true                    # only if the probe isn't using it
    echo "purged the collector's config, keys, webhook, results and user"
fi
echo "EXM collector removed."
