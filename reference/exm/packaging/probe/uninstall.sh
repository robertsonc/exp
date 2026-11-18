#!/usr/bin/env bash
# Remove the EXM probe (exm-probe package) and return every port to the host:
#   sudo ./uninstall.sh [--purge]
# --purge also deletes the probe's config, results, the exm-stream user and supercronic.
# A collector on the same host (exm-collector package) is left alone.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo $0" >&2; exit 1; }
systemctl disable --now exm-cron.service 2>/dev/null
for u in $(systemctl list-units --all --plain --no-legend 'exm-dhcp@*' 'exm-server@*' | awk '{print $1}'); do
    systemctl disable --now "$u"
done
systemctl disable --now exm-netns.service 2>/dev/null     # its stop action deletes the namespaces
systemctl disable exm-bypass.service 2>/dev/null          # ports stay connected until the next power cycle
[ -x /opt/exm/bin/exm ] && /opt/exm/bin/exm netns down
rm -rf /etc/systemd/system/exm-netns.service.wants
rm -f /etc/systemd/system/exm-netns.service /etc/systemd/system/exm-dhcp@.service /etc/systemd/system/exm-cron.service \
      /etc/systemd/system/exm-bypass.service /etc/systemd/system/exm-server@.service
systemctl daemon-reload
rm -f /usr/local/bin/exm
rm -rf /opt/exm
if [ "${1:-}" = "--purge" ]; then
    rm -f /etc/exm/exm.toml /etc/exm/crontab
    rm -rf /var/lib/exm /usr/local/bin/supercronic
    if id exm-stream >/dev/null 2>&1; then
        usermod -L -s /usr/sbin/nologin exm-stream 2>/dev/null; pkill -u exm-stream 2>/dev/null; sleep 1
        userdel -r exm-stream 2>/dev/null || userdel exm-stream
    fi
    rmdir /etc/exm 2>/dev/null || true                    # only if the collector isn't using it
    echo "purged the probe's config, results, stream user and supercronic"
fi
echo "EXM probe removed; ports are back on the host, admin down."
