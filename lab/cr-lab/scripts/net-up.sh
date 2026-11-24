#!/usr/bin/env bash
# Bring the attendee clients onto their VLANs: drop the mgmt default route, DHCP on eth1 (served by Kea on svc via the
# AOS-CX relay), point DNS at svc. Waits for the switch, which takes several minutes to boot. Safe to re-run.
source "$(dirname "$0")/common.sh"
deadline=$(( $(date +%s) + ${NETUP_TIMEOUT:-900} ))
for n in "${CLIENTS[@]}"; do
  running "$n" || die "$n is not running (deploy first)"
  # stop a dhclient left from an earlier run (no release), so re-runs do not stack daemons
  dx "$n" sh -c 'dhclient -x eth1 2>/dev/null; ip route del default 2>/dev/null; ip link set eth1 up' || true
  until dx "$n" timeout 25 dhclient -1 -4 eth1 >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || die "$n: no DHCP lease on eth1 (is the AOS-CX up? see README, Troubleshooting)"
    say "$n: no lease yet (switch still booting?), retrying..."; sleep 15
  done
  # dhclient-script does not reliably finish in a container (docker bind-mounts /etc/resolv.conf), so set the default
  # route from the lease's router option and write resolv.conf in place.
  gw=$(dx "$n" sh -c "sed -n 's/^ *option routers \([0-9.]*\);/\1/p' /var/lib/dhcp/dhclient.leases | tail -1")
  [ -n "$gw" ] || die "$n: lease has no router option (check Kea's subnet option-data)"
  dx "$n" ip route replace default via "$gw" dev eth1
  dx "$n" sh -c 'printf "nameserver 172.30.1.7\nsearch cr-lab.test\n" > /etc/resolv.conf'
  say "$n: $(dx "$n" sh -c "ip -4 -br addr show eth1 | awk '{print \$3}'; ip route show default | awk '{print \"via\",\$3}'" | tr '\n' ' ')"
done
