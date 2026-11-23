#!/usr/bin/env bash
# One-screen health check of the lab: routing, DHCP/DNS, the speed-check page from each client, exp services per node.
source "$(dirname "$0")/common.sh"
ok() { printf '  %-44s %s\n' "$1" "$2"; }
t() { if "$@" >/dev/null 2>&1; then echo ok; else echo FAIL; fi; }
say "routing / services"
ok "core -> edge -> isp (ping 172.30.255.5)" "$(t dx core ping -c1 -W2 172.30.255.5)"
ok "isp -> internet (ping 1.1.1.1)" "$(t dx isp ping -c1 -W3 1.1.1.1)"
ok "svc: kea-dhcp4-server" "$(dx svc systemctl is-active kea-dhcp4-server 2>/dev/null || true)"
ok "svc: dnsmasq" "$(dx svc systemctl is-active dnsmasq 2>/dev/null || true)"
for n in "${CLIENTS[@]}"; do
  say "$n"
  ok "lease on eth1" "$(dx "$n" sh -c "ip -4 -o addr show dev eth1 | awk '{print \$4}'" 2>/dev/null | head -1 | grep . || echo 'none (run scripts/net-up.sh)')"
  ok "default route" "$(dx "$n" ip route show default 2>/dev/null | awk '{print "via", $3, "dev", $5; exit}' | grep . || echo none)"
  if dx "$n" ip route show default 2>/dev/null | grep -q 'dev eth0'; then
    say "  !! default route is still the mgmt network (eth0): net-up.sh has not run for $n; the checks below do not test the venue path"
  fi
  ok "gateway (SVI)" "$(t dx "$n" sh -c 'ping -c1 -W2 $(ip route show default | awk "{print \$3}")')"
  ok "DNS speed.cr-lab.test" "$(dx "$n" dig +short +time=2 +tries=1 speed.cr-lab.test 2>/dev/null | head -1 || true)"
  ok "page http://speed.cr-lab.test/" "$(dx "$n" curl -s -o /dev/null -m 5 -w '%{http_code}' http://speed.cr-lab.test/ 2>/dev/null || echo FAIL)"
  ok "internet (https://www.cloudflare.com)" "$(dx "$n" curl -s -o /dev/null -m 8 -w '%{http_code}' https://www.cloudflare.com/ 2>/dev/null || echo FAIL)"
done
for n in "${AGENT_NODES[@]}"; do
  say "$n"
  units=$(dx "$n" sh -c "systemctl list-units --no-legend --plain 'exp-*' 2>/dev/null | awk '{print \$1\"=\"\$3}' | tr '\n' ' '" 2>/dev/null || true)
  ok "exp units" "${units:-not enrolled}"
done
