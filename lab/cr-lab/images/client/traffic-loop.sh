#!/usr/bin/env bash
# Background attendee traffic for one lab client. Started/stopped by scripts/traffic.sh (docker exec -d).
#   traffic-loop.sh <profile: light|busy> <zone>
# Each cycle picks one action: web/DNS browsing, an internet download, a LAN iperf3 burst to the collector,
# or (rarely) a full exp speed test. Everything is bounded (timeouts, byte caps) so it never runs away.
set -uo pipefail
profile="${1:-light}"; zone="${2:-}"
COLLECTOR="${LAB_COLLECTOR:-172.30.1.1}"
case "$profile" in
  light) pause_min=20; pause_max=60; st_every=12 ;;   # a speed test about every 12 cycles
  busy)  pause_min=3;  pause_max=12; st_every=6 ;;
  *) echo "profile must be light or busy" >&2; exit 2 ;;
esac
sites=(www.hpe.com www.arubanetworks.com www.juniper.net www.wikipedia.org www.cloudflare.com www.github.com)
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> /var/log/lab-traffic.log; }
n=0
while :; do
  n=$((n + 1))
  r=$((RANDOM % 10))
  if (( n % st_every == 0 )); then
    log "speedtest $(node /opt/lab/speedtest-run.js --zone "$zone" 2>&1 | tail -1)"
  elif (( r < 5 )); then
    s="${sites[$((RANDOM % ${#sites[@]}))]}"
    dig +time=2 +tries=1 "$s" >/dev/null 2>&1
    code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' "https://$s/") ; log "web $s $code"
  elif (( r < 8 )); then
    mb=$(( (RANDOM % 20) + 5 ))
    out=$(curl -s -o /dev/null -m 60 -w '%{speed_download}' "https://speed.cloudflare.com/__down?bytes=$((mb * 1000000))")
    log "download ${mb}MB $(awk -v b="${out:-0}" 'BEGIN{printf "%.1f Mb/s", b*8/1e6}')"
  else
    log "iperf3 $(iperf3 -c "$COLLECTOR" -t 8 -P 2 -J 2>/dev/null | awk -F: '/"bits_per_second"/{v=$2} END{gsub(/[ ,]/,"",v); printf "%.1f Mb/s", v/1e6}')"
  fi
  sleep $(( pause_min + RANDOM % (pause_max - pause_min + 1) ))
done
