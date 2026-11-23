#!/usr/bin/env bash
# Attendee traffic on the clients.
#   scripts/traffic.sh start [light|busy]   background loop on every client (web, DNS, downloads, iperf3, speed tests)
#   scripts/traffic.sh stop
#   scripts/traffic.sh status               is the loop running, last log lines
#   scripts/traffic.sh speedtest [client] [--report "text"]   one real speed test now (all clients in turn by default)
#   scripts/traffic.sh burst                every client runs a speed test at the same time (local-leg load)
source "$(dirname "$0")/common.sh"
zone_of() { docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$(c "$1")" | sed -n 's/^LAB_ZONE=//p'; }
cmd="${1:-status}"; shift || true
case "$cmd" in
  start)
    prof="${1:-light}"; [[ "$prof" =~ ^(light|busy)$ ]] || die "profile must be light or busy"
    for n in "${CLIENTS[@]}"; do
      if dx "$n" pgrep -f traffic-loop.sh >/dev/null; then say "$n: already running"; continue; fi
      docker exec -d "$(c "$n")" /opt/lab/traffic-loop.sh "$prof" "$(zone_of "$n")"; say "$n: started ($prof, $(zone_of "$n"))"
    done ;;
  stop)
    for n in "${CLIENTS[@]}"; do if dx "$n" pkill -f traffic-loop.sh >/dev/null 2>&1; then say "$n: stopped"; else say "$n: not running"; fi; done ;;
  status)
    for n in "${CLIENTS[@]}"; do
      st=stopped; dx "$n" pgrep -f traffic-loop.sh >/dev/null 2>&1 && st=running
      say "== $n ($st)"; dx "$n" sh -c 'tail -n 3 /var/log/lab-traffic.log 2>/dev/null' || true
    done ;;
  speedtest)
    sel=(); extra=()
    while [ $# -gt 0 ]; do case "$1" in --report) extra=(--report "$2"); shift 2 ;; *) sel+=("$1"); shift ;; esac; done
    [ ${#sel[@]} -gt 0 ] || sel=("${CLIENTS[@]}")
    for n in "${sel[@]}"; do say "$n: $(dx "$n" node /opt/lab/speedtest-run.js --zone "$(zone_of "$n")" "${extra[@]}")"; done ;;
  burst)
    for n in "${CLIENTS[@]}"; do (say "$n: $(dx "$n" node /opt/lab/speedtest-run.js --zone "$(zone_of "$n")")") & done; wait ;;
  *) die "usage: traffic.sh start [light|busy] | stop | status | speedtest [client...] [--report text] | burst" ;;
esac
