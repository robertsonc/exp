#!/usr/bin/env bash
# Start the reference server for the browser bench on this machine (port 8081). Needs nginx installed locally.
#   bench/ref-server.sh start | stop
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; data="${BENCH_DATA:-/tmp/mgig-bench-data}"; conf=/tmp/mgig-bench-nginx.conf
case "${1:-start}" in
  start)
    mkdir -p "$data"; truncate -s 25000000 "$data/25m"; truncate -s 100000000 "$data/100m"
    sed -e "s#BENCH_ROOT#$here#" -e "s#BENCH_DATA#$data#" "$here/nginx.conf" > "$conf"
    nginx -t -c "$conf" -q && nginx -c "$conf" && echo "reference server on :8081 (page: http://<this host>:8081/)" ;;
  stop) nginx -c "$conf" -s quit && echo stopped ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
