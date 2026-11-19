#!/bin/bash
# Container LAN harness (WP-8): a simulated event network + exp "hosts" (systemd containers) in Docker.
# Design ported from reference/exm/test/harness.sh (bridge with pinned MAC, dnsmasq DHCP+DNS, veth ports, NAT),
# see test/harness/README.md. Nothing here touches the docker host's network or needs the internet.
#
#   harness.sh build             build the two images (net, host)
#   harness.sh up [all|split|multisite]
#                                start the LAN and the hosts of a layout
#                                  all   : one host (h1: probe + collector + dashboard), 3 test ports
#                                  split : hc (collector + dashboard, no ports) and hp (probe, 3 test ports)
#                                  multisite : TWO event LANs (site 1 = 10.1.0.0/24, site 2 = 10.2.0.0/24, own
#                                          gateway + dnsmasq each) and 4 hosts: hb1, hb2 (site 1) and hc1 (site 2),
#                                          each with 3 test ports (collector + probe), and hd (dashboard, no ports);
#                                          plus a webhook receiver (https, 9443) in the net container
#   harness.sh down              remove every container and the management network
#   harness.sh status            what is running, as JSON
#   harness.sh shell [name]      interactive shell in a host (default: first host) or `net`
#   harness.sh lanctl ARGS...    the fault API (block-dns, cut-egress, restore, ...), see net/lanctl
#
# Env: EXP_HARNESS_PREFIX (default expm1) prefixes every docker resource; EXP_HARNESS_SUBNET (172.30.41.0/24).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
P=${EXP_HARNESS_PREFIX:-expm1}
SUBNET=${EXP_HARNESS_SUBNET:-172.30.41.0/24}
BASE=${SUBNET%.*/*}                       # 172.30.41
NET_IMG=exp-lan-net:local
HOST_IMG=exp-harness-host:${EXP_HARNESS_UBUNTU:-24.04}
MGMT=$P-mgmt
NETC=$P-net
NET_IP=$BASE.2

say() { echo "harness: $*" >&2; }
die() { echo "harness: $*" >&2; exit 1; }

image_build() {
    docker build -q -t "$NET_IMG" "$HERE/net" >/dev/null
    docker build -q --build-arg "UBUNTU=${EXP_HARNESS_UBUNTU:-24.04}" -t "$HOST_IMG" "$HERE/host" >/dev/null
}

ensure_images() {
    docker image inspect "$NET_IMG" >/dev/null 2>&1 && docker image inspect "$HOST_IMG" >/dev/null 2>&1 || image_build
}

# layout -> "name:ip-last-octet:ports[:site]" per host (site = which event LAN the test ports plug into, default 1)
layout_hosts() {
    case "$1" in
        all)   echo "h1:11:3" ;;
        split) echo "hc:12:0 hp:13:3" ;;
        multisite) echo "hb1:21:3:1 hb2:22:3:1 hc1:23:3:2 hd:24:0" ;;
        *) die "unknown layout '$1' (all|split|multisite)" ;;
    esac
}
layout_sites() { case "$1" in multisite) echo 2 ;; *) echo 1 ;; esac; }

wait_systemd() {
    local c=$1 st=""
    for _ in $(seq 60); do
        st=$(docker exec "$c" systemctl is-system-running 2>/dev/null || true)
        case "$st" in running|degraded) return 0 ;; esac
        [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] || break
        sleep 1
    done
    docker logs --tail 8 "$c" >&2 || true
    die "systemd in $c did not reach running/degraded (state=$st)"
}

start_host() {          # name last-octet nports idx [site]
    local name=$1 oct=$2 nports=$3 idx=$4 site=${5:-1} c="$P-$1"
    docker run -d --name "$c" --hostname "$name" --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
        --network "$MGMT" --ip "$BASE.$oct" "$HOST_IMG" >/dev/null
    wait_systemd "$c"
    # systemd builds LoadCredential= directories in a helper mount namespace and MS_MOVEs them into place; that
    # only reaches the service when / is a shared mount, which it is on a VM but not in a container. Without this
    # the service starts with a missing $CREDENTIALS_DIRECTORY (harmless to the product, fatal to the test).
    docker exec "$c" mount --make-rshared /
    # the management path to the "internet" (1.1.1.1, 8.8.8.8, app servers) is through the net container,
    # a different route than the event LAN: that is what the probe's control-path trace uses
    docker exec "$c" ip route replace default via "$NET_IP"
    docker exec "$NETC" cat /run/lan/pki/ca.pem | docker exec -i "$c" sh -c \
        'cat > /usr/local/share/ca-certificates/exp-harness-ca.crt && update-ca-certificates >/dev/null 2>&1'
    local pid i
    pid=$(docker inspect -f '{{.State.Pid}}' "$c")
    for ((i = 0; i < nports; i++)); do
        docker exec "$NETC" /opt/lan/lanctl plug "$name-tp$i" --pid "$pid" --ifname "tp$i" \
            --mac "$(printf '02:ee:%02x:00:00:%02x' "$idx" "$i")" --site "$site"
    done
}

cmd_up() {
    local layout=${1:-all} spec idx=1
    command -v docker >/dev/null || die "docker not found"
    layout_hosts "$layout" >/dev/null
    cmd_down >/dev/null 2>&1 || true
    ensure_images
    # not --internal: docker drops (br_netfilter) anything leaving an internal network for a non-local destination,
    # which would block the management path to the simulated internet; masquerade off = no NAT to the real one
    docker network create -o com.docker.network.bridge.enable_ip_masquerade=false --subnet "$SUBNET" --gateway "$BASE.1" "$MGMT" >/dev/null
    docker run -d --name "$NETC" --hostname "$NETC" --privileged --pid=host --network "$MGMT" --ip "$NET_IP" \
        -e "EXP_LAN_SITES=$(layout_sites "$layout")" -v "$HERE/net:/opt/lan:ro" "$NET_IMG" >/dev/null
    for _ in $(seq 120); do
        docker exec "$NETC" test -e /run/lan/ready 2>/dev/null && break
        [ "$(docker inspect -f '{{.State.Running}}' "$NETC")" = true ] || { docker logs "$NETC" >&2; die "net container exited"; }
        sleep 0.5
    done
    docker exec "$NETC" test -e /run/lan/ready || { docker logs "$NETC" >&2; die "LAN did not become ready"; }
    for spec in $(layout_hosts "$layout"); do
        IFS=: read -r name oct nports site <<<"$spec"
        say "starting host $name ($BASE.$oct, $nports test ports, site ${site:-1})"
        start_host "$name" "$oct" "$nports" "$idx" "${site:-1}"
        idx=$((idx + 1))
    done
    say "up: layout=$layout (docker prefix $P)"
}

cmd_down() {
    local c
    for c in $(docker ps -aq --filter "name=^$P-" --format '{{.Names}}' 2>/dev/null); do
        docker rm -f "$c" >/dev/null 2>&1 || true
    done
    docker network rm "$MGMT" >/dev/null 2>&1 || true
}

cmd_status() {
    docker ps -a --filter "name=^$P-" --format '{"name":"{{.Names}}","status":"{{.Status}}"}' | paste -sd, | sed 's/^/[/;s/$/]/'
}

cmd_shell() {
    local t=${1:-}
    if [ -z "$t" ]; then t=$(docker ps --filter "name=^$P-h" --format '{{.Names}}' | sort | head -1); else t="$P-$t"; fi
    [ -n "$t" ] || die "nothing running"
    exec docker exec -it "$t" bash
}

case "${1:-}" in
    build)  image_build ;;
    up)     shift; cmd_up "${1:-all}" ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    shell)  shift; cmd_shell "${1:-}" ;;
    lanctl) shift; exec docker exec "$NETC" /opt/lan/lanctl "$@" ;;
    *) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
