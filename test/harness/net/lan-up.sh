#!/bin/bash
# Build the simulated event LAN inside this (privileged) container. Ported in design from
# reference/exm/test/harness.sh (bridge with a PINNED MAC, dnsmasq DHCP+DNS, veth "ports", NAT), extended with
# a router chain so traceroute has hops and the "internet" is local so no test needs real connectivity.
#
#   test ports (veth, other containers)           one L2 segment: br-ev (MAC pinned)
#        |                                             |
#   [br-ev] --- gw-ev 10.1.0.1 [ns gw: dnsmasq DHCP+DNS, router] -- 10.255.1.0/30 --
#        [ns edge: NAT 10.1.0.0/24] -- 10.255.2.0/30 -- [ns isp: 1.1.1.1 8.8.8.8, app targets, resolvers 1.1.1.1/8.8.8.8]
#   management path (container eth0, mgmt net) --- rt-isp 10.255.3.0/30 --- [ns isp]   (the "control path")
#
# A bridge takes the lowest MAC of its ports unless pinned, so adding/removing ports would change the
# gateway's MAC under the test ports; the bridge AND the gateway interface are pinned here (EXM lesson).
set -euo pipefail
LAN=/opt/lan
RUN=/run/lan
LOG=/var/log/lan
mkdir -p "$RUN" "$LOG" /var/lib/lan /etc/netns
BR_MAC=02:e0:00:00:00:01
GW_MAC=02:e0:00:00:10:01
TARGET_IPS="1.1.1.1 8.8.8.8 142.250.80.46 17.253.144.10 20.70.246.20 104.16.132.229 192.0.2.53"

ns() { local n=$1; shift; ip netns exec "$n" "$@"; }
sysctl_ns() {
    ns "$1" sysctl -qw net.ipv4.ip_forward=1 net.ipv4.icmp_ratelimit=0 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
}

for n in gw edge isp; do ip netns add "$n"; ns "$n" ip link set lo up; sysctl_ns "$n"; done
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.icmp_ratelimit=0 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

# --- event bridge (pinned MAC) and the gateway's LAN interface (pinned MAC)
ip link add br-ev type bridge
ip link set br-ev address "$BR_MAC"
ip link set br-ev up
ip link add gw-ev type veth peer name gw-evp
ip link set gw-ev address "$GW_MAC"
ip link set gw-evp master br-ev up
ip link set gw-ev netns gw
ns gw ip addr add 10.1.0.1/24 dev gw-ev
ns gw ip link set gw-ev up

# --- gateway <-> edge <-> isp, root <-> isp (management path)
ip link add gw-up type veth peer name edge-dn
ip link set gw-up netns gw; ip link set edge-dn netns edge
ns gw ip addr add 10.255.1.1/30 dev gw-up; ns gw ip link set gw-up up
ns edge ip addr add 10.255.1.2/30 dev edge-dn; ns edge ip link set edge-dn up
ip link add edge-up type veth peer name isp-dn
ip link set edge-up netns edge; ip link set isp-dn netns isp
ns edge ip addr add 10.255.2.1/30 dev edge-up; ns edge ip link set edge-up up
ns isp ip addr add 10.255.2.2/30 dev isp-dn; ns isp ip link set isp-dn up
ip link add rt-isp type veth peer name isp-mg
ip link set isp-mg netns isp
ip addr add 10.255.3.1/30 dev rt-isp; ip link set rt-isp up
ns isp ip addr add 10.255.3.2/30 dev isp-mg; ns isp ip link set isp-mg up

# routes: gw default -> edge; edge default -> isp, LAN back via gw; isp: the management subnet back via root
ns gw ip route add default via 10.255.1.2
ns edge ip route add default via 10.255.2.2
ns edge ip route add 10.1.0.0/24 via 10.255.1.1
MGMT_NET=$(ip -4 -o route show dev eth0 scope link | awk '{print $1}' | head -1)
[ -n "$MGMT_NET" ] || { echo "no management network on eth0" >&2; exit 1; }
ns isp ip route add "$MGMT_NET" via 10.255.3.1
for ip in $TARGET_IPS; do
    ns isp ip addr add "$ip/32" dev lo
    ip route add "$ip/32" via 10.255.3.2
done
# the edge NATs everything behind it (an EC / firewall does in real life): the ISP only ever sees 10.255.2.1
ns edge iptables -w -t nat -A POSTROUTING -s 10.0.0.0/8 -o edge-up -j MASQUERADE

# --- fault chains (the fault API, lanctl, fills them; empty = no fault)
for c in EXP_FAULT_IN EXP_FAULT_FWD; do ns gw iptables -w -N "$c"; done
ns gw iptables -w -A INPUT -j EXP_FAULT_IN
ns gw iptables -w -A FORWARD -j EXP_FAULT_FWD
ns edge iptables -w -N EXP_FAULT_FWD
ns edge iptables -w -A FORWARD -j EXP_FAULT_FWD

# --- DHCP + DNS for the event VLAN (the gateway). No upstream: nothing can leave the simulation.
cat > "$RUN/gw-dnsmasq.conf" <<CONF
user=root
interface=gw-ev
listen-address=10.1.0.1
bind-interfaces
no-resolv
no-hosts
no-poll
dhcp-range=10.1.0.100,10.1.0.199,255.255.255.0,12h
dhcp-option=option:router,10.1.0.1
dhcp-option=option:dns-server,10.1.0.1
dhcp-authoritative
no-ping
dhcp-leasefile=/var/lib/lan/gw.leases
log-dhcp
log-facility=$LOG/gw-dnsmasq.log
pid-file=$RUN/gw-dnsmasq.pid
conf-file=$LAN/names.conf
CONF
ns gw dnsmasq --conf-file="$RUN/gw-dnsmasq.conf"

# --- the "public" resolvers 1.1.1.1 / 8.8.8.8 (alternate resolver), in the isp namespace
cat > "$RUN/isp-dnsmasq.conf" <<CONF
user=root
listen-address=1.1.1.1
listen-address=8.8.8.8
bind-interfaces
no-resolv
no-hosts
no-poll
log-facility=$LOG/isp-dnsmasq.log
pid-file=$RUN/isp-dnsmasq.pid
conf-file=$LAN/names.conf
CONF
ns isp dnsmasq --conf-file="$RUN/isp-dnsmasq.conf"

# --- throwaway CA + server certificate for the app targets (hosts import the CA; nothing is trusted globally)
PKI=$RUN/pki; mkdir -p "$PKI"; chmod 700 "$PKI"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=exp harness CA" \
    -keyout "$PKI/ca.key" -out "$PKI/ca.pem" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=exp harness apps" \
    -keyout "$PKI/srv.key" -out "$PKI/srv.csr" 2>/dev/null
printf 'subjectAltName=DNS:google.com,DNS:*.google.com,DNS:apple.com,DNS:*.apple.com,DNS:microsoft.com,DNS:*.microsoft.com,DNS:cloudflare.com,DNS:*.cloudflare.com\nextendedKeyUsage=serverAuth\n' > "$PKI/ext.cnf"
openssl x509 -req -in "$PKI/srv.csr" -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" -CAcreateserial -days 30 \
    -extfile "$PKI/ext.cnf" -out "$PKI/srv.pem" 2>/dev/null
chmod 644 "$PKI/ca.pem"

# --- local HTTP(S) stand-ins for the apps (google-search, ...)
ns isp python3 -u "$LAN/targets.py" --cert "$PKI/srv.pem" --key "$PKI/srv.key" > "$LOG/targets.log" 2>&1 &
echo $! > "$RUN/targets.pid"

# wait until the things the tests depend on really answer (known-good before any fault is injected)
for _ in $(seq 40); do
    if ns gw ping -c1 -W1 -q 8.8.8.8 >/dev/null 2>&1 && ns gw python3 "$LAN/lanctl" canary 10.1.0.1 >/dev/null 2>&1 \
       && ns gw curl -sf -m 2 -o /dev/null http://142.250.80.46/; then
        touch "$RUN/ready"
        break
    fi
    sleep 0.5
done
[ -e "$RUN/ready" ] || { echo "LAN did not come up" >&2; exit 1; }
echo "lan ready"
exec sleep infinity
