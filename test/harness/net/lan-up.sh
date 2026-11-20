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
# M6 "core" layout (EXP_LAN_CORE=1): a routed core segment (br-core, 10.9.0.0/24, gateway 10.9.0.1 in ns gw) for the
# all-in-one box (EXP_CORE_IP), a fake Cloudflare speed server in its own namespace `cf` behind the isp
# (speed.cloudflare.com -> CF_IP), a fake Mist API and a fake EdgeConnect Orchestrator on the management network
# (https, harness CA), and the delegation of the DNS-leg zone to the box in the gateway's dnsmasq.
CORE=${EXP_LAN_CORE:-0}
CORE_IP=${EXP_CORE_IP:-10.9.0.10}
CF_IP=104.16.132.230
DNS_ZONE=${EXP_DNS_ZONE:-t.speed.exp.test}

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

# --- OPTIONAL second site (EXP_LAN_SITES>=2, the "multisite" layout): its own event bridge (pinned MAC), its own
# gateway namespace gw2 (10.2.0.1/24, own dnsmasq DHCP+DNS) and its own uplink to the SAME edge/isp chain, so the
# two sites fail independently (the fault API takes --site) while one simulated internet serves both.
SITES=${EXP_LAN_SITES:-1}
if [ "$SITES" -ge 2 ]; then
    ip netns add gw2; ns gw2 ip link set lo up; sysctl_ns gw2
    ip link add br-ev2 type bridge
    ip link set br-ev2 address 02:e0:00:00:00:02
    ip link set br-ev2 up
    ip link add gw-ev2 type veth peer name gw-ev2p
    ip link set gw-ev2 address 02:e0:00:00:10:02
    ip link set gw-ev2p master br-ev2 up
    ip link set gw-ev2 netns gw2
    ns gw2 ip addr add 10.2.0.1/24 dev gw-ev2
    ns gw2 ip link set gw-ev2 up
    ip link add gw2-up type veth peer name edge-dn2
    ip link set gw2-up netns gw2; ip link set edge-dn2 netns edge
    ns gw2 ip addr add 10.255.4.1/30 dev gw2-up; ns gw2 ip link set gw2-up up
    ns edge ip addr add 10.255.4.2/30 dev edge-dn2; ns edge ip link set edge-dn2 up
    ns gw2 ip route add default via 10.255.4.2
    ns edge ip route add 10.2.0.0/24 via 10.255.4.1
fi

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
if [ "$CORE" = 1 ]; then
    ip link add br-core type bridge
    ip link set br-core address 02:e0:00:00:00:09
    ip link set br-core up
    ip link add gw-core type veth peer name gw-corep
    ip link set gw-core address 02:e0:00:00:10:09
    ip link set gw-corep master br-core up
    ip link set gw-core netns gw
    ns gw ip addr add 10.9.0.1/24 dev gw-core
    ns gw ip link set gw-core up
    ns edge ip route add 10.9.0.0/24 via 10.255.1.1          # routed, NOT translated, towards the core
    # the fake Cloudflare lives behind the isp in its own namespace (443 is taken by the app stand-ins in the isp)
    ip netns add cf; ns cf ip link set lo up
    ip link add isp-cf type veth peer name cf-isp
    ip link set isp-cf netns isp; ip link set cf-isp netns cf
    ns isp ip addr add 10.255.5.1/30 dev isp-cf; ns isp ip link set isp-cf up
    ns cf ip addr add 10.255.5.2/30 dev cf-isp; ns cf ip link set cf-isp up
    ns cf ip addr add "$CF_IP/32" dev lo
    ns cf ip route add default via 10.255.5.1
    ns isp ip route add "$CF_IP/32" via 10.255.5.2
    ip route add "$CF_IP/32" via 10.255.3.2
    # 1.1.1.1 (the box's TTL-limited trace target for "edge+1") lives one router BEYOND the isp, in the cf namespace, so the
    # trace has a real hop after the edge (a destination local to the isp would answer at TTL 3 and there would be no edge+1)
    ns isp ip addr del 1.1.1.1/32 dev lo
    ns cf ip addr add 1.1.1.1/32 dev lo
    ns isp ip route add 1.1.1.1/32 via 10.255.5.2
fi
# the edge NATs everything behind it (an EC / firewall does in real life): the ISP only ever sees 10.255.2.1
ns edge iptables -w -t nat -A POSTROUTING -s 10.0.0.0/8 -o edge-up -j MASQUERADE

# --- fault chains (the fault API, lanctl, fills them; empty = no fault)
for c in EXP_FAULT_IN EXP_FAULT_FWD; do ns gw iptables -w -N "$c"; done
ns gw iptables -w -A INPUT -j EXP_FAULT_IN
ns gw iptables -w -A FORWARD -j EXP_FAULT_FWD
ns edge iptables -w -N EXP_FAULT_FWD
ns edge iptables -w -A FORWARD -j EXP_FAULT_FWD
if [ "$SITES" -ge 2 ]; then
    for c in EXP_FAULT_IN EXP_FAULT_FWD; do ns gw2 iptables -w -N "$c"; done
    ns gw2 iptables -w -A INPUT -j EXP_FAULT_IN
    ns gw2 iptables -w -A FORWARD -j EXP_FAULT_FWD
fi

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
if [ "$CORE" = 1 ]; then
    echo "address=/speed.cloudflare.com/$CF_IP" > "$RUN/core-names.conf"
    echo "server=/$DNS_ZONE/$CORE_IP" > "$RUN/gw-servers.conf"      # the NS delegation of the DNS-leg zone to the box
    printf 'conf-file=%s\nservers-file=%s\n' "$RUN/core-names.conf" "$RUN/gw-servers.conf" >> "$RUN/gw-dnsmasq.conf"
fi
ns gw dnsmasq --conf-file="$RUN/gw-dnsmasq.conf"
if [ "$SITES" -ge 2 ]; then
    sed -e 's/gw-ev/gw-ev2/; s/10\.1\.0\./10.2.0./g; s/gw\.leases/gw2.leases/; s/gw-dnsmasq/gw2-dnsmasq/g' \
        "$RUN/gw-dnsmasq.conf" > "$RUN/gw2-dnsmasq.conf"
    ns gw2 dnsmasq --conf-file="$RUN/gw2-dnsmasq.conf"
fi

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
if [ "$CORE" = 1 ]; then
    echo "conf-file=$RUN/core-names.conf" >> "$RUN/isp-dnsmasq.conf"
    sed -e '/^listen-address=8.8.8.8/d' -e 's/isp-dnsmasq/cf-dnsmasq/' "$RUN/isp-dnsmasq.conf" > "$RUN/cf-dnsmasq.conf"
    sed -i '/^listen-address=1.1.1.1/d' "$RUN/isp-dnsmasq.conf"
    ns cf dnsmasq --conf-file="$RUN/cf-dnsmasq.conf"
fi
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

# --- core layout: fake Cloudflare (namespace cf, https 443 with SAN speed.cloudflare.com), fake Mist (8485) and fake
# EdgeConnect Orchestrator (8486) on the management address (certificates from the harness CA)
if [ "$CORE" = 1 ]; then
    MGMT_IP=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -1)
    issue() {   # name san
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=exp harness $1" \
            -keyout "$PKI/$1.key" -out "$PKI/$1.csr" 2>/dev/null
        printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$2" > "$PKI/$1.cnf"
        openssl x509 -req -in "$PKI/$1.csr" -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" -CAcreateserial -days 30 \
            -extfile "$PKI/$1.cnf" -out "$PKI/$1.pem" 2>/dev/null
    }
    issue cf "DNS:speed.cloudflare.com"
    issue mist "IP:$MGMT_IP,DNS:mist.exp.test"
    issue orch "IP:$MGMT_IP,DNS:orch.exp.test"
    # the browser trusts the fake Cloudflare certificate by its public-key pin (no CA store in the client namespace)
    openssl x509 -in "$PKI/cf.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary \
        | base64 > "$PKI/cf.spki"
    ns cf python3 -u /opt/repo/test/fakes/cloudflare_speed/server.py --listen 0.0.0.0:443 --cert "$PKI/cf.pem" --key "$PKI/cf.key" \
        > "$LOG/cf.log" 2>&1 &
    echo $! > "$RUN/cf.pid"
    python3 -u /opt/repo/test/fakes/mist/server.py --listen 0.0.0.0:8485 --cert "$PKI/mist.pem" --key "$PKI/mist.key" \
        > "$LOG/mist.log" 2>&1 &
    echo $! > "$RUN/mist.pid"
    python3 -u /opt/repo/test/fakes/orchestrator/server.py --listen 0.0.0.0:8486 --cert "$PKI/orch.pem" --key "$PKI/orch.key" \
        > "$LOG/orch.log" 2>&1 &
    echo $! > "$RUN/orch.pid"
fi

# --- multisite: the local webhook receiver the collectors' webhooks.json points at (https, certificate from the
# throwaway CA, bound to this container's management address; every POST is recorded in /var/lib/lan/webhooks.jsonl)
HOOKS_IP=
if [ "$SITES" -ge 2 ]; then
    HOOKS_IP=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -1)
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=exp harness webhooks" \
        -keyout "$PKI/hooks.key" -out "$PKI/hooks.csr" 2>/dev/null
    printf 'subjectAltName=IP:%s,DNS:hooks.exp.test\nextendedKeyUsage=serverAuth\n' "$HOOKS_IP" > "$PKI/hooks.cnf"
    openssl x509 -req -in "$PKI/hooks.csr" -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" -CAcreateserial -days 30 \
        -extfile "$PKI/hooks.cnf" -out "$PKI/hooks.pem" 2>/dev/null
    : > /var/lib/lan/webhooks.jsonl
    python3 -u "$LAN/webhook_receiver.py" --cert "$PKI/hooks.pem" --key "$PKI/hooks.key" --bind "$HOOKS_IP" \
        --port 9443 --log /var/lib/lan/webhooks.jsonl --mode-file "$RUN/hooks.mode" > "$LOG/webhooks.log" 2>&1 &
    echo $! > "$RUN/hooks.pid"
fi

# wait until the things the tests depend on really answer (known-good before any fault is injected)
for _ in $(seq 40); do
    if ns gw ping -c1 -W1 -q 8.8.8.8 >/dev/null 2>&1 && ns gw python3 "$LAN/lanctl" _canary 10.1.0.1 >/dev/null 2>&1 \
       && ns gw curl -sf -m 2 -o /dev/null http://142.250.80.46/ \
       && { [ "$CORE" != 1 ] || { curl -sk -m 2 -o /dev/null "https://127.0.0.1:8485/_fake/log" && curl -sk -m 2 -o /dev/null "https://127.0.0.1:8486/_fake/log" \
            && ns gw curl -sk -m 2 -o /dev/null "https://$CF_IP/cdn-cgi/trace"; }; } \
       && { [ "$SITES" -lt 2 ] || { ns gw2 ping -c1 -W1 -q 8.8.8.8 >/dev/null 2>&1 \
            && ns gw2 python3 "$LAN/lanctl" _canary 10.2.0.1 >/dev/null 2>&1 \
            && curl -sf -m 2 -o /dev/null --cacert "$PKI/ca.pem" "https://$HOOKS_IP:9443/_health"; }; }; then
        touch "$RUN/ready"
        break
    fi
    sleep 0.5
done
[ -e "$RUN/ready" ] || { echo "LAN did not come up" >&2; exit 1; }
echo "lan ready"
exec sleep infinity
