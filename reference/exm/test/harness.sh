#!/usr/bin/env bash
# End-to-end validation of the EXM probe, in a throwaway container on a docker host.
#
# The container plays the probe host. Three veth pairs stand in for physical
# ports, all bridged to a LAN with dnsmasq (DHCP + DNS) and NAT to the internet.
# Every check prints PASS or FAIL; the script exits non-zero if any failed.
# Includes negative controls: each detector is shown to fire, not only to stay quiet.
#
#   test/harness.sh                 # ~8 minutes, needs internet for DNS/apps/speed tests
#   CRON_SECONDS=300 test/harness.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
C=exm-harness-ci
CRON_SECONDS="${CRON_SECONDS:-150}"
PASS=0
FAIL=0

ctr() { docker exec "$C" bash -c "$1"; }
check() {
    local name="$1" out; shift
    if out=$("$@" 2>&1); then echo "PASS  $name"; PASS=$((PASS + 1))
    else echo "FAIL  $name"; FAIL=$((FAIL + 1)); [ -n "$out" ] && tail -c 600 <<<"$out" | sed 's/^/      /'; fi
}
# ev TEST CLIENT PYTHON-EXPR : evaluate EXPR against the newest event `e` for that test and client
ev() { ctr "python3 /usr/local/bin/exm-ev $1 $2 '$3'"; }
# ev for the gateway check, plus the server port's view of the gateway when it fails
gw_ev() { ev gateway any "$1" || { ctr 'echo "s01 neigh:"; ip -n exm-s01 neigh show; ip -n exm-s01 -br addr; ip netns exec exm-s01 tc qdisc show; ip netns exec exm-s01 ping -c 2 -W 1 10.99.0.1 | tail -2'; return 1; }; }
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; }
trap cleanup EXIT

[ -f "$ROOT/vendor/supercronic-linux-amd64" ] || { echo "vendor/supercronic-linux-amd64 missing" >&2; exit 2; }
cleanup
echo "== container"
docker run -d --name "$C" --hostname exm-harness --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined --sysctl net.ipv4.ip_forward=1 \
    -v "$ROOT":/src:ro ubuntu:24.04 sleep infinity >/dev/null
ctr 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends python3 python3-scapy python3-dnspython curl iproute2 busybox-static dnsmasq-base iptables tcpdump procps ca-certificates iputils-ping openssl >/dev/null 2>&1; mount -o remount,rw /proc/sys'
check "packages installed (scapy, dnspython, busybox udhcpc)" ctr 'python3 -c "import scapy, dns" && busybox --list | grep -qx udhcpc'

echo "== fake LAN and probe install"
# The bridge is the gateway (10.99.0.1). A bridge takes the lowest MAC of its ports unless pinned, so controls
# that add and remove ports would change the gateway's MAC under the test ports, and a port holding a stale
# ARP entry then misses its gateway pings. Pinned here.
ctr '
ip link add br0 type bridge && ip link set br0 address 02:99:00:00:00:01 && ip addr add 10.99.0.1/24 dev br0 && ip link set br0 up
for i in 0 1 2 3 4; do ip link add fnic$i type veth peer name fnic$i-sw; ip link set fnic$i-sw master br0 up; done
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE
mkdir -p /var/lib/misc /var/log/exm
dnsmasq --interface=br0 --bind-interfaces --dhcp-range=10.99.0.100,10.99.0.199,12h \
  --dhcp-option=option:router,10.99.0.1 --dhcp-option=option:dns-server,10.99.0.1 --dhcp-option=26,1500 \
  --no-resolv --server=1.1.1.1 --server=8.8.8.8 --log-dhcp --log-facility=/var/log/dnsmasq-main.log \
  --pid-file=/run/dnsmasq-main.pid --dhcp-leasefile=/var/lib/misc/main.leases
ip addr add 10.99.0.2/24 dev br0
dnsmasq --listen-address=10.99.0.2 --bind-interfaces --port=53 --no-dhcp-interface=br0 --no-resolv \
  --server=1.1.1.1 --server=8.8.8.8 --pid-file=/run/dnsmasq-alt.pid --dhcp-leasefile=/var/lib/misc/alt.leases
mkdir -p /opt/exm /etc/exm && cp -r /src/bin /src/lib /src/hooks /src/VERSION /opt/exm/ && ln -sf /opt/exm/bin/exm /usr/local/bin/exm
ln -sf /opt/exm/bin/exm-collector /usr/local/bin/exm-collector
install -m 0755 /src/vendor/supercronic-linux-amd64 /usr/local/bin/supercronic
python3 - <<PY
import re
out, skip = [], False
for ln in open("/src/etc/probe/exm.toml").read().splitlines():
    if ln.strip() == "[[client]]":
        skip = True; continue
    if skip:
        if not ln.strip(): skip = False
        continue
    out.append(ln)
cfg = "\n".join(out) + "\n"
cfg = cfg.replace("probe-01", "harness")
cfg = re.sub(r"(dhcp|dns|apps|speedtest)_interval_s = \d+", r"\1_interval_s = 60", cfg).replace("jitter_s = 10", "jitter_s = 2")
cfg = cfg.replace("download_bytes = 50000000", "download_bytes = 8000000").replace("upload_bytes = 10000000", "upload_bytes = 3000000")
cfg += "".join(f"\n[[client]]\nid = \"c0{i+1}\"\niface = \"fnic{i}\"\nvlan = \"lab\"\nexpect_subnet = \"10.99.0.0/24\"\n" for i in range(3))
cfg = cfg.replace("dns_alt = \"1.1.1.1\"", "dns_alt = \"10.99.0.2\"")
cfg += "\n[[client]]\nid = \"s01\"\niface = \"fnic3\"\nrole = \"server\"\naddress = \"10.99.0.250/24\"\ngateway = \"10.99.0.1\"\ndns = [\"10.99.0.1\"]\n"
open("/etc/exm/exm.toml", "w").write(cfg)
PY
cat > /usr/local/bin/exm-ev <<PY
# Test-only helper inside the throwaway container. eval() runs assertion
# expressions written in harness.sh itself, never external input.
import glob, json, sys
test, client, expr = sys.argv[1], sys.argv[2], sys.argv[3]
evs = [json.loads(l) for f in sorted(glob.glob(f"/var/lib/exm/results/*/{test}.jsonl")) for l in open(f)]
evs = [e for e in evs if client in ("any", e.get("client_id"))]
e = evs[-1] if evs else None
ok = bool(e is not None and eval(expr, {"e": e, "evs": evs}))
if not ok:
    print("newest " + test + " event, last 520 chars: " + (json.dumps(e)[-520:] if e else "none"))
sys.exit(0 if ok else 1)
PY'

echo "== namespaces and leases"
ctr 'exm netns up' >/dev/null
check "four namespaces created (3 clients, 1 server), ports moved out" ctr '[ "$(ip netns list | grep -c exm-)" = 4 ] && ! ip link show fnic0'
ctr 'for c in c01 c02 c03; do nohup exm dhcp-daemon $c > /var/log/exm/dhcp-$c.log 2>&1 & done; for i in $(seq 30); do [ "$(grep -l "\"bound\"" /var/lib/exm/state/c0*.lease.json 2>/dev/null | wc -l)" = 3 ] && break; sleep 1; done'
check "all three clients hold a lease" ctr '[ "$(grep -l "\"bound\"" /var/lib/exm/state/c0*.lease.json | wc -l)" = 3 ]'
check "each namespace resolves through its DHCP resolver" ctr 'ip netns exec exm-c01 grep -q "nameserver 10.99.0.1" /etc/resolv.conf'
check "host resolv.conf untouched" ctr '! grep -q 10.99.0.1 /etc/resolv.conf'

echo "== server port (Marvis Minis target)"
ctr 'nohup exm server-daemon s01 > /var/log/exm/server-s01.log 2>&1 & for i in $(seq 40); do curl -s -o /dev/null http://10.99.0.250/ && break; sleep 1; done'
check "server claimed its fixed address" ctr 'ip -n exm-s01 -4 -br addr show dev fnic3 | grep -q 10.99.0.250/24'
check "HTTP returns 200 to another LAN host (what Minis needs)" ctr '[ "$(curl -s -o /dev/null -w %{http_code} http://10.99.0.250/)" = 200 ]'
check "HTTPS returns 200 (self-signed)" ctr '[ "$(curl -sk -o /dev/null -w %{http_code} https://10.99.0.250/)" = 200 ]'
check "server answers ping" ctr 'ping -c 2 -q -W 1 10.99.0.250'
check "crontab schedules no client tests on the server port" ctr '! exm crontab | grep -q " s01 "'
check "request log records the requester" ctr 'grep -q "\"src_ip\":\"10.99.0.1\"" /var/lib/exm/results/*/server_access.jsonl'
ctr 'exm run apps c01' >/dev/null
check "clients test the server as an app, ok" ev app c01 'any(x["target"]=="lab-server-s01" and x["outcome"]=="ok" for x in evs[-11:])'
ctr 'exm server set s01 --http-status 503; exm run apps c01' >/dev/null
check "CONTROL injected HTTP 503 fails the client test" ev app c01 'any(x["target"]=="lab-server-s01" and x["outcome"]=="fail" for x in evs[-11:])'
ctr 'exm server clear s01; exm server set s01 --netem "delay 150ms"' >/dev/null
check "CONTROL injected 150 ms netem delay shows in ping" ctr 'ping -c 3 -q -W 2 10.99.0.250 | grep -qE "= 1[45][0-9]\.[0-9]+/"'
ctr 'exm server clear s01; exm run apps c01' >/dev/null
check "faults cleared: client test ok again" ev app c01 'any(x["target"]=="lab-server-s01" and x["outcome"]=="ok" for x in evs[-11:])'
ctr 'printf "\n[[client]]\nid = \"s02\"\niface = \"fnic4\"\nrole = \"server\"\naddress = \"10.99.0.1/24\"\n" >> /etc/exm/exm.toml; exm netns up --client s02 >/dev/null; exm server-daemon s02 > /tmp/s02.log 2>&1; echo $? > /tmp/s02.rc; exm netns down --client s02 >/dev/null 2>&1
    python3 - <<PY
t = open("/etc/exm/exm.toml").read(); open("/etc/exm/exm.toml", "w").write(t[:t.index("\n[[client]]\nid = \"s02\"")] + "\n")
PY'
check "GUARD: a server port refuses an address another host already uses" ctr '[ "$(cat /tmp/s02.rc)" = 2 ] && grep -q REFUSED /tmp/s02.log'

echo "== DHCP"
ctr 'exm run dhcp c01; exm run dhcp c01 --mode init-reboot; exm run dhcp c01' >/dev/null
check "DORA ok, single server, held lease re-confirmed" ev dhcp c01 'e["outcome"]=="ok" and e["value"]["mode"]=="dora" and e["value"]["servers"]==["10.99.0.1"] and e["value"]["ack_ip"]==e["value"]["held_ip"]'
check "DORA total within 50 ms on a local LAN" ev dhcp c01 'e["phase_ms"]["total"] < 50'
check "INIT-REBOOT ok" ev dhcp c01 'any(x["value"]["mode"]=="init-reboot" and x["outcome"]=="ok" for x in evs)'
check "no lease burn: one lease per client" ctr '[ "$(wc -l < /var/lib/misc/main.leases)" = 3 ]'
ctr 'ip netns add rogue && ip link add rogue0 type veth peer name rogue0-sw && ip link set rogue0-sw master br0 up && ip link set rogue0 netns rogue
    ip -n rogue addr add 10.99.0.240/24 dev rogue0 && ip -n rogue link set rogue0 up
    ip netns exec rogue dnsmasq --interface=rogue0 --bind-interfaces --port=0 --dhcp-range=10.99.0.200,10.99.0.210,1h --pid-file=/run/dnsmasq-rogue.pid --dhcp-leasefile=/tmp/rogue.leases; sleep 2
    exm run dhcp c02' >/dev/null
check "CONTROL rogue DHCP server (with ping check) detected" ev dhcp c02 '"multiple_dhcp_servers" in e["value"]["flags"] and len(e["value"]["servers"])==2 and e["outcome"]=="degraded"'
ctr 'kill $(cat /run/dnsmasq-rogue.pid); sleep 1; ip netns del rogue; sleep 3; exm run dhcp c02' >/dev/null
check "rogue removed: back to one server, ok" ev dhcp c02 'e["outcome"]=="ok" and len(e["value"]["servers"])==1'
check "summary counts a degraded lease as served (c02: 100%)" ctr '[ "$(exm summary --json | python3 -c "import sys, json; print(json.load(sys.stdin)[\"c02\"][\"dhcp\"][\"ok_pct\"])")" = 100.0 ]'
ctr 'iptables -I INPUT -i br0 -p udp --dport 53 -j DROP; iptables -I INPUT -i br0 -p tcp --dport 53 -j DROP; exm run dhcp c03; iptables -D INPUT -i br0 -p udp --dport 53 -j DROP; iptables -D INPUT -i br0 -p tcp --dport 53 -j DROP' >/dev/null
check "CONTROL DNS down: DHCP still ok, first_dns_failed reported" ev dhcp c03 'e["outcome"]=="ok" and "first_dns_failed" in e["value"]["flags"]'

echo "== DNS"
ctr 'exm run dns c01' >/dev/null
check "DHCP resolver and four public resolvers all answered" ctr 'python3 /usr/local/bin/exm-ev dns c01 "len([x for x in evs if x[\"client_id\"]==\"c01\" and x[\"value\"].get(\"answered\")])>=5"'
check "no false interception with nothing redirected" ev dns_intercept c01 'sum(1 for x in evs[-4:] if x["value"]["intercepted"] is False)==4'
check "DNS over TLS reachable" ev dns_dot c01 'all(x["outcome"]=="ok" for x in evs[-3:])'
ctr 'ip addr add 10.99.0.53/24 dev br0
    dnsmasq --listen-address=10.99.0.53 --bind-interfaces --no-dhcp-interface=br0 --no-resolv --server=1.1.1.1 --pid-file=/run/icpt.pid
    for d in 8.8.8.8 9.9.9.9 208.67.222.222; do for p in udp tcp; do iptables -t nat -A PREROUTING -i br0 -p $p -d $d --dport 53 -j DNAT --to-destination 10.99.0.53:53; done; done
    exm run dns c02' >/dev/null
check "CONTROL interception of Google, Quad9, OpenDNS flagged; Cloudflare clean" ev dns_intercept c02 '{x["resolver"]: x["value"]["intercepted"] for x in evs[-4:]} == {"google": True, "quad9": True, "opendns": True, "cloudflare": False}'
ctr 'iptables -t nat -F PREROUTING; kill $(cat /run/icpt.pid); sleep 1
    dnsmasq --listen-address=10.99.0.53 --bind-interfaces --no-dhcp-interface=br0 --no-resolv --server=8.8.8.8 --pid-file=/run/icpt.pid
    for p in udp tcp; do iptables -t nat -A PREROUTING -i br0 -p $p -d 1.1.1.1 --dport 53 -j DNAT --to-destination 10.99.0.53:53; done
    exm run dns c02' >/dev/null
check "CONTROL interception of Cloudflare flagged; others clean" ev dns_intercept c02 '{x["resolver"]: x["value"]["intercepted"] for x in evs[-4:]} == {"google": False, "quad9": False, "opendns": False, "cloudflare": True}'
ctr 'iptables -t nat -F PREROUTING; kill $(cat /run/icpt.pid)'

echo "== apps"
ctr 'exm run apps c01' >/dev/null
check "eleven app transactions (10 apps + the lab server), no harness errors" ev app c01 'len([x for x in evs[-11:] if x["outcome"]!="harness_error"])==11'
check "phone connectivity check ok" ev app c01 'any(x["target"]=="phone-connectivity" and x["outcome"]=="ok" for x in evs[-11:])'
ctr 'mkdir -p /tmp/portal && echo "<title>Event WiFi Login</title>" > /tmp/portal/index.html
    (cd /tmp/portal && exec python3 -m http.server 8080 --bind 10.99.0.1 >/dev/null 2>&1) & echo $! > /run/portal.pid; sleep 1
    iptables -t nat -A PREROUTING -i br0 -p tcp --dport 80 -j DNAT --to-destination 10.99.0.1:8080
    exm run apps c02' >/dev/null
check "CONTROL captive portal classed as portal" ev app c02 'any(x["target"]=="phone-connectivity" and x["outcome"]=="portal" for x in evs[-11:])'
ctr 'iptables -t nat -F PREROUTING; kill $(cat /run/portal.pid); exm run apps c02' >/dev/null
check "portal removed: connectivity check ok" ev app c02 'any(x["target"]=="phone-connectivity" and x["outcome"]=="ok" for x in evs[-11:])'

echo "== speed tests"
ctr 'exm speedtest-next; exm speedtest-next' >/dev/null
check "Cloudflare: download and upload measured" ev speedtest any 'any(x["target"]=="cloudflare" and x["outcome"] in ("ok","degraded") and x["value"].get("up_mbps") for x in evs)'
check "fast.com: measured, or a harness_error (best effort, never a network fail)" ev speedtest any 'any(x["target"]=="fastcom" and x["outcome"] in ("ok","degraded","harness_error") for x in evs)'
check "heavy-test lock refuses a second concurrent run" ctr '(exm speedtest-next >/dev/null 2>&1 &) ; sleep 1; exm speedtest-next | grep -q "another heavy test"; sleep 20'

echo "== unplugged port"
ctr 'ip link add fnic9 type veth peer name fnic9-dead; printf "\n[[client]]\nid = \"c09\"\niface = \"fnic9\"\n" >> /etc/exm/exm.toml; exm netns up --client c09; exm run dns c09; exm netns down --client c09
    python3 - <<PY
t = open("/etc/exm/exm.toml").read(); open("/etc/exm/exm.toml", "w").write(t[:t.index("\n[[client]]\nid = \"c09\"")] + "\n")
PY' >/dev/null 2>&1
check "test on a port with no link records one clear failure" ev dns c09 'e["outcome"]=="fail" and "carrier down" in e["error"]'

echo "== network heartbeat"
ctr 'flock /run/exm/heavy.lock true; exm gateway-check; exm gateway-check' >/dev/null   # quiet LAN: no speed test still running
check "gateway check: every port up, one event for all ports" gw_ev 'e["outcome"]=="ok" and e["value"]["up"]==e["value"]["total"]==4 and e["phase_ms"]["rtt_p50"] is not None'
ctr 'ip link set fnic2-sw down; sleep 1; exm gateway-check' >/dev/null
check "CONTROL a port with no link: degraded, port named" gw_ev 'e["outcome"]=="degraded" and e["value"]["down"]==["c03"] and e["value"]["ports"]["c03"]["error"]=="no link"'
ctr 'ip link set fnic2-sw up; sleep 3; exm gateway-check; ip link set fnic2-sw down; sleep 1; ip link set fnic2-sw up; sleep 3; exm gateway-check' >/dev/null
check "CONTROL a link that dropped and came back between runs is caught" ev gateway any 'e["outcome"]=="degraded" and "c03" in e["value"]["flapped"] and e["value"]["up"]==4'
ctr 'exm gateway-check' >/dev/null
check "steady again: ok" ev gateway any 'e["outcome"]=="ok"'
check "crontab runs the heartbeat every 10 s" ctr 'exm crontab | grep -q "^\*/10 \* \* \* \* \* \* .* heartbeat$"'
ctr 'exm heartbeat; exm heartbeat' >/dev/null
check "DHCP heartbeat: OFFER from the LAN server" ev dhcp_hb any 'e["outcome"]=="ok" and e["value"]["server_id"]=="10.99.0.1" and e["phase_ms"]["offer"] < 1000'
check "DNS heartbeat: the DHCP-given resolver answers" ev dns_hb any 'e["outcome"]=="ok" and e["resolver"]=="dhcp" and e["value"]["server"]=="10.99.0.1"'
check "heartbeats rotate through the clients" ctr 'python3 -c "import json, glob; c = [json.loads(l)[\"client_id\"] for f in glob.glob(\"/var/lib/exm/results/*/dhcp_hb.jsonl\") for l in open(f)]; raise SystemExit(0 if len(set(c[-2:])) == 2 else 1)"'
ctr 'iptables -I INPUT -i br0 -p udp --dport 67 -j DROP; exm heartbeat; iptables -D INPUT -i br0 -p udp --dport 67 -j DROP' >/dev/null
check "CONTROL DHCP server silent: DHCP heartbeat fails within 3 s" ev dhcp_hb any 'e["outcome"]=="fail" and "no DHCPOFFER" in e["error"]'
check "...while DNS keeps answering" ev dns_hb any 'e["outcome"]=="ok"'
ctr 'for p in udp tcp; do iptables -I INPUT -i br0 -p $p --dport 53 -j DROP; done; exm heartbeat; for p in udp tcp; do iptables -D INPUT -i br0 -p $p --dport 53 -j DROP; done' >/dev/null
check "CONTROL DNS server silent: DNS heartbeat fails" ev dns_hb any 'e["outcome"]=="fail" and "no answer" in e["error"]'
check "...while DHCP keeps answering" ev dhcp_hb any 'e["outcome"]=="ok"'
check "DHCP heartbeat takes no leases (still one per client)" ctr '[ "$(wc -l < /var/lib/misc/main.leases)" = 3 ]'
check "trace heartbeat: reaches the target, first hop is the LAN gateway" ev trace any 'e["outcome"]=="ok" and e["value"]["reached"] and e["value"]["hops"][0][1]=="10.99.0.1" and e["value"]["dest_ttl"] > 1'
ctr 'iptables -I FORWARD -d 8.8.8.8 -j DROP; exm heartbeat; iptables -D FORWARD -d 8.8.8.8 -j DROP' >/dev/null
check "CONTROL internet cut after the gateway: trace names the last hop that answers" ev trace any 'e["outcome"]=="fail" and not e["value"]["reached"] and e["value"]["last_ip"]=="10.99.0.1" and "stops after 10.99.0.1 (hop 1)" in e["error"]'
check "...while the control path, around the gateway, still gets out (edge, not ISP)" ev trace_ctl any 'e["outcome"]=="ok" and e["value"]["reached"]'
check "DNS heartbeat also asks an alternate resolver" ev dns_hb any 'e["value"]["alt"]["server"]=="10.99.0.2" and e["value"]["alt"]["ok"] is True'
check "where: every verdict from synthetic signals (link, switch, gateway, edge, isp, resolver, dns_path, apps, dhcp, ssid)" ctr 'python3 - <<PY
import sys
sys.path.insert(0, "/opt/exm/lib")
from exm import pulse as P
w = "2026-10-27T03:10:00.000Z"; t = P.ms(w) + 5000
S = lambda *s: [{"s": x} for x in s]
gw = lambda ug=(), nl=(): {"k": "gateway", "w": w, "ug": [list(u) for u in ug], "nl": list(nl), "n": 4}
tr = lambda rc, k="trace": {"k": k, "w": w, "rc": rc, "lh": "10.99.0.1", "lt": 1, "g": "8.8.8.8"}
dns = lambda ao: {"k": "dns_hb", "w": w, "o": "fail", "sx": "10.99.0.1", "ax": "1.1.1.1", "ao": ao}
wifi = lambda gk, sd="ACME", tg="ACME": {"k": "wifi_hb", "w": w, "gk": gk, "sd": sd, "tg": tg}
cases = [
  ("link", [gw(nl=["c01", "c02", "c03"])], S("fail", "ok", "ok", "ok", "ok")),
  ("switch", [gw(ug=[("10.99.0.1", 3, 3)]), wifi(True)], S("fail", "ok", "fail", "fail", "ok")),
  ("gateway", [gw(ug=[("10.99.0.1", 3, 3)]), wifi(False)], S("fail", "ok", "fail", "fail", "fail")),
  ("lan", [gw(ug=[("10.99.0.1", 3, 3)])], S("fail", "ok", "fail", "fail", "unk")),
  ("edge", [tr(False), tr(True, "trace_ctl")], S("ok", "ok", "ok", "fail", "ok")),
  ("isp", [tr(False), tr(False, "trace_ctl")], S("ok", "ok", "fail", "fail", "ok")),
  ("resolver", [tr(True), dns(True)], S("ok", "ok", "fail", "fail", "ok")),
  ("dns_path", [tr(True), dns(False)], S("ok", "ok", "fail", "fail", "ok")),
  ("apps", [tr(True)], S("ok", "ok", "ok", "fail", "ok")),
  ("dhcp", [{"k": "dhcp_hb", "w": w, "sv": "10.99.0.1"}], S("ok", "fail", "ok", "ok", "ok")),
  ("ssid", [wifi(False, sd="MistiFi")], S("ok", "ok", "ok", "ok", "fail")),
]
bad = [(want, (P.where_of(V, t, st) or {}).get("seg")) for want, V, st in cases if (P.where_of(V, t, st) or {}).get("seg") != want]
print(bad)
raise SystemExit(1 if bad or P.where_of([], t, S("ok", "ok", "ok", "ok", "ok")) is not None else 0)
PY'

echo "== dashboard (the collector, all-in-one: this probe read in place, a test laptop attached)"
ctr 'mkdir -p /etc/exm/probes.d /var/lib/exm-collector
cat > /etc/exm/collector.toml <<TOML
data_dir = "/var/lib/exm-collector"
[web]
edge_label = "EC"
[alerts]
enabled = true
format = "json"
board_url = "http://127.0.0.1:8080/"
timezone = "UTC"
hold_fail_s = 20
hold_ok_s = 20
TOML
printf "name = \"harness\"\nlocal = true\nresults_dir = \"/var/lib/exm/results\"\n" > /etc/exm/probes.d/harness.toml
printf "name = \"testmac\"\nkind = \"mac\"\nhost = \"127.0.0.1\"\nuser = \"nobody\"\nattach_to = \"harness\"\nssid = \"ACME\"\n" > /etc/exm/probes.d/testmac.toml
exm summary --emit >/dev/null' >/dev/null
check "collector config: the local board and the attached laptop load" ctr 'exm-collector probe list | grep -q "^testmac .* harness"'
ctr 'nohup exm-collector web --port 8080 > /var/log/exm/web.log 2>&1 & echo $! > /tmp/web.pid; for i in $(seq 20); do curl -s -o /dev/null http://127.0.0.1:8080/healthz && break; sleep 0.5; done'
check "dashboard page served" ctr 'curl -s http://127.0.0.1:8080/ | grep -q "<title>EXM Pulse</title>"'
check "DNS line takes the DHCP-given resolver whether DHCP hands out one (dhcp) or several (dhcp1 first)" ctr 'python3 -c "import sys; sys.path.insert(0, \"/opt/exm/lib\"); from exm import web; L = lambda r: web.lane_of({\"test\": \"dns\", \"resolver\": r, \"outcome\": \"ok\"}); raise SystemExit(0 if (L(\"dhcp\"), L(\"dhcp1\"), L(\"dhcp2\"), L(\"google\")) == (2, 2, None, None) else 1)"'
check "history feeds the wired lines (network, DHCP, DNS, internet)" ctr 'curl -s "http://127.0.0.1:8080/api/history?minutes=30" | python3 -c "import sys, json; ls = {e[\"l\"] for e in json.load(sys.stdin)[\"events\"]}; raise SystemExit(0 if {0, 1, 2, 3} <= ls else 1)"'
check "history carries the traceroute's last answering hop" ctr 'curl -s "http://127.0.0.1:8080/api/history?minutes=30" | python3 -c "import sys, json; t = [e for e in json.load(sys.stdin)[\"events\"] if e[\"k\"] == \"trace\"][-1]; raise SystemExit(0 if t[\"rc\"] is False and t[\"lh\"] == \"10.99.0.1\" and t[\"lt\"] == 1 and t[\"l\"] is None else 1)"'
ctr 'iptables -I INPUT -i br0 -p icmp --icmp-type echo-request -j DROP; exm gateway-check; iptables -D INPUT -i br0 -p icmp --icmp-type echo-request -j DROP' >/dev/null
check "CONTROL gateway silent: history names the unreachable gateway and how many ports" ctr 'curl -s "http://127.0.0.1:8080/api/history?minutes=2" | python3 -c "import sys, json; g = [e for e in json.load(sys.stdin)[\"events\"] if e[\"k\"] == \"gateway\"][-1]; raise SystemExit(0 if g[\"o\"] == \"fail\" and g[\"ug\"] == [[\"10.99.0.1\", 4, 4]] and g[\"nl\"] == [] else 1)"'
ctr 'exm gateway-check' >/dev/null
check "history ?at= returns only that window; a malformed time is refused" ctr 'python3 - <<PY
import json, urllib.request, urllib.error, datetime
now = datetime.datetime.now(datetime.timezone.utc)
at = (now - datetime.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
lo = (now - datetime.timedelta(minutes=7, seconds=5)).strftime("%Y-%m-%dT%H:%M:%S")
j = json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/history?minutes=5&at=" + at))
ts = [e["t"] for e in j["events"]]
ok = j["at"].startswith(at[:19]) and bool(ts) and max(ts) <= at[:19] + ".999Z" and min(ts) >= lo
try:
    urllib.request.urlopen("http://127.0.0.1:8080/api/history?at=yesterday")
    ok = False
except urllib.error.HTTPError as e:
    ok = ok and e.code == 400
print(len(ts), min(ts) if ts else None, max(ts) if ts else None, j["at"])
raise SystemExit(0 if ok else 1)
PY'
check "remote ingest: a Wi-Fi line is stored, a forged wired result is refused" ctr 'python3 - <<PY
import sys, json, datetime
sys.path.insert(0, "/opt/exm/lib")
from exm import collector as K, remote
cfg = K.load()
p = K.get(cfg, "testmac")
ing = remote.Ingest(p["results_dir"], K.state_path(cfg, "follow-testmac.json"), "testmac", "wifi")
now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
stored = ing.line(json.dumps({"ts": now, "test": "wifi_hb", "outcome": "ok", "value": {"rssi": -50}, "phase_ms": {"gateway": 3.0}}).encode())
forged = ing.line(json.dumps({"ts": now, "emitted": now, "test": "dhcp", "outcome": "fail"}).encode())
raise SystemExit(0 if stored is None and forged and "not accepted" in forged else 1)
PY'
check "remote ingest refuses malformed lines (NaN, wrong shapes, unknown outcome, deep nesting)" ctr 'python3 - <<PY
import sys, json, datetime
sys.path.insert(0, "/opt/exm/lib")
from exm import collector as K, remote
cfg = K.load()
ing = remote.Ingest(K.get(cfg, "testmac")["results_dir"], K.state_path(cfg, "follow-testmac.json"), "testmac", "wifi")
now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
head = b"{\"ts\":\"" + now.encode() + b"\",\"test\":\"wifi_hb\",\"outcome\":\"ok\","
bad = [head + b"\"phase_ms\":{\"gateway\":NaN}}", head + b"\"phase_ms\":{\"gateway\":1e400}}", head + b"\"phase_ms\":5}",
       head + b"\"value\":[1]}", head + b"\"value\":{\"x\":{\"y\":1}}}", head + b"\"value\":" + b"[" * 3000 + b"]" * 3000 + b"}",
       json.dumps({"ts": now, "test": "wifi_hb", "outcome": "pwned"}).encode()]
refused = [ing.line(b) for b in bad]
print(refused)
raise SystemExit(0 if all(refused) else 1)
PY'
check "a malformed line in a results file does not hide the lines before it" ctr 'python3 - <<PY
import sys, json, datetime, os, tempfile
sys.path.insert(0, "/opt/exm/lib")
from exm import tail
now = datetime.datetime.now(datetime.timezone.utc)
iso = lambda d: d.isoformat(timespec="milliseconds").replace("+00:00", "Z")
p = os.path.join(tempfile.mkdtemp(), "x.jsonl")
with open(p, "w") as fh:
    fh.write(json.dumps({"ts": iso(now)}, separators=(",", ":")) + "\n")
    fh.write("{\"ts\": \"" + iso(now) + "\"}\n" + "garbage\n")
raise SystemExit(0 if len(tail.lines_since(p, now - datetime.timedelta(minutes=1))) == 1 else 1)
PY'
check "a remote probe feeds the fifth line (Wi-Fi)" ctr 'curl -s "http://127.0.0.1:8080/api/history?minutes=5" | python3 -c "import sys, json; ev = [e for e in json.load(sys.stdin)[\"events\"] if e[\"l\"] == 4]; raise SystemExit(0 if ev and ev[-1][\"rs\"] == -50 and ev[-1][\"p\"] == \"testmac\" else 1)"'
check "collector refuses a laptop ssid longer than 32 bytes, and passes a valid one to the laptop as hex" ctr 'd=$(mktemp -d); printf "name = \"m\"\nkind = \"mac\"\nhost = \"10.0.0.1\"\nuser = \"a\"\nattach_to = \"harness\"\nssid = \"%s\"\n" $(printf "x%.0s" $(seq 33)) > $d/m.toml; cp /etc/exm/probes.d/harness.toml $d/; ! exm-collector --probes-dir $d probe list >/dev/null 2>&1 && python3 -c "import sys; sys.path.insert(0, \"/opt/exm/lib\"); from exm import remote; assert remote.stream_command({\"ssid\": \"ACME CORP;x\"}) == \"stream ssid-hex=41434d4520434f52503b78\"; assert remote.stream_command({}) == \"stream\""'
check "the Mac side stores a valid network to monitor and refuses any other command" ctr 'd=$(mktemp -d); mkdir -p $d/exm-wifi/results; touch $d/exm-wifi/results/current.jsonl
HOME=$d SSH_ORIGINAL_COMMAND="stream ssid-hex=41434d455f434f5250" timeout 1 sh /src/mac/stream.sh >/dev/null; [ "$(cat $d/exm-wifi/target-ssid.hex)" = 41434d455f434f5250 ] || exit 1
rm $d/exm-wifi/target-ssid.hex
for c in "id" "stream; id" "stream ssid-hex=\$(id)" "stream ssid-hex=41434D45" "stream ssid-hex=414"; do HOME=$d SSH_ORIGINAL_COMMAND="$c" timeout 1 sh /src/mac/stream.sh >/dev/null 2>&1; [ $? = 2 ] || exit 1; done
[ ! -e $d/exm-wifi/target-ssid.hex ]'
check "collector refuses a probe name that is not a safe unit/file name" ctr 'd=$(mktemp -d); printf "name = \"../evil\"\nhost = \"10.0.0.1\"\n" > "$d/evil.toml"; ! exm-collector --probes-dir $d probe list >/dev/null 2>&1'
ctr '(timeout 12 curl -sN http://127.0.0.1:8080/events > /tmp/sse.txt &); sleep 1; exm run dns c01; exm gateway-check; sleep 2' >/dev/null
check "new results reach the live stream within 1 s of being written" ctr 'python3 - <<PY
import json, datetime
msgs = [json.loads(l[6:]) for l in open("/tmp/sse.txt").read().splitlines() if l.startswith("data: ") and "\"k\"" in l]
lag = [m["s"] - datetime.datetime.fromisoformat(m["w"].replace("Z", "+00:00")).timestamp() * 1000 for m in msgs]
raise SystemExit(0 if msgs and {"dns", "gateway"} <= {m["k"] for m in msgs} and max(lag) < 1000 else 1)
PY'
check "summary API serves the per-client summary" ctr 'curl -s http://127.0.0.1:8080/api/summary | python3 -c "import sys, json; j = json.load(sys.stdin); raise SystemExit(0 if \"c01\" in j[\"clients\"] and \"dhcp\" in j[\"resolvers\"] and \"wifi\" in j else 1)"'
check "nothing outside the fixed routes is served" ctr '[ "$(curl -s --path-as-is -o /dev/null -w %{http_code} http://127.0.0.1:8080/../etc/passwd)" = 404 ]'

echo "== scheduler (${CRON_SECONDS}s of supercronic)"
ctr 'exm crontab --write /etc/exm/crontab' >/dev/null
check "supercronic accepts the generated crontab" ctr 'supercronic -test /etc/exm/crontab'
# Alerts ride along: a webhook receiver, the alerter, and the LAN's DNS server silenced for 50 s mid-run.
ctr 'printf "http://127.0.0.1:9099/hook\n" > /etc/exm/alert-webhook; chmod 600 /etc/exm/alert-webhook; : > /tmp/hooks.jsonl
nohup python3 -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers[\"Content-Length\"]); open(\"/tmp/hooks.jsonl\", \"ab\").write(self.rfile.read(n) + b\"\\n\")
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer((\"127.0.0.1\", 9099), H).serve_forever()
" > /dev/null 2>&1 &
nohup exm-collector alert-follow > /var/log/exm/alert.log 2>&1 &' >/dev/null
ctr "date -u +%FT%T > /tmp/cron-start; (supercronic -passthrough-logs /etc/exm/crontab > /var/log/exm/supercronic.log 2>&1 &); sleep 8; for p in udp tcp; do iptables -I INPUT -i br0 -d 10.99.0.1 -p \$p --dport 53 -j DROP; done; sleep 50; for p in udp tcp; do iptables -D INPUT -i br0 -d 10.99.0.1 -p \$p --dport 53 -j DROP; done; sleep \$(( $CRON_SECONDS - 58 )); kill \$(pgrep -x supercronic); sleep 2"
check "summary lists the server port with requests" ctr 'exm summary --minutes 60 | grep -A1 "Server ports" | grep -q "s01 .* requests"'
check "every client ran dhcp, dns and apps under the scheduler" ctr 'python3 - <<PY
import glob, json
start = open("/tmp/cron-start").read().strip()
seen = {(e["test"], e["client_id"]) for f in glob.glob("/var/lib/exm/results/*/*.jsonl") for l in open(f)
        for e in [json.loads(l)] if e["ts"][:19] >= start}
need = {(t, c) for t in ("dhcp", "dns", "app") for c in ("c01", "c02", "c03")}
raise SystemExit(0 if need <= seen else 1)
PY'
check "no job failures reported by supercronic" ctr '! grep -q "level=error" /var/log/exm/supercronic.log'
check "status snapshot written by the scheduler (3 clients + 1 server)" ctr 'python3 -c "import json; s=json.load(open(\"/var/lib/exm/status.json\")); r=s[\"clients\"]; assert len(r)==4 and [x[\"role\"] for x in r].count(\"server\")==1"'
check "summary renders" ctr 'exm summary --minutes 60'
check "alerts: one DNS page naming the resolver, Internet folded into it, then DNS back; no Network page" ctr 'cat /var/log/exm/alert.log; python3 - <<PY
import json
m = [json.loads(l) for l in open("/tmp/hooks.jsonl") if l.strip()]
print([(x["kind"], x["line"], (x.get("where") or {}).get("seg"), x["title"], x["link"][-30:]) for x in m])
down = [x for x in m if x["kind"] == "down" and x["line"] == "DNS"]
back = [x for x in m if x["kind"] == "resolved" and x["line"] == "DNS"]
ok = (len(down) == 1 and len(back) == 1 and down[0]["where"]["seg"] == "resolver" and "?probe=harness&at=" in down[0]["link"]
      and not [x for x in m if x["line"] in ("Network", "Internet")] and "back" in back[0]["title"])
raise SystemExit(0 if ok else 1)
PY'
check "alert-test --dry-run prints a message without sending" ctr 'exm-collector alert-test --dry-run | python3 -c "import sys, json; t = sys.stdin.read(); assert \"[TEST]\" in t and \"&at=\" in t"'
check "incidents are logged on the collector and served at /api/incidents" ctr 'out=$(curl -s "http://127.0.0.1:8080/api/incidents?hours=1"); if ! python3 -c "import sys, json; i = json.loads(sys.argv[1])[\"incidents\"]; sys.exit(0 if [x for x in i if x[\"kind\"] == \"down\" and x[\"line\"] == \"DNS\"] else 1)" "$out"; then echo "response: ${out:0:300}"; curl -sv "http://127.0.0.1:8080/api/incidents?hours=1" 2>&1 | grep -E "^[<>*]" | head -8; ls -la /var/lib/exm-collector/incidents/; pgrep -a python3 | grep -c "exm-collector web"; tail -5 /var/log/exm/web.log; exit 1; fi'
check "the dashboard is still serving after the scheduler run" ctr 'curl -sf http://127.0.0.1:8080/healthz >/dev/null || { tail -20 /var/log/exm/web.log; exit 1; }'

echo "== teardown"
ctr 'for f in /run/exm/udhcpc-c0*.pid /run/exm/server-s01.pid; do kill "$(cat "$f")"; done; sleep 2' >/dev/null 2>&1
check "each client sent DHCPRELEASE on stop" ctr '[ "$(grep -c DHCPRELEASE /var/log/dnsmasq-main.log)" -ge 3 ]'
ctr 'exm netns down' >/dev/null 2>&1
check "namespaces removed" ctr '[ "$(ip netns list | grep -c exm-)" = 0 ]'

echo
echo "PASS $PASS   FAIL $FAIL"
[ "$FAIL" -eq 0 ]
