#!/usr/bin/env bash
# The release tarballs, installed as an operator would, in two systemd containers (a probe with a fake
# event LAN, and a collector), then linked over SSH. ~6 minutes; needs Docker with privileged containers.
#
#   test/package.sh            builds dist/ first (scripts/build-release.sh)
#
# Checks: both installers twice (idempotent), enrolment, the stream and what the collector's key can't do,
# the dashboard and APIs, catching up after the collector was away (no gap, no duplicates), an incident
# logged with no webhook, and both uninstallers.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
check() {
    local name="$1" out; shift
    if out=$("$@" 2>&1); then echo "PASS  $name"; PASS=$((PASS + 1))
    else echo "FAIL  $name"; FAIL=$((FAIL + 1)); [ -n "$out" ] && tail -c 900 <<<"$out" | sed 's/^/      /'; fi
}
P=exm-pkg-probe; C=exm-pkg-collector; NET=exm-pkg-net
in_p() { docker exec "$P" bash -c "$1"; }
in_c() { docker exec "$C" bash -c "$1"; }
cleanup() { docker rm -f "$P" "$C" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; true; }
trap cleanup EXIT

"$ROOT/scripts/build-release.sh" >/dev/null || { echo "build failed" >&2; exit 2; }
V="$(cat "$ROOT/VERSION")"
docker build -q -t exm-systemd:24.04 "$ROOT/test/package" >/dev/null || { echo "image build failed" >&2; exit 2; }
cleanup
docker network create "$NET" >/dev/null
for n in "$P" "$C"; do
    docker run -d --name "$n" --hostname "$n" --network "$NET" --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock exm-systemd:24.04 >/dev/null
done
sleep 5
docker cp "$ROOT/dist/exm-probe-$V.tar.gz" "$P:/root/"
docker cp "$ROOT/dist/exm-collector-$V.tar.gz" "$C:/root/"

echo "== probe: a fake event LAN (two test ports behind a bridge with DHCP and DNS), then the package"
in_p '
ip link add br0 type bridge && ip link set br0 address 02:99:00:00:00:01 && ip addr add 10.99.0.1/24 dev br0 && ip link set br0 up
for i in 0 1; do ip link add fnic$i type veth peer name fnic$i-sw; ip link set fnic$i-sw master br0 up; done
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE; sysctl -qw net.ipv4.ip_forward=1
mkdir -p /var/lib/misc
dnsmasq --interface=br0 --bind-interfaces --dhcp-range=10.99.0.100,10.99.0.199,12h --dhcp-option=option:router,10.99.0.1 \
  --dhcp-option=option:dns-server,10.99.0.1 --no-resolv --server=1.1.1.1 --pid-file=/run/dnsmasq-lan.pid
mkdir -p /etc/exm && tar xzf /root/exm-probe-*.tar.gz -C /root
python3 - <<PY
import re
s = open("/root/exm-probe-'"$V"'/etc/exm.toml.example").read()
s = s.replace("probe_id = \"probe-01\"", "probe_id = \"pkg-probe\"").replace("ens19", "fnic0").replace("ens20", "fnic1")
s = re.sub(r"(dhcp|dns|apps)_interval_s = \d+", r"\1_interval_s = 60", s)
open("/etc/exm/exm.toml", "w").write(s)
PY
systemctl start ssh'
check "probe: preflight passes (no root, changes nothing)" in_p "cp -r /root/exm-probe-$V /tmp/ && chmod -R a+rX /tmp/exm-probe-$V && cd /tmp/exm-probe-$V && su nobody -s /bin/bash -c './install.sh --preflight'"
check "probe: install" in_p "cd /root/exm-probe-$V && EXM_INSTALL_WAIT_S=15 ./install.sh > /root/install1.log 2>&1 || { tail -30 /root/install1.log; exit 1; }"
check "probe: install again (idempotent)" in_p "cd /root/exm-probe-$V && EXM_INSTALL_WAIT_S=5 ./install.sh > /root/install2.log 2>&1 || { tail -30 /root/install2.log; exit 1; }"
check "probe: services up, both ports leased in their namespaces" in_p 'systemctl is-active exm-netns exm-cron exm-dhcp@c01 exm-dhcp@c02 >/dev/null && ip -n exm-c01 -4 addr show fnic0 | grep -q "inet 10.99.0." && ip -n exm-c02 -4 addr show fnic1 | grep -q "inet 10.99.0."'
check "probe: version and no dashboard units on the probe" in_p "exm version | grep -qx 'exm-probe $V' && ! systemctl cat exm-web.service >/dev/null 2>&1"
check "probe: heartbeats are being written" in_p 'for i in $(seq 30); do [ -s /var/lib/exm/results/$(date -u +%F)/gateway.jsonl ] && exit 0; sleep 2; done; exit 1'

echo "== collector: the package, then the probe added over SSH"
check "collector: install" in_c "cd /root && tar xzf exm-collector-$V.tar.gz && cd exm-collector-$V && ./install.sh > /root/install1.log 2>&1 || { tail -30 /root/install1.log; exit 1; }"
check "collector: install again (idempotent)" in_c "cd /root/exm-collector-$V && ./install.sh > /root/install2.log 2>&1 || { tail -30 /root/install2.log; exit 1; }"
check "collector: dashboard and incident log running (no webhook yet), prune timer on" in_c 'systemctl is-active exm-web exm-alert exm-collector-prune.timer >/dev/null && curl -sf localhost/healthz >/dev/null'
check "collector: probe add pins the host key and makes a key" in_c "exm-collector probe add pkg-probe --host $P --label 'Package test probe' --trust > /root/add.log 2>&1 && grep -q 'exm authorize-collector' /root/add.log && [ -s /etc/exm/collector/keys/known_hosts ]"
check "collector: keys are root's and group-readable only; the data directory is root's" in_c 'stat -c "%U:%G %a" /etc/exm/collector/keys/pkg-probe_ed25519 | grep -qx "root:exm-collector 640" && stat -c "%U %a" /etc/exm/collector/keys | grep -qx "root 750" && stat -c %U /var/lib/exm-collector | grep -qx root'
KEY=$(docker exec "$C" cat /etc/exm/collector/keys/pkg-probe_ed25519.pub)
check "probe: authorize-collector, twice (one key line)" in_p "exm authorize-collector '$KEY' >/dev/null && exm authorize-collector '$KEY' >/dev/null && [ \$(wc -l < /var/lib/exm-stream/.ssh/authorized_keys) = 1 ]"
check "probe: the stream user owns nothing (its home, .ssh and keys are root's)" in_p '[ "$(stat -c %U /var/lib/exm-stream /var/lib/exm-stream/.ssh /var/lib/exm-stream/.ssh/authorized_keys | sort -u)" = root ]'
check "the collector's key cannot run anything but the stream" in_c "out=\$(runuser -u exm-collector -- ssh -T -i /etc/exm/collector/keys/pkg-probe_ed25519 -o BatchMode=yes -o UserKnownHostsFile=/etc/exm/collector/keys/known_hosts exm-stream@$P 'id; cat /etc/shadow' 2>&1); rc=\$?; echo \"\$out\"; [ \$rc = 2 ] && ! grep -q uid= <<<\"\$out\""
check "the collector's key reaches the probe, but cannot forward ports" in_c "runuser -u exm-collector -- ssh -T -i /etc/exm/collector/keys/pkg-probe_ed25519 -o BatchMode=yes -o UserKnownHostsFile=/etc/exm/collector/keys/known_hosts exm-stream@$P stream </dev/null | head -1 | grep -q '\"ts\"' && ! timeout 8 runuser -u exm-collector -- ssh -N -i /etc/exm/collector/keys/pkg-probe_ed25519 -o BatchMode=yes -o ExitOnForwardFailure=yes -o UserKnownHostsFile=/etc/exm/collector/keys/known_hosts -L 2222:127.0.0.1:22 exm-stream@$P"
check "collector: apply starts the follower" in_c 'exm-collector apply >/dev/null && sleep 3 && systemctl is-active exm-follow@pkg-probe >/dev/null'
check "collector: the probe's results arrive within 20 s" in_c 'for i in $(seq 20); do [ -s /var/lib/exm-collector/probes/pkg-probe/$(date -u +%F)/gateway.jsonl ] && exit 0; sleep 1; done; journalctl -u exm-follow@pkg-probe --no-pager | tail -5; exit 1'
check "collector: the board shows the probe's lines (Network and DNS known)" in_c 'for i in $(seq 20); do curl -s localhost/api/boards | python3 -c "import sys, json; b = json.load(sys.stdin)[\"boards\"][0]; sys.exit(0 if b[\"name\"] == \"pkg-probe\" and b[\"lines\"][0] != \"unk\" and b[\"lines\"][2] != \"unk\" else 1)" && exit 0; sleep 2; done; curl -s localhost/api/boards; exit 1'
check "collector: the probe's details tables arrive (summary published each minute)" in_c 'for i in $(seq 45); do curl -s "localhost/api/summary?probe=pkg-probe" | python3 -c "import sys, json; s = json.load(sys.stdin); sys.exit(0 if \"c01\" in s.get(\"clients\", {}) else 1)" && exit 0; sleep 2; done; exit 1'
check "collector: probe list shows it following" in_c 'exm-collector probe list | grep -E "^pkg-probe .* active"'
check "probe: a heartbeat every 10 s (at least 5 gateway results in the last minute)" in_p 'journalctl -u exm-cron --no-pager -o cat | grep -i "heartbeat" | grep -iv "job succeeded\|starting" | tail -3
python3 - <<PY
import json, glob, datetime
cut = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=60)).isoformat()[:19]
n = sum(1 for f in glob.glob("/var/lib/exm/results/*/gateway.jsonl") for l in open(f) if json.loads(l)["ts"][:19] >= cut)
print(n, "gateway results in 60 s"); raise SystemExit(0 if n >= 5 else 1)
PY'

echo "== the collector away for 40 s: it catches up, with no gap and no duplicates"
in_c 'systemctl stop exm-follow@pkg-probe; sleep 40; systemctl start exm-follow@pkg-probe; sleep 15'
gap_check() {
    python3 - <(docker exec "$P" bash -c 'cat /var/lib/exm/results/*/gateway.jsonl') \
              <(docker exec "$C" bash -c 'cat /var/lib/exm-collector/probes/pkg-probe/*/gateway.jsonl') <<'PY'
import sys, json, datetime
probe = [json.loads(l)["emitted"] for l in open(sys.argv[1])]
coll = [json.loads(l)["emitted"] for l in open(sys.argv[2])]
cut = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=15)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
missing = sorted(set(e for e in probe if e < cut) - set(coll))
dups = len(coll) - len(set(coll))
print(f"probe wrote {len(probe)}, collector has {len(coll)}; missing {len(missing)} {missing[:3]}, duplicates {dups}")
sys.exit(0 if not missing and not dups and len(probe) > 10 else 1)
PY
}
check "every heartbeat the probe wrote is on the collector exactly once" gap_check

echo "== a DNS outage on the probe's LAN: an incident is logged on the collector (no webhook)"
in_p 'for p in udp tcp; do iptables -I INPUT -i br0 -d 10.99.0.1 -p $p --dport 53 -j DROP; done; sleep 60; for p in udp tcp; do iptables -D INPUT -i br0 -d 10.99.0.1 -p $p --dport 53 -j DROP; done'
check "collector: a DNS incident in /api/incidents, naming the probe and linking to its board" in_c 'for i in $(seq 20); do curl -s "localhost/api/incidents?probe=pkg-probe" | python3 -c "import sys, json; i = [x for x in json.load(sys.stdin)[\"incidents\"] if x[\"kind\"] == \"down\" and x[\"line\"] == \"DNS\"]; sys.exit(0 if i and \"probe=pkg-probe\" in i[0][\"link\"] else 1)" && exit 0; sleep 3; done; journalctl -u exm-alert --no-pager | tail -5; exit 1'

echo "== removal"
check "collector: uninstall --purge leaves nothing running" in_c "cd /root/exm-collector-$V && ./uninstall.sh --purge >/dev/null && ! systemctl is-active exm-web >/dev/null 2>&1 && ! id exm-collector >/dev/null 2>&1 && [ ! -e /opt/exm-collector ]"
check "probe: uninstall --purge returns the ports" in_p "cd /root/exm-probe-$V && ./uninstall.sh --purge >/dev/null && ip link show fnic0 >/dev/null && [ \$(ip netns list | grep -c exm-) = 0 ] && ! id exm-stream >/dev/null 2>&1"

echo
echo "PASS $PASS   FAIL $FAIL"
exit $FAIL
