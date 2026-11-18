#!/usr/bin/env bash
# Upgrading 0.9.0 (when EXM was called UXM) to this version, as an operator would: the real 0.9.0
# tarballs installed, linked and running with history, then this version's installers run over them.
# Two layouts in systemd containers: a probe and a collector linked over SSH (the probe upgraded first,
# the collector a minute later, so the stream really is cut in between), and an all-in-one host.
# ~10 minutes; needs Docker with privileged containers.
#
#   test/upgrade.sh [OLD_DIST]     OLD_DIST holds uxm-probe-0.9.0.tar.gz and uxm-collector-0.9.0.tar.gz
#                                  (default ~/labs/uxm-0.9.0-handoff/dist)
#
# Checks: config, results, the collector's stored streams, cursors, incidents and keys survive; both
# users keep their uids under the new names; the stream key keeps its options and runs `exm stream`;
# no uxm unit, path, user or namespace is left; no heartbeat goes missing or doubles across the
# upgrade; re-running either installer finds nothing to migrate.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OLD="${1:-$HOME/labs/uxm-0.9.0-handoff/dist}"
OLDV=0.9.0
for f in "uxm-probe-$OLDV.tar.gz" "uxm-collector-$OLDV.tar.gz"; do
    [ -f "$OLD/$f" ] || { echo "missing $OLD/$f" >&2; exit 2; }
done
(cd "$OLD" && sha256sum -c --ignore-missing --quiet SHA256SUMS) || { echo "the 0.9.0 tarballs do not match their SHA256SUMS" >&2; exit 2; }
PASS=0; FAIL=0
check() {
    local name="$1" out; shift
    if out=$("$@" 2>&1); then echo "PASS  $name"; PASS=$((PASS + 1))
    else echo "FAIL  $name"; FAIL=$((FAIL + 1)); [ -n "$out" ] && tail -c 900 <<<"$out" | sed 's/^/      /'; fi
}
P=exm-up-probe; C=exm-up-collector; A=exm-up-aio; NET=exm-up-net
# Run a script from stdin in a container: on NAME <<'EOF' ... EOF (no quoting games).
on() { docker exec -i -e V="$V" -e OLDV="$OLDV" -e P="$P" -e CIP="${CIP:-}" -e T0="${T0:-}" "$1" bash -s; }
TMPD="$(mktemp -d)"
cleanup() { docker rm -f "$P" "$C" "$A" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; true; }
trap 'cleanup; rm -rf "$TMPD"' EXIT

"$ROOT/scripts/build-release.sh" >/dev/null || { echo "build failed" >&2; exit 2; }
V="$(cat "$ROOT/VERSION")"
docker build -q -t exm-systemd:24.04 "$ROOT/test/package" >/dev/null || { echo "image build failed" >&2; exit 2; }
cleanup
docker network create "$NET" >/dev/null
for n in "$P" "$C" "$A"; do
    docker run -d --name "$n" --hostname "$n" --network "$NET" --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock exm-systemd:24.04 >/dev/null
done
sleep 5
CIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$C")
docker cp "$OLD/uxm-probe-$OLDV.tar.gz" "$P:/root/"; docker cp "$ROOT/dist/exm-probe-$V.tar.gz" "$P:/root/"
docker cp "$OLD/uxm-collector-$OLDV.tar.gz" "$C:/root/"; docker cp "$ROOT/dist/exm-collector-$V.tar.gz" "$C:/root/"
for f in "$OLD/uxm-probe-$OLDV.tar.gz" "$OLD/uxm-collector-$OLDV.tar.gz" "$ROOT/dist/exm-probe-$V.tar.gz" "$ROOT/dist/exm-collector-$V.tar.gz"; do
    docker cp "$f" "$A:/root/"
done

old_probe() {   # a fake event LAN (two test ports behind a bridge with DHCP and DNS), then UXM 0.9.0 on it
    docker exec -i -e OLDV="$OLDV" -e ID="$2" "$1" bash -s <<'EOF'
set -e
ip link add br0 type bridge && ip link set br0 address 02:99:00:00:00:01 && ip addr add 10.99.0.1/24 dev br0 && ip link set br0 up
for i in 0 1; do ip link add fnic$i type veth peer name fnic$i-sw; ip link set fnic$i-sw master br0 up; done
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE; sysctl -qw net.ipv4.ip_forward=1
mkdir -p /var/lib/misc
dnsmasq --interface=br0 --bind-interfaces --dhcp-range=10.99.0.100,10.99.0.199,12h --dhcp-option=option:router,10.99.0.1 \
  --dhcp-option=option:dns-server,10.99.0.1 --no-resolv --server=1.1.1.1 --pid-file=/run/dnsmasq-lan.pid
systemctl start ssh
tar xzf /root/uxm-probe-$OLDV.tar.gz -C /root
mkdir -p /etc/uxm
python3 - <<PY
import re
s = open("/root/uxm-probe-$OLDV/etc/uxm.toml.example").read()
s = s.replace('probe_id = "probe-01"', 'probe_id = "$ID"').replace("ens19", "fnic0").replace("ens20", "fnic1")
s = re.sub(r"(dhcp|dns|apps)_interval_s = \d+", r"\1_interval_s = 60", s)
s = "# UXM probe configuration: the client end of the Event UXM Platform Spec.\n" + s   # as the lab config starts
open("/etc/uxm/uxm.toml", "w").write(s)
PY
cd /root/uxm-probe-$OLDV && UXM_INSTALL_WAIT_S=15 ./install.sh > /root/install-old.log 2>&1 || { tail -30 /root/install-old.log; exit 1; }
EOF
}
old_collector() {
    docker exec -i -e OLDV="$OLDV" "$1" bash -s <<'EOF'
set -e
tar xzf /root/uxm-collector-$OLDV.tar.gz -C /root
cd /root/uxm-collector-$OLDV && ./install.sh > /root/install-old-collector.log 2>&1 || { tail -30 /root/install-old-collector.log; exit 1; }
EOF
}

echo "== UXM $OLDV, as deployed: a probe and a collector linked over SSH, and an all-in-one host"
check "0.9.0 probe installed (separate host)" old_probe "$P" pkg-probe
check "0.9.0 collector installed (separate host)" old_collector "$C"
check "0.9.0 all-in-one installed (probe, then collector)" eval 'old_probe "$A" aio && old_collector "$A"'
check "0.9.0: the collector adds the probe; the probe authorizes its key, from the collector's address only" on "$C" <<'EOF'
uxm-collector probe add pkg-probe --host "$P" --label "Upgrade test probe" --trust > /root/add.log 2>&1 || { cat /root/add.log; exit 1; }
EOF
KEY=$(docker exec "$C" cat /etc/uxm/collector/keys/pkg-probe_ed25519.pub)
check "0.9.0: authorize-collector --from" docker exec "$P" uxm authorize-collector "$KEY" --from "$CIP"
check "0.9.0: following, and the all-in-one board reads its own probe" eval 'docker exec "$C" uxm-collector apply && docker exec "$A" uxm-collector probe add aio --local && docker exec "$A" uxm-collector apply'
check "0.9.0: the probe's results arrive on the collector" on "$C" <<'EOF'
for i in $(seq 40); do [ -s /var/lib/uxm-collector/probes/pkg-probe/$(date -u +%F)/gateway.jsonl ] && exit 0; sleep 2; done
journalctl -u uxm-follow@pkg-probe --no-pager | tail -5; exit 1
EOF

echo "== history to keep: a DNS outage on the probe's LAN, logged as an incident by the 0.9.0 collector"
on "$P" <<'EOF'
for p in udp tcp; do iptables -I INPUT -i br0 -d 10.99.0.1 -p $p --dport 53 -j DROP; done; sleep 60
for p in udp tcp; do iptables -D INPUT -i br0 -d 10.99.0.1 -p $p --dport 53 -j DROP; done
EOF
check "0.9.0: a DNS incident is logged" on "$C" <<'EOF'
for i in $(seq 20); do
    curl -s "localhost/api/incidents?probe=pkg-probe" | python3 -c 'import sys, json; sys.exit(0 if [x for x in json.load(sys.stdin)["incidents"] if x["kind"] == "down" and x["line"] == "DNS"] else 1)' && exit 0
    sleep 3
done; exit 1
EOF
T0=$(date -u +%Y-%m-%dT%H:%M:%S)                           # everything before this was written by 0.9.0
echo "info  0.9.0 probe: $(docker exec "$P" sh -c 'journalctl -u uxm-cron --no-pager -o cat | grep -ciE "still running|too long|skip"') heartbeat run(s) skipped by supercronic, $(docker exec "$P" sh -c 'cat /var/lib/uxm/results/*/gateway.jsonl | wc -l') gateway results, first $(docker exec "$P" sh -c 'head -qn1 /var/lib/uxm/results/*/gateway.jsonl | cut -c1-40 | head -1')"
STREAM_UID=$(docker exec "$P" id -u uxm-stream)
COLL_IDS=$(docker exec "$C" id uxm-collector | sed 's/ groups=.*//; s/uxm-/exm-/g')
AIO_IDS=$(docker exec "$A" id uxm-collector | sed 's/ groups=.*//; s/uxm-/exm-/g')
OLD_INCIDENTS=$(docker exec "$C" sh -c 'cat /var/lib/uxm-collector/incidents/*.jsonl | wc -l')

echo "== upgrade the probe ($V); its 0.9.0 collector is left running and loses the stream"
check "probe: the $V installer migrates it" on "$P" <<'EOF'
cd /root && tar xzf exm-probe-$V.tar.gz && cd exm-probe-$V && EXM_INSTALL_WAIT_S=15 ./install.sh > /root/upgrade.log 2>&1 || { tail -40 /root/upgrade.log; exit 1; }
grep -q "/etc/uxm/uxm.toml -> /etc/exm/exm.toml" /root/upgrade.log && grep -q "uxm-stream -> exm-stream; 1 collector key(s) kept" /root/upgrade.log \
  && grep -q "note: still says uxm" /root/upgrade.log && grep -q "to change them: .*restart 'exm-dhcp@\*'" /root/upgrade.log || { cat /root/upgrade.log; exit 1; }
EOF
check "probe: services up, both ports leased in exm-* namespaces, none left in uxm-*" on "$P" <<'EOF'
systemctl is-active exm-netns exm-cron exm-dhcp@c01 exm-dhcp@c02 && ip -n exm-c01 -4 addr show fnic0 | grep -q "inet 10.99.0." \
  && ip -n exm-c02 -4 addr show fnic1 | grep -q "inet 10.99.0." && ! ip netns list | grep uxm-
EOF
check "probe: config moved, its paths follow, its names kept" on "$P" <<'EOF'
grep -q '^probe_id = "pkg-probe"' /etc/exm/exm.toml && grep -q '^results_dir = "/var/lib/exm/results"' /etc/exm/exm.toml \
  && grep -q '^hostname_prefix = "uxm-srv02"' /etc/exm/exm.toml && ! grep -n '^#.*uxm' /etc/exm/exm.toml \
  && head -1 /etc/exm/exm.toml | grep -qx '# EXM probe configuration: the client end of the Event UXM Platform Spec.'
EOF
check "probe: every 0.9.0 result is in /var/lib/exm" on "$P" <<'EOF'
python3 - <<PY
import glob, json
old = [json.loads(l) for f in glob.glob("/var/lib/exm/results/*/gateway.jsonl") for l in open(f)]
n = sum(1 for e in old if e["ts"][:19] < "$T0")
print(n, "gateway results from 0.9.0"); raise SystemExit(0 if n >= 5 else 1)
PY
EOF
check "probe: exm-stream is uxm-stream renamed (uid $STREAM_UID), owning nothing" on "$P" <<EOF
[ "\$(id -u exm-stream)" = "$STREAM_UID" ] && ! getent passwd uxm-stream && ! getent group uxm-stream \
  && [ "\$(stat -c %U /var/lib/exm-stream /var/lib/exm-stream/.ssh /var/lib/exm-stream/.ssh/authorized_keys | sort -u)" = root ]
EOF
check "probe: the collector's key kept its from= and now runs exm stream" on "$P" <<'EOF'
ak=/var/lib/exm-stream/.ssh/authorized_keys
[ "$(wc -l < $ak)" = 1 ] && grep -qF 'restrict,command="/opt/exm/bin/exm stream",from="'"$CIP"'" ssh-ed25519 ' $ak || { cat $ak; exit 1; }
EOF
check "probe: no uxm unit, code or path left" on "$P" <<'EOF'
! ls /etc/systemd/system | grep -E '^uxm-' && ! systemctl list-units --all --no-legend 'uxm-*' | grep . \
  && for d in /opt/uxm /usr/local/bin/uxm /etc/uxm /var/lib/uxm /var/lib/uxm-stream /run/uxm; do [ ! -e $d ] || { echo $d; exit 1; }; done
EOF
sleep 60                                                  # the stream stays cut: the 0.9.0 collector asks for uxm-stream
check "probe: a heartbeat every 10 s after the upgrade (at least 5 gateway results in the last minute)" on "$P" <<'EOF'
journalctl -u exm-cron --no-pager -o cat | grep -iE "still running|too long|skip" | tail -3
python3 - <<PY
import json, glob, datetime
cut = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=60)).isoformat()[:19]
n = sum(1 for f in glob.glob("/var/lib/exm/results/*/gateway.jsonl") for l in open(f) if json.loads(l)["ts"][:19] >= cut)
print(n, "gateway results in 60 s"); raise SystemExit(0 if n >= 5 else 1)
PY
EOF

echo "== upgrade the collector ($V)"
check "collector: the $V installer migrates it" on "$C" <<'EOF'
cd /root && tar xzf exm-collector-$V.tar.gz && cd exm-collector-$V && ./install.sh > /root/upgrade.log 2>&1 || { tail -40 /root/upgrade.log; exit 1; }
grep -q "user uxm-collector -> exm-collector" /root/upgrade.log && grep -q "/var/lib/uxm-collector -> /var/lib/exm-collector" /root/upgrade.log || { cat /root/upgrade.log; exit 1; }
EOF
check "collector: exm-collector is uxm-collector renamed ($COLL_IDS)" on "$C" <<EOF
[ "\$(id exm-collector | sed 's/ groups=.*//')" = "$COLL_IDS" ] && ! getent passwd uxm-collector && ! getent group uxm-collector
EOF
check "collector: dashboard, incident log, prune timer and the follower are up" on "$C" <<'EOF'
systemctl is-active exm-web exm-alert exm-collector-prune.timer exm-follow@pkg-probe && curl -sf localhost/healthz >/dev/null
EOF
check "collector: probe file moved, reaches exm-stream; keys root:exm-collector 640" on "$C" <<'EOF'
grep -qx 'user = "exm-stream"' /etc/exm/probes.d/pkg-probe.toml \
  && ! grep -nE '^\s*#.*uxm|/etc/uxm|/var/lib/uxm|/opt/uxm|"uxm-stream"' /etc/exm/probes.d/pkg-probe.toml /etc/exm/collector.toml \
  && [ "$(stat -c '%U:%G %a' /etc/exm/collector/keys/pkg-probe_ed25519)" = "root:exm-collector 640" ] && [ -f /etc/exm/alert-webhook ] \
  && ! ls /etc/exm/probes.d | grep -v -e '^pkg-probe.toml$' -e '\.example$' && ! grep -l uxm /etc/exm/probes.d/*.example
EOF
check "collector: the 0.9.0 incident is still in /api/incidents ($OLD_INCIDENTS line(s) logged before)" on "$C" <<'EOF'
curl -s "localhost/api/incidents?probe=pkg-probe" | python3 -c 'import sys, json, os; i = [x for x in json.load(sys.stdin)["incidents"] if x["kind"] == "down" and x["line"] == "DNS" and x["ts"][:19] < os.environ["T0"]]; print(len(i), "old DNS incident(s)"); sys.exit(0 if i else 1)'
EOF
check "collector: no uxm unit, code or path left" on "$C" <<'EOF'
! ls /etc/systemd/system /etc/systemd/system/*.wants | grep -E '^uxm-' && ! systemctl list-units --all --no-legend 'uxm-*' | grep . \
  && for d in /opt/uxm-collector /usr/local/bin/uxm-collector /etc/uxm /var/lib/uxm-collector; do [ ! -e $d ] || { echo $d; exit 1; }; done
EOF
gap_check() {   # every heartbeat the probe wrote, before and after the upgrade, on the collector exactly once
    python3 - <(docker exec "$P" bash -c 'cat /var/lib/exm/results/*/gateway.jsonl') \
              <(docker exec "$C" bash -c 'cat /var/lib/exm-collector/probes/pkg-probe/*/gateway.jsonl') "$T0" <<'PY'
import sys, json, datetime
probe = [json.loads(l)["emitted"] for l in open(sys.argv[1])]
coll = [json.loads(l)["emitted"] for l in open(sys.argv[2])]
cut = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=15)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
missing = sorted(set(e for e in probe if e < cut) - set(coll))
dups = len(coll) - len(set(coll))
before = sum(1 for e in probe if e[:19] < sys.argv[3])
print(f"probe wrote {len(probe)} ({before} under 0.9.0), collector has {len(coll)}; missing {len(missing)} {missing[:3]}, duplicates {dups}")
sys.exit(0 if not missing and not dups and before >= 5 and len(probe) - before >= 5 else 1)
PY
}
check "no heartbeat lost or doubled across the upgrade (the cut stream caught up)" eval 'for i in $(seq 12); do out=$(gap_check 2>&1) && { echo "$out"; exit 0; }; sleep 5; done; echo "$out"; exit 1'

echo "== all-in-one: probe first, then the collector, back to back"
check "all-in-one: probe migrated; the 0.9.0 collector keeps reading through a link" on "$A" <<'EOF'
cd /root && tar xzf exm-probe-$V.tar.gz && cd exm-probe-$V && EXM_INSTALL_WAIT_S=15 ./install.sh > /root/upgrade.log 2>&1 || { tail -40 /root/upgrade.log; exit 1; }
[ "$(readlink /var/lib/uxm)" = /var/lib/exm ] && [ -f /etc/uxm/collector.toml ] && systemctl is-active uxm-web
EOF
check "all-in-one: collector migrated" on "$A" <<'EOF'
cd /root && tar xzf exm-collector-$V.tar.gz && cd exm-collector-$V && ./install.sh > /root/upgrade.log 2>&1 || { tail -40 /root/upgrade.log; exit 1; }
grep -qx 'results_dir = "/var/lib/exm/results"' /etc/exm/probes.d/aio.toml && systemctl is-active exm-web exm-alert exm-cron exm-netns
EOF
check "all-in-one: exm-collector is uxm-collector renamed ($AIO_IDS); nothing uxm left" on "$A" <<EOF
[ "\$(id exm-collector | sed 's/ groups=.*//')" = "$AIO_IDS" ] && ! getent passwd uxm-collector uxm-stream \
  && ! ls /etc/systemd/system /etc/systemd/system/*.wants | grep -E '^uxm-' && ! ip netns list | grep uxm- \
  && for d in /opt/uxm /opt/uxm-collector /etc/uxm /var/lib/uxm /var/lib/uxm-collector; do [ ! -e \$d ] || { echo \$d; exit 1; }; done
EOF
check "all-in-one: the board serves 0.9.0 history and new results" on "$A" <<'EOF'
for i in $(seq 20); do
    curl -s "localhost/api/history?probe=aio&minutes=30" | python3 -c '
import sys, json, os
w = sorted(e["w"] for e in json.load(sys.stdin)["events"])
old = sum(1 for x in w if x[:19] < os.environ["T0"])
print(len(w), "events,", old, "from 0.9.0, newest", w[-1] if w else None)
sys.exit(0 if old > 10 and w and w[-1][:19] > os.environ["T0"] else 1)' && exit 0
    sleep 3
done; exit 1
EOF

echo "== re-running the installers: nothing left to migrate"
rerun() { docker exec -e V="$V" "$1" bash -c "cd /root/exm-$2-\$V && EXM_INSTALL_WAIT_S=5 ./install.sh" > "$TMPD/rerun-$1-$2.log" 2>&1 && grep -q 'nothing to migrate' "$TMPD/rerun-$1-$2.log" || { tail -20 "$TMPD/rerun-$1-$2.log"; return 1; }; }
check "probe and collector installers again, on each host" eval 'rerun "$P" probe && rerun "$C" collector && rerun "$A" probe && rerun "$A" collector'
check "still following after the re-runs" on "$C" <<'EOF'
sleep 5; systemctl is-active exm-follow@pkg-probe && exm-collector probe list | grep -E "^pkg-probe .* active"
EOF

echo
echo "PASS $PASS   FAIL $FAIL"
exit $FAIL
