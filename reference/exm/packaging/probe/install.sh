#!/usr/bin/env bash
# Install or upgrade the EXM probe (exm-probe package):   sudo ./install.sh
# Idempotent: re-running converges to the same state. It keeps /etc/exm/exm.toml,
# results, and any collector keys. Check without changing anything: ./install.sh --preflight
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SUPERCRONIC_VERSION="v0.2.51"
SUPERCRONIC_SHA256="cc232108374e8e2b537045f2d5eaa1229f619db314c3ba6a14d38b35dc0aa123"
WAIT_S="${EXM_INSTALL_WAIT_S:-40}"

PREFLIGHT_ONLY=0
[ "${1:-}" = "--preflight" ] && PREFLIGHT_ONLY=1      # check only; needs no root, changes nothing
[ "$PREFLIGHT_ONLY" -eq 1 ] || [ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo $0   (or $0 --preflight to check only)" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

VERSION="$(cat "$HERE/VERSION")"
CFG=/etc/exm/exm.toml
[ -f "$CFG" ] || CFG=/etc/uxm/uxm.toml                  # 0.9.0 was called UXM: its config is migrated below
[ -f "$CFG" ] || CFG="$HERE/etc/exm.toml.example"
echo "exm-probe $VERSION"

say "Preflight: every configured port must be free to move (nothing is changed if not)"
python3 - "$CFG" <<'PY'
import json, os, subprocess, sys, tomllib
cfg = tomllib.load(open(sys.argv[1], "rb"))
def ipj(*a):
    out = subprocess.run(["ip", "-j", *a], capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else []
default_devs = {r.get("dev") for r in ipj("route", "show", "default")}
bad = []
for c in cfg.get("client", []):
    i = c["iface"]
    link = ipj("-d", "link", "show", "dev", i)
    if not link:
        # An upgrade's ports are inside the probe's namespaces (uxm-* before 0.9.1), not missing.
        nss = [ns for ns in ("exm-" + c["id"], "uxm-" + c["id"]) if os.path.exists(f"/run/netns/{ns}")]
        inside = [ns for ns in nss if subprocess.run(["ip", "-n", ns, "link", "show", "dev", i], capture_output=True).returncode == 0]
        if inside:
            print(f"  {c['id']} {i}: already in {inside[0]}")
        elif os.geteuid() != 0 and nss:
            # Only root can look inside a namespace.
            print(f"  {c['id']} {i}: in {nss[0]} (probe already installed; run as root to look inside)")
        else:
            bad.append(f"{i}: not found on this host")
        continue
    L = link[0]
    if L.get("master"):
        bad.append(f"{i}: enslaved to {L['master']}")
    for e in ipj("addr", "show", "dev", i):
        for a in e.get("addr_info", []):
            if a.get("scope") == "global":
                bad.append(f"{i}: carries address {a['local']}")
    if i in default_devs:
        bad.append(f"{i}: holds the default route")
    print(f"  {c['id']} {i}: free (mac {L.get('address')}, {L.get('operstate')})")
if bad:
    print("\nREFUSING to install. Nothing has been changed:")
    for b in bad:
        print("  - " + b)
    sys.exit(1)
PY

if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
    echo; echo "Preflight passed. Install with: sudo $0"
    exit 0
fi

say "Packages"
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3-scapy python3-dnspython curl iproute2 tcpdump iputils-ping openssl >/dev/null
busybox --list 2>/dev/null | grep -qx udhcpc || { echo "busybox with udhcpc is required (apt install busybox-static)" >&2; exit 1; }
echo "  python3-scapy, python3-dnspython, curl, iproute2, tcpdump present; busybox udhcpc present"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "python 3.11 or newer is required (tomllib)" >&2; exit 1; }
command -v sshd >/dev/null || echo "  NOTE: no sshd: the collector reaches probes over SSH (apt install openssh-server)"

say "supercronic $SUPERCRONIC_VERSION"
SRC="$HERE/vendor/supercronic-linux-amd64"
if [ ! -f "$SRC" ]; then
    SRC="$(mktemp)"
    curl -fsSL -o "$SRC" "https://github.com/aptible/supercronic/releases/download/$SUPERCRONIC_VERSION/supercronic-linux-amd64"
fi
echo "$SUPERCRONIC_SHA256  $SRC" | sha256sum -c --quiet - || { echo "supercronic checksum mismatch; refusing" >&2; exit 1; }
install -o root -g root -m 0755 "$SRC" /usr/local/bin/supercronic
echo "  /usr/local/bin/supercronic (sha256 verified)"

say "Upgrade from UXM"
# 0.9.0 was called UXM. Its config, results and collector keys move to the EXM names, in place.
# Every step checks for the old thing first, so a re-run (or a run after a failed one) finishes the job.
migrated=0
if compgen -G '/etc/systemd/system/uxm-netns.service' >/dev/null || compgen -G '/etc/systemd/system/uxm-dhcp@*' >/dev/null || [ -x /opt/uxm/bin/uxm ]; then
    systemctl disable --now uxm-cron.service 2>/dev/null || true
    for u in $(systemctl list-units --all --plain --no-legend 'uxm-dhcp@*' 'uxm-server@*' | awk '{print $1}'); do
        systemctl disable --now "$u" 2>/dev/null || true
    done
    systemctl disable --now uxm-netns.service 2>/dev/null || true     # its stop action hands the ports back
    systemctl disable --now uxm-bypass.service 2>/dev/null || true    # no stop action: the ports stay connected
    [ -x /opt/uxm/bin/uxm ] && { /opt/uxm/bin/uxm netns down || true; }
    rm -rf /etc/systemd/system/uxm-netns.service.wants /run/uxm
    rm -f /etc/systemd/system/uxm-netns.service /etc/systemd/system/uxm-dhcp@.service /etc/systemd/system/uxm-cron.service \
          /etc/systemd/system/uxm-bypass.service /etc/systemd/system/uxm-server@.service
    systemctl daemon-reload
    echo "  stopped and removed the uxm-* probe units; ports are back on the host until EXM takes them"
    migrated=1
fi
install -d -m 0755 /etc/exm
if [ -f /etc/uxm/uxm.toml ] && [ ! -f /etc/exm/exm.toml ]; then
    # Paths follow the move and the package's comments say EXM; names (hostname_prefix, vendor_class) are yours and stay.
    sed -e 's#/var/lib/uxm/#/var/lib/exm/#g' -e 's#/etc/uxm/#/etc/exm/#g' \
        -e '/^\s*#/{s/UXM Platform Spec/@SPEC@/g;s/uxm/exm/g;s/UXM/EXM/g;s/@SPEC@/UXM Platform Spec/g}' /etc/uxm/uxm.toml > /etc/exm/exm.toml.new
    chmod --reference=/etc/uxm/uxm.toml /etc/exm/exm.toml.new
    mv /etc/exm/exm.toml.new /etc/exm/exm.toml
    for f in /etc/uxm/uxm.toml.*; do [ -f "$f" ] && mv "$f" "/etc/exm/exm.toml.${f#/etc/uxm/uxm.toml.}"; done
    rm -f /etc/uxm/uxm.toml /etc/uxm/crontab
    echo "  /etc/uxm/uxm.toml -> /etc/exm/exm.toml"
    if grep -nE '^\s*(hostname_prefix|vendor_class)\s*=.*uxm' /etc/exm/exm.toml | sed 's/^/  note: still says uxm (your choice to change): /'; then
        echo "  to change them: edit /etc/exm/exm.toml, then sudo systemctl restart 'exm-dhcp@*' (lease holders read them at start)"
    fi
    migrated=1
fi
if [ -d /etc/uxm/tls ] && [ ! -L /etc/uxm/tls ] && [ ! -e /etc/exm/tls ]; then
    mv /etc/uxm/tls /etc/exm/tls && echo "  /etc/uxm/tls -> /etc/exm/tls"
fi
if [ -d /var/lib/uxm ] && [ ! -L /var/lib/uxm ]; then
    if [ -e /var/lib/exm ]; then
        echo "  NOTE: both /var/lib/uxm and /var/lib/exm exist; left /var/lib/uxm alone (merge or delete it yourself)"
    else
        mv /var/lib/uxm /var/lib/exm
        echo "  /var/lib/uxm -> /var/lib/exm (results kept)"
        # A UXM collector on this host still reads the old path until it is upgraded too.
        [ -f /etc/uxm/collector.toml ] && ln -s /var/lib/exm /var/lib/uxm && echo "  /var/lib/uxm -> /var/lib/exm link for the UXM collector here (its upgrade removes it)"
    fi
    migrated=1
fi
if getent passwd uxm-stream >/dev/null; then
    if getent passwd exm-stream >/dev/null; then
        echo "  NOTE: both uxm-stream and exm-stream exist; left uxm-stream alone"
    else
        # Same uid, new name: the collector keys stay authorized, now for exm-stream and `exm stream`.
        usermod -L -s /usr/sbin/nologin uxm-stream     # no new stream starts while it is renamed
        [ -d /var/lib/uxm-stream ] && [ ! -L /var/lib/uxm-stream ] && [ ! -e /var/lib/exm-stream ] && mv /var/lib/uxm-stream /var/lib/exm-stream
        for i in 1 2 3 4 5; do                          # usermod refuses while a stream is still running
            pkill -u uxm-stream 2>/dev/null || true; sleep 1
            usermod -l exm-stream -d /var/lib/exm-stream -c "EXM collector stream (forced command only)" uxm-stream 2>/dev/null && break
        done
        getent passwd exm-stream >/dev/null || { echo "could not rename uxm-stream to exm-stream (still in use?): re-run this installer" >&2; exit 1; }
        getent group uxm-stream >/dev/null && groupmod -n exm-stream uxm-stream
        usermod -p '*' -s /bin/sh exm-stream           # as authorize-collector leaves it
        ak=/var/lib/exm-stream/.ssh/authorized_keys
        if [ -f "$ak" ] && [ ! -L "$ak" ]; then
            sed 's#command="/opt/uxm/bin/uxm stream"#command="/opt/exm/bin/exm stream"#' "$ak" > "$ak.tmp"
            chown root:root "$ak.tmp"; chmod 0644 "$ak.tmp"; mv "$ak.tmp" "$ak"
            echo "  uxm-stream -> exm-stream; $(grep -c 'exm/bin/exm stream' "$ak") collector key(s) kept (upgrade the collector next)"
        else
            echo "  uxm-stream -> exm-stream (no collector keys)"
        fi
    fi
    migrated=1
fi
if [ -e /opt/uxm ] || [ -L /usr/local/bin/uxm ]; then
    rm -rf /opt/uxm; rm -f /usr/local/bin/uxm
    echo "  removed /opt/uxm and /usr/local/bin/uxm"
fi
rmdir /etc/uxm 2>/dev/null || true                     # kept while a UXM collector still uses it
[ "$migrated" -eq 1 ] || echo "  nothing to migrate"

say "Files"
rm -rf /opt/exm.new
mkdir -p /opt/exm.new
cp -r "$HERE/bin" "$HERE/lib" "$HERE/hooks" "$HERE/README.md" "$HERE/VERSION" /opt/exm.new/
find /opt/exm.new -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root /opt/exm.new          # root runs this code: no user may be able to edit it
chmod -R go-w /opt/exm.new
rm -rf /opt/exm.old
[ -d /opt/exm ] && mv /opt/exm /opt/exm.old
mv /opt/exm.new /opt/exm
rm -rf /opt/exm.old
ln -sf /opt/exm/bin/exm /usr/local/bin/exm
install -d -m 0755 /etc/exm /var/lib/exm /var/lib/exm/results /var/lib/exm/state
if [ -f /etc/exm/exm.toml ]; then
    echo "  keeping existing /etc/exm/exm.toml"
else
    install -m 0644 "$HERE/etc/exm.toml.example" /etc/exm/exm.toml
    echo "  /etc/exm/exm.toml installed from the example: edit the [[client]] ports, then: sudo exm apply"
fi
install -m 0644 "$HERE"/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
echo "  /opt/exm, /usr/local/bin/exm, units in /etc/systemd/system"

say "Services"
# Silicom bypass adapters need their control driver to connect the ports at boot.
if grep -qx 0x1374 /sys/bus/pci/devices/*/subsystem_vendor 2>/dev/null; then
    if modinfo bpctl_mod >/dev/null 2>&1 && [ -x /usr/local/sbin/bpctl_util ]; then
        systemctl enable --now exm-bypass.service || echo "  exm-bypass.service failed: see journalctl -u exm-bypass"
    else
        echo "  Silicom bypass adapters found but bpctl_mod/bpctl_util are not installed: ports will show no link."
        echo "  See README, 'Silicom bypass adapters'."
    fi
fi
systemctl enable --now exm-netns.service
systemctl enable exm-cron.service
/opt/exm/bin/exm apply

say "Waiting ${WAIT_S}s for DHCP leases"
sleep "$WAIT_S"
/opt/exm/bin/exm status --write
PROBE_ID=$(python3 -c 'import tomllib; print(tomllib.load(open("/etc/exm/exm.toml", "rb"))["probe_id"])')
KEEP=$(python3 -c 'import tomllib; print(tomllib.load(open("/etc/exm/exm.toml", "rb")).get("retention_days", 7))')
cat <<MSG

exm-probe $VERSION installed as "$PROBE_ID". Tests start on the next cron tick: each
client runs DHCP, DNS and app tests every 5 minutes (staggered), heartbeats run
every 10 s, and one client runs a speed test every 10 minutes.

  collector  on the collector: sudo exm-collector probe add $PROBE_ID --host <this probe's mgmt address>
             then here:        sudo exm authorize-collector '<the key it prints>'
  results    /var/lib/exm/results/<date>/<test>.jsonl   (kept $KEEP days)
  summary    exm summary --minutes 30
  status     exm status            (non-root: last snapshot)
  logs       journalctl -u exm-cron -u 'exm-dhcp@*' -f
  config     /etc/exm/exm.toml, then: sudo exm apply
  remove     sudo ./uninstall.sh   (returns every port to the host)
MSG
