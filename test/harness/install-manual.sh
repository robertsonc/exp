#!/bin/bash
# Manual install of exp components from signed release tarballs and a LOCAL config directory: M1 "no manager".
# Run as root on the Ubuntu host (inside the harness host container in tests). It does exactly what exp-agent
# does (docs/spec/06-agent.md section 3, 01-contracts.md sections 10-11), step by step, and refuses on any doubt:
#
#   1. verify the Ed25519 signature of the manifest with openssl against the release public key, then every
#      artifact's size and sha256 against the (now trusted) manifest;
#   2. unpack SAFELY (no absolute/.. paths, no links or devices, size caps) into /opt/exp/<c>/.staging-*, then
#      rename to /opt/exp/<c>/<version> and flip the `current` symlink; /usr/local/bin/exp-<c> -> current;
#   3. install the packages in requirements.apt, but only those on the agent's allowlist;
#   4. create the service users (collector: exp-collector + exp-vm; dashboard: exp-dashboard);
#   5. write /etc/exp/<c>/config.json (0644) and /etc/exp/<c>/creds/* (0600, dir 0700) from the local config dir,
#      plus an empty file for every LoadCredential= a unit names (a missing one stops the unit from starting);
#   6. prepare /var/lib/exp/<c> (collector: tls/ vm/ per docs/spec/changes/CR-wp2-state-layout-and-wrappers.md;
#      dashboard: tls/) and generate the self-signed P-256 key+cert locally (never sent anywhere);
#   7. render the unit templates by plain placeholder substitution (@VERSION@ @PREFIX@ @CONFIG@ @CREDS@ @STATE@
#      @RUN@ only; config values are never interpolated), daemon-reload, enable and start in dependency order;
#   8. wait for `exp-<c> health --json` to pass.
#
# usage: install-manual.sh [--pubkey FILE] [--conf DIR] [--no-start] <dist-dir> <shape>...
#   shapes: collector dashboard probe        (any subset; install the collector first: probes and the dashboard
#                                             pin its TLS fingerprint, printed as "FINGERPRINT collector AA:BB:..")
#   --pubkey   release public key PEM (default /etc/exp/release-pub.pem)
#   --conf     local config directory: DIR/<shape>/config.json and DIR/<shape>/creds/<name> (default /root/exp-conf)
set -euo pipefail
umask 022
export LC_ALL=C DEBIAN_FRONTEND=noninteractive

PUBKEY=/etc/exp/release-pub.pem
CONF=/root/exp-conf
START=1
APT_ALLOW=" busybox busybox-static iproute2 iputils-ping iperf3 curl openssl ca-certificates ethtool iw wpasupplicant tcpdump "

die() { echo "install-manual: $*" >&2; exit 1; }
say() { echo "install-manual: $*" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --pubkey) PUBKEY=${2:?}; shift 2 ;;
        --conf) CONF=${2:?}; shift 2 ;;
        --no-start) START=0; shift ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d;s/^# \{0,1\}//'; exit 0 ;;
        --) shift; break ;;
        -*) die "unknown option $1" ;;
        *) break ;;
    esac
done
[ $# -ge 2 ] || die "usage: install-manual.sh [--pubkey FILE] [--conf DIR] [--no-start] <dist-dir> <shape>..."
DIST=$1; shift
SHAPES=("$@")
[ "$(id -u)" = 0 ] || die "run as root"
for t in openssl python3 tar sha256sum base64 systemctl install; do command -v "$t" >/dev/null || die "$t is required"; done
[ -d "$DIST" ] || die "dist dir $DIST not found"
[ -f "$PUBKEY" ] || die "release public key $PUBKEY not found (--pubkey)"
for s in "${SHAPES[@]}"; do
    case "$s" in collector|dashboard|probe) ;; *) die "unknown shape '$s' (collector|dashboard|probe)" ;; esac
    [ -f "$CONF/$s/config.json" ] || die "$CONF/$s/config.json not found"
done

case "$(dpkg --print-architecture 2>/dev/null || uname -m)" in
    amd64|x86_64) ARCH=amd64 ;; arm64|aarch64) ARCH=arm64 ;; *) die "unsupported architecture" ;;
esac

# ------------------------------------------------------------------ 1. verify (signature, then every hash)
shopt -s nullglob
manifests=("$DIST"/exp-*-manifest.json)
[ "${#manifests[@]}" -eq 1 ] || die "expected exactly one exp-<version>-manifest.json in $DIST, found ${#manifests[@]}"
MAN=${manifests[0]}
SIG="$MAN.sig"
[ -f "$SIG" ] || die "missing $SIG"
TMP=$(mktemp -d /root/.exp-install.XXXXXX); chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT
base64 -d "$SIG" > "$TMP/sig.bin" 2>/dev/null || die "signature file is not base64"
openssl pkeyutl -verify -pubin -inkey "$PUBKEY" -rawin -in "$MAN" -sigfile "$TMP/sig.bin" >/dev/null 2>&1 \
    || die "REFUSED: manifest signature does not verify against $PUBKEY"
say "manifest signature OK"

# manifest -> "version" and per-component "<file> <sha256> <size>" (python reads only; nothing is executed)
VERSION=$(python3 -I - "$MAN" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))
v = d.get("version", "")
if d.get("schema") != "exp.manifest/1" or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?", v):
    sys.exit("bad manifest")
print(v)
PY
) || die "unusable manifest"
artifact() {   # component -> "file sha256 size" for this arch (noarch preferred)
    python3 -I - "$MAN" "$1" "$ARCH" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1])); comp, arch = sys.argv[2:4]
best = None
for a in d["artifacts"]:
    if a.get("component") == comp and a.get("arch") in ("noarch", arch):
        if not re.fullmatch(r"exp-[a-z]+-[0-9A-Za-z.+-]+-(noarch|amd64|arm64)\.tar\.gz", a["name"]):
            sys.exit("bad artifact name")
        if best is None or a["arch"] == "noarch":
            best = a
if best is None:
    sys.exit("no artifact for %s/%s" % (comp, arch))
print(best["name"], best["sha256"], best["size"])
PY
}

# ------------------------------------------------------------------ helpers
unit_dir=/etc/systemd/system

safe_unpack_check() {   # tarball top-dir
    python3 -I - "$1" "$2" <<'PY'
import sys, tarfile
path, top = sys.argv[1:3]
total = n = 0
with tarfile.open(path, "r:gz") as t:
    for m in t:
        n += 1
        parts = m.name.split("/")
        if n > 20000 or m.name.startswith("/") or ".." in parts or "\\" in m.name or "\0" in m.name:
            sys.exit("REFUSED: unsafe path %r" % m.name[:80])
        if parts[0] != top:
            sys.exit("REFUSED: %r is outside %s/" % (m.name[:80], top))
        if not (m.isreg() or m.isdir()):
            sys.exit("REFUSED: %r is a link/device/special file" % m.name[:80])
        total += m.size
        if m.size > 200 * 2**20 or total > 600 * 2**20:
            sys.exit("REFUSED: archive too large")
PY
}

component_install() {   # c -> unpacks and activates; sets PREFIX
    local c=$1 file sha size top stage
    read -r file sha size < <(artifact "$c") || die "no $c artifact for $ARCH in the manifest"
    [ -f "$DIST/$file" ] || die "$DIST/$file not found"
    [ "$(stat -c %s "$DIST/$file")" = "$size" ] || die "REFUSED: $file size differs from the manifest"
    [ "$(sha256sum "$DIST/$file" | cut -d' ' -f1)" = "$sha" ] || die "REFUSED: $file sha256 differs from the manifest"
    top="exp-$c-$VERSION"
    safe_unpack_check "$DIST/$file" "$top" || die "REFUSED to unpack $file"
    PREFIX=/opt/exp/$c/$VERSION
    install -d -m 0755 -o root -g root /opt/exp "/opt/exp/$c"
    if [ -d "$PREFIX" ]; then
        say "$c $VERSION already unpacked"
    else
        stage=$(mktemp -d "/opt/exp/$c/.staging-XXXXXX")
        tar -xzf "$DIST/$file" -C "$stage" --strip-components=1 --no-same-owner --no-same-permissions
        chown -R root:root "$stage"; chmod -R go-w "$stage"; chmod 0755 "$stage"
        [ -x "$stage/bin/exp-$c" ] || die "$file has no bin/exp-$c"
        mv -T "$stage" "$PREFIX"
    fi
    ln -sfn "$VERSION" "/opt/exp/$c/current.new" && mv -T "/opt/exp/$c/current.new" "/opt/exp/$c/current"
    ln -sfn "../../../opt/exp/$c/current/bin/exp-$c" "/usr/local/bin/exp-$c"
}

apt_requirements() {    # c
    local f=$PREFIX/requirements.apt pkg missing=()
    [ -f "$f" ] || return 0
    while read -r pkg; do
        pkg=${pkg%%#*}; pkg=${pkg// /}
        [ -n "$pkg" ] || continue
        [[ "$APT_ALLOW" == *" $pkg "* ]] || die "REFUSED: requirements.apt names '$pkg', which is not on the allowlist"
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done < "$f"
    if [ "${#missing[@]}" -gt 0 ]; then
        say "apt-get install ${missing[*]}"
        apt-get update -qq >/dev/null 2>&1 || say "apt-get update failed (continuing with cached lists)"
        apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null || die "apt-get install failed: ${missing[*]}"
    fi
}

ensure_user() {         # name
    getent passwd "$1" >/dev/null || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$1"
}

jget() {                # file dotted.path  (read-only config query; "listen_ip" and "client_ports" are derived)
    python3 -I - "$1" "$2" <<'PY' 2>/dev/null
import json, sys
d = json.load(open(sys.argv[1])); key = sys.argv[2]
if key == "listen_ip":
    print(d["listen"].rsplit(":", 1)[0])
elif key == "client_ports":
    print(" ".join(p["id"] for p in d["ports"] if p["role"] == "client"))
else:
    for part in key.split("."):
        d = d[part]
    print(d)
PY
}

install_config() {      # c
    local c=$1 f
    install -d -m 0755 -o root -g root /etc/exp "/etc/exp/$c"
    install -d -m 0700 -o root -g root "/etc/exp/$c/creds"
    install -m 0644 -o root -g root "$CONF/$c/config.json" "/etc/exp/$c/config.json"
    if [ -d "$CONF/$c/creds" ]; then
        for f in "$CONF/$c/creds"/*; do
            [ -f "$f" ] && [ ! -L "$f" ] || continue
            install -m 0600 -o root -g root "$f" "/etc/exp/$c/creds/$(basename "$f")"
        done
    fi
    # every credential a unit names must exist (possibly empty)
    local name
    for name in $(grep -hoE '^LoadCredential=[^:]+' "$PREFIX"/systemd/* 2>/dev/null | cut -d= -f2 | sort -u); do
        [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "unit names a suspicious credential '$name'"
        [ -e "/etc/exp/$c/creds/$name" ] || install -m 0600 -o root -g root /dev/null "/etc/exp/$c/creds/$name"
    done
}

make_tls() {            # c service-user cn san
    local c=$1 user=$2 cn=$3 san=$4 state=/var/lib/exp/$1 d
    for d in "$state" "$state/tls"; do [ ! -L "$d" ] || die "REFUSED: $d is a symlink"; done
    if [ -s "$state/tls/key.pem" ] && [ -s "$state/tls/cert.pem" ]; then
        say "$c TLS pair already present"
    else
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=$cn" \
            -addext "subjectAltName=$san" -keyout "$TMP/$c.key" -out "$TMP/$c.crt" 2>/dev/null || die "openssl req failed"
        install -m 0600 -o "$user" -g "$user" "$TMP/$c.key" "$state/tls/key.pem"
        install -m 0644 -o "$user" -g "$user" "$TMP/$c.crt" "$state/tls/cert.pem"
    fi
    TLS_FP=$(openssl x509 -in "$state/tls/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)
    echo "$TLS_FP" > "/etc/exp/$c/tls_fingerprint"
    echo "FINGERPRINT $c $TLS_FP"
}

host_ips() { hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true; }

render_units() {        # c
    local c=$1 u out
    local cfg=/etc/exp/$c/config.json creds=/etc/exp/$c/creds state=/var/lib/exp/$c run=/run/exp/$c
    for u in "$PREFIX"/systemd/exp-*.service "$PREFIX"/systemd/exp-*.timer; do
        [ -e "$u" ] || continue
        out="$unit_dir/$(basename "$u")"
        sed -e "s|@VERSION@|$VERSION|g" -e "s|@PREFIX@|$PREFIX|g" -e "s|@CONFIG@|$cfg|g" \
            -e "s|@CREDS@|$creds|g" -e "s|@STATE@|$state|g" -e "s|@RUN@|$run|g" "$u" > "$out.new"
        if grep -q '@[A-Z_]*@' "$out.new"; then rm -f "$out.new"; die "unit $(basename "$u") has an unknown placeholder"; fi
        chmod 0644 "$out.new"; mv -f "$out.new" "$out"
    done
}

start_units() {         # unit...
    systemctl daemon-reload
    local u
    for u in "$@"; do
        systemctl enable "$u" >/dev/null 2>&1 || die "systemctl enable $u failed"
        if [ "$START" = 1 ]; then systemctl restart "$u" || { journalctl -u "$u" --no-pager -n 20 >&2 || true; die "$u failed to start"; }; fi
    done
}

health_gate() {         # c
    [ "$START" = 1 ] || return 0
    local c=$1 i out=""
    for i in $(seq 60); do
        if out=$(CREDENTIALS_DIRECTORY="/etc/exp/$c/creds" "/opt/exp/$c/current/bin/exp-$c" health --json --config "/etc/exp/$c/config.json" 2>&1); then
            say "$c health: $(printf '%s' "$out" | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("status"))' 2>/dev/null || echo ok)"
            return 0
        fi
        sleep 1
    done
    printf '%s\n' "$out" | tail -c 1500 >&2
    die "$c did not become healthy within 60 s"
}

# ------------------------------------------------------------------ per shape
for s in collector dashboard probe; do          # fixed order: the collector first, then what pins its certificate
    case " ${SHAPES[*]} " in *" $s "*) ;; *) continue ;; esac
    say "== $s $VERSION"
    component_install "$s"
    apt_requirements "$s"
    cfg=$CONF/$s/config.json
    case "$s" in
        collector)
            ensure_user exp-collector; ensure_user exp-vm
            install_config collector
            install -d -m 0755 /var/lib/exp
            [ ! -L /var/lib/exp/collector ] || die "REFUSED: /var/lib/exp/collector is a symlink"
            install -d -m 0755 -o exp-collector -g exp-collector /var/lib/exp/collector
            install -d -m 0700 -o exp-collector -g exp-collector /var/lib/exp/collector/tls
            install -d -m 0700 -o exp-vm -g exp-vm /var/lib/exp/collector/vm
            lip=$(jget "$cfg" listen_ip)
            make_tls collector exp-collector "$(jget "$cfg" collector_id)" "IP:$lip,IP:127.0.0.1,DNS:$(hostname)"
            render_units collector
            CREDENTIALS_DIRECTORY=/etc/exp/collector/creds "$PREFIX/bin/exp-collector" selftest --config /etc/exp/collector/config.json >/dev/null \
                || die "exp-collector selftest failed"
            start_units exp-victoriametrics.service exp-collector.service exp-reflector.service exp-iperf3.service
            health_gate collector ;;
        dashboard)
            ensure_user exp-dashboard
            install_config dashboard
            install -d -m 0755 /var/lib/exp
            [ ! -L /var/lib/exp/dashboard ] || die "REFUSED: /var/lib/exp/dashboard is a symlink"
            install -d -m 0700 -o exp-dashboard -g exp-dashboard /var/lib/exp/dashboard
            install -d -m 0700 -o exp-dashboard -g exp-dashboard /var/lib/exp/dashboard/tls
            if [ "$(jget "$cfg" tls.mode)" != provided ]; then
                san="DNS:$(hostname),IP:127.0.0.1"
                for ip in $(host_ips); do san="$san,IP:$ip"; done
                make_tls dashboard exp-dashboard "$(jget "$cfg" dashboard_id)" "$san"
            fi
            render_units dashboard
            CREDENTIALS_DIRECTORY=/etc/exp/dashboard/creds "$PREFIX/bin/exp-dashboard" selftest --config /etc/exp/dashboard/config.json >/dev/null \
                || die "exp-dashboard selftest failed"
            start_units exp-dashboard.service
            health_gate dashboard ;;
        probe)
            install_config probe
            install -d -m 0755 /var/lib/exp
            render_units probe
            CREDENTIALS_DIRECTORY=/etc/exp/probe/creds "$PREFIX/bin/exp-probe" selftest --config /etc/exp/probe/config.json >/dev/null || die "exp-probe selftest failed"
            units=(exp-probe-netns.service)
            for pid in $(jget "$cfg" client_ports); do
                [[ "$pid" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]] || die "port id '$pid' is not a slug"
                units+=("exp-probe-lease@$pid.service")
            done
            units+=(exp-probe.service)
            start_units "${units[@]}"
            health_gate probe ;;
    esac
done
say "done: ${SHAPES[*]} $VERSION"
