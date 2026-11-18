#!/usr/bin/env bash
# exp host bootstrap (docs/spec/06-agent.md section 1).
#
#   curl -fsSL https://<manager>/install.sh | sudo bash -s -- expe_XXXXXXXX...
#
# No argument and no /etc/exp/agent.json: the token is prompted for with echo off (read from /dev/tty).
# Re-run with a new token: re-enrols this host (replaces its credentials).
# Re-run with no token on an enrolled host: repairs the agent installation.
#
# This file is served by the manager with three values substituted at serve time (no secrets); it
# refuses to run while any of them is still a placeholder. Preflight changes nothing on the host
# except installing ca-certificates/curl/openssl when one is missing; everything else happens after
# the enrol step. The enrol token is only ever sent in the JSON body of POST /api/agent/v1/enrol
# (curl --data @- from a pipe), never in argv or a URL; the agent secret goes straight into
# /etc/exp/agent.json (0600) and to curl through a config pipe, never into argv, a log or the screen.
set -euo pipefail
set +x # a traced run would print the token; tracing is switched off on purpose
umask 077
unset HISTFILE || true

MANAGER_URL='@@MANAGER_URL@@'
AGENT_VERSION='@@AGENT_VERSION@@'
RELEASE_PUBKEY_PEM='@@RELEASE_PUBKEY_PEM@@'

# ----------------------------------------------------------------------------------------------
# Python helper: every parse/validate/write step that handles remote data or secrets. Standard
# library only, run isolated (-I). Subcommands are called as: py <name> [args...]
# ----------------------------------------------------------------------------------------------
IFS= read -r -d '' PYHELPER <<'PYEOF' || true
import base64, json, os, platform, re, sys, tarfile, tempfile

TOKEN_RE = re.compile(r"expe_[A-Za-z0-9_-]{43}\Z")
SECRET_RE = re.compile(r"expa_[A-Za-z0-9_-]{43}\Z")
HOST_RE = re.compile(r"h_[0-9A-Za-z]{26}\Z")
ART_RE = re.compile(r"art_[0-9A-HJKMNP-TV-Z]{26}\Z")
SEMVER_RE = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.]+))?\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
CONFIG = "/etc/exp/agent.json"
UNITS = ("exp-agent.service", "exp-agent-rollback.service", "exp-agent-rollback.timer")
MAX_FILES, MAX_TOTAL, MAX_NAME = 20000, 512 * 1024 * 1024, 4096


def die(msg):
    sys.stderr.write("exp install: ERROR: " + msg + "\n")
    sys.exit(1)


def clean(s, n=80):
    return "".join(c for c in str(s) if c.isprintable())[:n]


def semver(v):
    m = SEMVER_RE.match(v or "")
    if not m:
        die("invalid version %r" % clean(v))
    pre = m.group(4)
    key = (1,) if pre is None else (0,) + tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), key


def load_json(path, limit):
    with open(path, "rb") as fh:
        raw = fh.read(limit + 1)
    if len(raw) > limit:
        die("%s is larger than %d bytes" % (os.path.basename(path), limit))
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError:
        die("%s is not valid JSON" % os.path.basename(path))
    return doc


def cmd_facts(arch):
    # token on stdin -> the enrol request body on stdout. Minimal facts: hostname, machine-id, os, arch.
    token = sys.stdin.read().strip()
    if not TOKEN_RE.match(token):
        die("that does not look like an enrol token (expe_ followed by 43 characters)")
    osr = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                k, sep, v = line.partition("=")
                if sep:
                    osr[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    try:
        with open("/etc/machine-id", encoding="ascii") as fh:
            mid = fh.read().strip()[:64]
    except OSError:
        mid = ""
    facts = {
        "hostname": platform.node()[:253] or "unknown",
        "arch": arch,
        "os": {"id": osr.get("ID", "")[:32], "version": osr.get("VERSION_ID", "")[:32]},
        "kernel": platform.release()[:128],
        "cpus": max(1, os.cpu_count() or 1),
        "python": platform.python_version()[:32],
    }
    if mid:
        facts["machine_id"] = mid
    sys.stdout.write(json.dumps({"token": token, "facts": facts}))


def cmd_write_config(manager_url, pubkey_pem):
    # enrol response on stdin -> /etc/exp/agent.json (0600, atomic). Prints agent_id and host name only.
    raw = sys.stdin.buffer.read(1 << 20)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError:
        die("the manager's enrol answer is not valid JSON")
    if not isinstance(doc, dict):
        die("the manager's enrol answer is not an object")
    aid, sec = doc.get("agent_id"), doc.get("agent_secret")
    if not (isinstance(aid, str) and HOST_RE.match(aid)):
        die("the manager's enrol answer has no valid agent_id")
    if not (isinstance(sec, str) and SECRET_RE.match(sec)):
        die("the manager's enrol answer has no valid agent_secret")
    theirs = doc.get("release_pubkey_pem")
    if isinstance(theirs, str) and theirs.strip() != pubkey_pem.strip():
        sys.stderr.write("exp install: warning: the manager's release key differs from the one pinned in this installer; "
                         "using the pinned key\n")
    cfg = {"manager_url": manager_url, "agent_id": aid, "agent_secret": sec, "release_pubkey_pem": pubkey_pem.strip() + "\n"}
    os.makedirs("/etc/exp", mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir="/etc/exp", prefix=".agent.json.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(cfg, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, CONFIG)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dfd = os.open("/etc/exp", os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    name = doc.get("host_name")
    print(aid + "\t" + (clean(name, 64) if isinstance(name, str) else ""))


def read_config(manager_url):
    try:
        fd = os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        die("%s cannot be read (%s)" % (CONFIG, exc.strerror))
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or (st.st_mode & 0o077) or not os.path.isfile(CONFIG):
            die("%s must be a regular file owned by root with mode 0600 (chmod 600 %s)" % (CONFIG, CONFIG))
        with os.fdopen(fd, "rb", closefd=False) as fh:
            doc = json.loads(fh.read(65537).decode("utf-8"))
    except ValueError:
        die("%s is not valid JSON; re-run with an enrol token" % CONFIG)
    finally:
        os.close(fd)
    if not (isinstance(doc, dict) and HOST_RE.match(str(doc.get("agent_id", ""))) and SECRET_RE.match(str(doc.get("agent_secret", "")))):
        die("%s is not a valid agent config; re-run with an enrol token" % CONFIG)
    if manager_url and doc.get("manager_url") != manager_url:
        die("this host is enrolled with a different manager (%s); re-run with an enrol token from %s to move it"
            % (clean(doc.get("manager_url")), manager_url))
    return doc


def cmd_check_config(manager_url):
    print(read_config(manager_url)["agent_id"])


def cmd_authcfg():
    # curl config on stdout (piped into `curl -K -`): the bearer header never touches argv.
    sec = read_config("")["agent_secret"]
    sys.stdout.write('header = "Authorization: Bearer %s"\n' % sec)


def cmd_desired(path):
    d = load_json(path, 8 * 1024 * 1024)
    try:
        if d.get("schema") != "exp.desired/1":
            die("the desired state is not exp.desired/1")
        if d.get("decommission") is True:
            die("this host is marked for decommission in the manager; nothing to install")
        ag, rel = d["agent"], d["release"]
        av, art, rv = ag["version"], ag["artifact"], rel["version"]
        site = clean((d.get("site") or {}).get("name") or (d.get("site") or {}).get("id") or "")
        hid = d["host_id"]
    except (KeyError, TypeError, AttributeError):
        die("the desired state is missing the agent or release section")
    semver(av)
    semver(rv)
    if not (isinstance(art, str) and ART_RE.match(art)):
        die("the desired state names an invalid agent artifact id")
    if not (isinstance(hid, str) and HOST_RE.match(hid)):
        die("the desired state has an invalid host id")
    if rel.get("manifest_url") != "/api/agent/v1/releases/%s/manifest" % rv:
        die("the desired state points at an unexpected manifest URL")
    if rel.get("signature_url") != "/api/agent/v1/releases/%s/manifest.sig" % rv:
        die("the desired state points at an unexpected signature URL")
    print("\t".join((av, art, rv, site or "-", hid)))


def cmd_manifest_entry(path, release_ver, agent_ver, arch):
    # after the signature verified: which artifact is the agent, and may this version be installed?
    m = load_json(path, 1024 * 1024)
    try:
        if m["schema"] != "exp.manifest/1" or m["version"] != release_ver:
            die("the signed manifest is not for release %s" % release_ver)
        minv = m["min_agent_version"]
        name = "exp-agent-%s-noarch.tar.gz" % agent_ver
        hits = [a for a in m["artifacts"] if a.get("name") == name]
    except (KeyError, TypeError, AttributeError):
        die("the signed manifest is malformed")
    if semver(agent_ver) < semver(minv):
        die("agent %s is older than the release's min_agent_version %s; refusing" % (agent_ver, minv))
    if len(hits) != 1:
        die("%s is not in the signed manifest" % name)
    e = hits[0]
    if e.get("component") != "agent" or e.get("arch") not in ("noarch", arch):
        die("%s is not an agent artifact for this host" % name)
    if not (isinstance(e.get("sha256"), str) and SHA_RE.match(e["sha256"])):
        die("manifest entry for %s has no valid sha256" % name)
    size = e.get("size")
    if not (isinstance(size, int) and not isinstance(size, bool) and 0 < size <= MAX_TOTAL):
        die("manifest entry for %s has an invalid size" % name)
    print("%s\t%s\t%d" % (name, e["sha256"], size))


def cmd_unpack(tarball, parent, top, version):
    # Strict, self-contained safe unpack (the tarball is already signature+sha256 verified): regular
    # files and directories only; no absolute paths, "..", links, devices, FIFOs, setuid/setgid/sticky;
    # one top directory; bounded counts and sizes; files created O_EXCL|O_NOFOLLOW. Prints the staging dir.
    stage = tempfile.mkdtemp(dir=parent, prefix=".staging-")
    try:
        total, n, seen = 0, 0, set()
        with tarfile.open(tarball, "r:gz") as tf:
            for m in tf:
                n += 1
                total += max(0, m.size)
                if n > MAX_FILES or total > MAX_TOTAL:
                    die("the agent artifact is too large or has too many entries")
                name = m.name
                if not name or len(name) > MAX_NAME or "\x00" in name or "\\" in name or name.startswith("/"):
                    die("unsafe path in the agent artifact: %r" % clean(name))
                parts = [p for p in name.split("/") if p not in ("", ".")]
                if not parts or any(p == ".." or len(p) > 255 for p in parts) or parts[0] != top:
                    die("unsafe path in the agent artifact: %r" % clean(name))
                if not (m.isreg() or m.isdir()):
                    die("the agent artifact contains a link or special file: %r" % clean(name))
                if m.mode & 0o7000:
                    die("the agent artifact contains a setuid/setgid/sticky entry: %r" % clean(name))
                rel = "/".join(parts[1:])
                if rel in seen:
                    die("duplicate entry in the agent artifact: %r" % clean(name))
                seen.add(rel)
                dest = os.path.join(stage, *parts[1:]) if rel else stage
                if m.isdir():
                    os.makedirs(dest, mode=0o755, exist_ok=True)
                    os.chmod(dest, 0o755)
                    continue
                os.makedirs(os.path.dirname(dest), mode=0o755, exist_ok=True)
                src = tf.extractfile(m)
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as out:
                    left = m.size
                    while left > 0:
                        chunk = src.read(min(left, 1 << 20))
                        if not chunk:
                            die("truncated agent artifact")
                        out.write(chunk)
                        left -= len(chunk)
                    os.fchmod(out.fileno(), 0o755 if m.mode & 0o111 else 0o644)
        for must in ("bin/exp-agent", "lib/exp_agent/__init__.py", "lib/exp_agent/rollback_check.py", "VERSION", "systemd/exp-agent.service"):
            if not os.path.isfile(os.path.join(stage, must)):
                die("the agent artifact has no %s" % must)
        with open(os.path.join(stage, "VERSION"), encoding="utf-8") as fh:
            if fh.read().strip() != version:
                die("the agent artifact's VERSION is not %s" % version)
        os.chmod(stage, 0o755)
    except BaseException:
        import shutil
        shutil.rmtree(stage, ignore_errors=True)
        raise
    print(stage)


def cmd_units(srcdir, version):
    vals = {"@VERSION@": version, "@PREFIX@": "/opt/exp/agent/" + version, "@CONFIG@": CONFIG,
            "@CREDS@": "/etc/exp/agent/creds", "@STATE@": "/var/lib/exp/agent", "@RUN@": "/run/exp/agent"}
    out = {}
    for name in UNITS:
        p = os.path.join(srcdir, "systemd", name)
        with open(p, encoding="utf-8") as fh:
            text = fh.read(65536)
        for k, v in vals.items():
            text = text.replace(k, v)
        if re.search(r"@[A-Z]+@", text) or "\x00" in text:
            die("unit %s uses an unknown placeholder" % name)
        out[name] = text
    for name, text in out.items():
        fd, tmp = tempfile.mkstemp(dir="/etc/systemd/system", prefix=".exp-unit.")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, "/etc/systemd/system/" + name)


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    {"facts": cmd_facts, "write-config": cmd_write_config, "check-config": cmd_check_config,
     "authcfg": cmd_authcfg, "desired": cmd_desired, "manifest-entry": cmd_manifest_entry,
     "unpack": cmd_unpack, "units": cmd_units}[cmd](*args)


main()
PYEOF

py() { python3 -I -c "$PYHELPER" "$@"; }

# ----------------------------------------------------------------------------------------------
say() { printf '%s\n' "$*"; }
warn() { printf 'exp install: warning: %s\n' "$*" >&2; }
die() { printf 'exp install: ERROR: %s\n' "$*" >&2; exit 1; }

TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf -- "$TMP"; return 0; }

# Every curl: fail on HTTP errors, bounded time, HTTPS only (also after redirects: there are none), TLS >= 1.2.
# HTTPS_PROXY / https_proxy / NO_PROXY are honoured by curl itself.
CURL_COMMON=(--fail --silent --show-error --connect-timeout 15 --max-time 60 --proto =https --proto-redir =https --tlsv1.2 --max-redirs 0)

# authed_get <path> <outfile> <max bytes> [max seconds]   (the bearer secret reaches curl through a pipe)
authed_get() {
    py authcfg | curl "${CURL_COMMON[@]}" --max-filesize "$3" --max-time "${4:-60}" -K - -o "$2" "$MANAGER_URL$1"
}

preflight() {
    [ "$(id -u)" -eq 0 ] || die "must run as root: curl -fsSL $MANAGER_URL/install.sh | sudo bash -s -- <enrol token>"
    [ -r /etc/os-release ] || die "cannot read /etc/os-release; this installer supports Ubuntu 22.04 and 24.04"
    local os_id os_ver
    os_id="$(. /etc/os-release && printf '%s' "${ID:-}")"
    os_ver="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
    case "$os_id:$os_ver" in
        ubuntu:22.04 | ubuntu:24.04) ;;
        *) die "unsupported OS '$os_id $os_ver'; this installer supports Ubuntu 22.04 and 24.04" ;;
    esac
    case "$(uname -m)" in
        x86_64 | amd64) ARCH=amd64 ;;
        aarch64 | arm64) ARCH=arm64 ;;
        *) die "unsupported architecture '$(uname -m)'; supported: amd64, arm64" ;;
    esac
    [ "$(cat /proc/1/comm 2>/dev/null || true)" = systemd ] && [ -d /run/systemd/system ] \
        || die "systemd is not PID 1 on this host; the agent runs as a systemd service"
    command -v python3 >/dev/null 2>&1 || die "python3 is not installed (3.10 or newer is required)"
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
        || die "python3 $(python3 -c 'import platform; print(platform.python_version())') is too old; 3.10 or newer is required"
    command -v tar >/dev/null 2>&1 || die "tar is not installed"
    local missing=0 t
    for t in curl openssl; do command -v "$t" >/dev/null 2>&1 || missing=1; done
    [ -e /etc/ssl/certs/ca-certificates.crt ] || missing=1
    if [ "$missing" -eq 1 ]; then
        say "installing ca-certificates, curl and openssl (missing)..."
        DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null >/dev/null \
            && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ca-certificates curl openssl </dev/null >/dev/null \
            || die "could not install ca-certificates curl openssl with apt-get"
    fi
    command -v sha256sum >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1 || die "coreutils (sha256sum, base64) are required"
    curl "${CURL_COMMON[@]}" --max-time 20 -o /dev/null "$MANAGER_URL/healthz" 2>"$TMP/https.err" \
        || die "cannot reach $MANAGER_URL over HTTPS: $(head -c 300 "$TMP/https.err" | tr -d '\r')$([ -z "${HTTPS_PROXY:-${https_proxy:-}}" ] && printf '. Behind a proxy? Run: curl -fsSL ... | sudo -E bash -s -- <token> with HTTPS_PROXY set')"
    local synced
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    [ "$synced" = yes ] || warn "the system clock is not reported as synchronized (timedatectl); timestamps and token expiry depend on it"
}

main() {
    case "$MANAGER_URL$AGENT_VERSION$RELEASE_PUBKEY_PEM" in
        *"@@"*) die "this installer still contains unsubstituted placeholders; fetch it from your manager: curl -fsSL https://<manager>/install.sh" ;;
    esac
    [[ "$MANAGER_URL" =~ ^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$ ]] || die "the manager URL in this installer is not a plain https://host[:port] origin"
    [[ "$AGENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "the agent version in this installer is not a version number"
    case "$RELEASE_PUBKEY_PEM" in
        "-----BEGIN PUBLIC KEY-----"*"-----END PUBLIC KEY-----"*) ;;
        *) die "the release public key in this installer is not a PEM public key" ;;
    esac
    [ -z "$(printf '%s' "$RELEASE_PUBKEY_PEM" | tr -d 'A-Za-z0-9+/= \n-')" ] || die "the release public key in this installer has unexpected characters"

    TMP="$(mktemp -d /tmp/exp-install.XXXXXXXX)"
    trap cleanup EXIT
    chmod 700 "$TMP"

    local token="${1:-}" mode
    if [ -n "$token" ]; then
        mode=enrol
    elif [ -e /etc/exp/agent.json ]; then
        mode=repair
    else
        mode=enrol
        printf 'Enrol token (input hidden): ' >&2
        if ! { IFS= read -rs token </dev/tty; } 2>/dev/null; then
            printf '\n' >&2
            die "no enrol token given and no terminal to ask on; usage: curl -fsSL $MANAGER_URL/install.sh | sudo bash -s -- expe_..."
        fi
        printf '\n' >&2
    fi
    if [ "$mode" = enrol ]; then
        [[ "$token" =~ ^expe_[A-Za-z0-9_-]{43}$ ]] || die "that does not look like an enrol token (expe_ followed by 43 characters)"
    fi

    # 1. preflight: changes nothing (except installing curl/openssl/ca-certificates when missing)
    preflight

    # 2. enrol (or, for a repair, check the existing identity)
    local agent_id host_name=""
    if [ "$mode" = enrol ]; then
        local code="" rc=0 out
        if ! code="$(printf '%s' "$token" | py facts "$ARCH" \
            | curl "${CURL_COMMON[@]}" -H 'Content-Type: application/json' --data @- \
                -o "$TMP/enrol.json" -w '%{http_code}' "$MANAGER_URL/api/agent/v1/enrol" 2>"$TMP/enrol.err")"; then
            rc=1
        fi
        token=""
        if [ "$rc" -ne 0 ]; then
            case "$code" in
                401) die "the manager does not know this enrol token (copy it again from the manager's add-host page)" ;;
                410) die "this enrol token was already used or has expired; create a new one in the manager" ;;
                429) die "too many enrolment attempts from this address; wait a minute and retry" ;;
                *) die "enrolment failed (HTTP ${code:-none}): $(head -c 300 "$TMP/enrol.err" | tr -d '\r')" ;;
            esac
        fi
        out="$(py write-config "$MANAGER_URL" "$RELEASE_PUBKEY_PEM" <"$TMP/enrol.json")" || die "could not store the agent credentials"
        rm -f -- "$TMP/enrol.json"
        agent_id="${out%%$'\t'*}"
        host_name="${out#*$'\t'}"
    else
        agent_id="$(py check-config "$MANAGER_URL")"
        say "repairing the exp agent installation of $agent_id"
    fi

    # 3. fetch and verify the agent
    authed_get /api/agent/v1/desired "$TMP/desired.json" 8388608 || die "cannot fetch this host's desired state (credentials revoked? re-run with a new enrol token)"
    local ag_ver ag_art rel_ver site hid
    IFS=$'\t' read -r ag_ver ag_art rel_ver site hid <<<"$(py desired "$TMP/desired.json")" || die "the desired state is not usable"
    [ -n "$ag_ver" ] || die "the desired state is not usable"
    authed_get "/api/agent/v1/releases/$rel_ver/manifest" "$TMP/manifest.json" 1048576 || die "cannot fetch the release manifest"
    authed_get "/api/agent/v1/releases/$rel_ver/manifest.sig" "$TMP/manifest.sig.b64" 4096 || die "cannot fetch the release manifest signature"
    printf '%s\n' "$RELEASE_PUBKEY_PEM" >"$TMP/release-pub.pem"
    base64 -d <"$TMP/manifest.sig.b64" >"$TMP/manifest.sig" 2>/dev/null || die "the manifest signature is not valid base64"
    [ "$(stat -c %s "$TMP/manifest.sig")" -eq 64 ] || die "the manifest signature is not a 64-byte Ed25519 signature"
    openssl pkeyutl -verify -pubin -inkey "$TMP/release-pub.pem" -rawin -in "$TMP/manifest.json" -sigfile "$TMP/manifest.sig" >"$TMP/verify.out" 2>&1 \
        && grep -q 'Signature Verified Successfully' "$TMP/verify.out" \
        || die "release manifest signature verification FAILED; nothing was installed"
    local art_name art_sha art_size
    IFS=$'\t' read -r art_name art_sha art_size <<<"$(py manifest-entry "$TMP/manifest.json" "$rel_ver" "$ag_ver" "$ARCH")" || die "the signed manifest does not offer a usable agent"
    [ -n "$art_name" ] || die "the signed manifest does not offer a usable agent"
    authed_get "/api/agent/v1/artifacts/$ag_art" "$TMP/$art_name" "$art_size" 900 || die "cannot download the agent artifact"
    [ "$(stat -c %s "$TMP/$art_name")" -eq "$art_size" ] || die "the agent artifact size does not match the signed manifest; nothing was installed"
    printf '%s  %s\n' "$art_sha" "$TMP/$art_name" | sha256sum -c --quiet - >/dev/null 2>&1 \
        || die "the agent artifact's sha256 does not match the signed manifest; nothing was installed"

    # 4. install
    install -d -m 0755 /opt/exp /opt/exp/agent /etc/exp /var/lib/exp
    local stage dest="/opt/exp/agent/$ag_ver" prev=""
    stage="$(py unpack "$TMP/$art_name" /opt/exp/agent "exp-agent-$ag_ver" "$ag_ver")" || die "the agent artifact was refused; nothing was installed"
    [ -L /opt/exp/agent/current ] && prev="$(readlink /opt/exp/agent/current || true)"
    if [ -e "$dest" ] || [ -L "$dest" ]; then
        mv -T -- "$dest" "$stage.old" && mv -T -- "$stage" "$dest" && rm -rf -- "$stage.old"
    else
        mv -T -- "$stage" "$dest"
    fi
    if [ -n "$prev" ] && [ "$prev" != "$ag_ver" ] && [[ "$prev" =~ ^[0-9][0-9A-Za-z.-]*$ ]] && [ -d "/opt/exp/agent/$prev" ]; then
        ln -sfn -- "$prev" /opt/exp/agent/previous
    fi
    ln -sfn -- "$ag_ver" /opt/exp/agent/current.new && mv -T -- /opt/exp/agent/current.new /opt/exp/agent/current
    ln -sfn -- ../../../opt/exp/agent/current/bin/exp-agent /usr/local/bin/exp-agent.new && mv -T -- /usr/local/bin/exp-agent.new /usr/local/bin/exp-agent
    # the version-independent rollback checker lives outside the versioned trees (atomic, root 0755), so
    # exp-agent-rollback.service verifies and runs even before any previous agent exists
    install -m 0755 -o root -g root -- "$dest/lib/exp_agent/rollback_check.py" /opt/exp/agent/.rollback-check.new
    mv -T -- /opt/exp/agent/.rollback-check.new /opt/exp/agent/rollback-check
    py units "$dest" "$ag_ver"
    systemctl daemon-reload
    systemctl enable exp-agent.service exp-agent-rollback.timer >/dev/null 2>&1 || die "systemctl enable failed"
    systemctl start exp-agent-rollback.timer
    systemctl restart exp-agent.service || die "the agent service failed to start (journalctl -u exp-agent)"
    local i
    for i in $(seq 1 20); do
        systemctl is-active --quiet exp-agent.service && break
        sleep 1
    done
    systemctl is-active --quiet exp-agent.service || die "the agent service is not running (journalctl -u exp-agent)"

    # 5. report
    if [ -z "$host_name" ] || [ "$host_name" = "$agent_id" ]; then host_name="$(hostname)"; fi
    say "exp agent $ag_ver installed and running."
    say "  host:  $host_name ($hid)"
    say "  site:  $site"
    say "Components will be installed by the agent; watch progress in the manager: $MANAGER_URL"
}

main "$@" </dev/null
exit $?
