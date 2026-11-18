#!/usr/bin/env bash
# Publish a signed release (built by packaging/build.sh) to the manager's R2 bucket and D1 database from the
# operator's machine. The alternative to Settings -> Releases -> Import / Upload in the UI; same trust rules:
# nothing is stored unless the manifest signature verifies and every artifact matches its signed sha256 and size.
#
#   publish-release.sh --dist DIR [--version X.Y.Z] [--pubkey release-pub.pem] [--set-site SITE]
#                      [--config FILE] [--bucket exp-artifacts] [--local [--persist-to DIR]] [--dry-run]
#
#   --dist DIR       directory with exp-<v>-manifest.json, exp-<v>-manifest.json.sig (or exp-<v>-manifest.sig) and the
#                    artifacts named in the manifest (exp-<component>-<v>-<arch>.tar.gz)
#   --pubkey FILE    the Ed25519 PUBLIC key the manager was deployed with (default: <repo>/packaging/keys/release-pub.pem).
#                    When manager/.deploy/wrangler.generated.toml exists its RELEASE_PUBKEY_PEM must be the same key.
#   --set-site SITE  also set that site's release_version (bootstrap convenience; production rollouts use the
#                    canary flow in the UI, which also recompiles desired state)
#   --config FILE    wrangler config (default: manager/.deploy/wrangler.generated.toml, else manager/wrangler.toml)
#   --bucket NAME    R2 bucket (default: the bucket in the config)
#   --local          write to the LOCAL (miniflare) D1/R2 instead of the account (development and tests)
#   --dry-run        verify everything locally, print the wrangler commands and the SQL, change nothing
#
# Needs CLOUDFLARE_API_TOKEN (Workers R2 Storage:Edit, D1:Edit) and CLOUDFLARE_ACCOUNT_ID for the real thing.
# Idempotent: re-running with the same release rewrites the same objects and upserts the same rows.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$MANAGER/.." && pwd)"

DIST=""; VERSION=""; PUBKEY="$REPO_ROOT/packaging/keys/release-pub.pem"; SET_SITE=""; CONFIG=""; BUCKET=""
LOCAL=0; PERSIST=""; DRY=0

log() { printf 'publish-release: %s\n' "$*" >&2; }
die() { printf 'publish-release: ERROR: %s\n' "$*" >&2; exit 1; }
plan() { printf '[dry-run] %s\n' "$*" >&2; }
usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dist) DIST="${2:?--dist needs a directory}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --pubkey) PUBKEY="${2:?--pubkey needs a file}"; shift 2 ;;
    --set-site) SET_SITE="${2:?--set-site needs a site}"; shift 2 ;;
    --config) CONFIG="${2:?--config needs a file}"; shift 2 ;;
    --bucket) BUCKET="${2:?--bucket needs a name}"; shift 2 ;;
    --local) LOCAL=1; shift ;;
    --persist-to) PERSIST="${2:?--persist-to needs a directory}"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done

for c in jq openssl; do command -v "$c" >/dev/null 2>&1 || die "$c is required"; done
[ -n "$DIST" ] || { usage; die "--dist is required"; }
[ -d "$DIST" ] || die "no such directory: $DIST"
DIST="$(cd "$DIST" && pwd)"
[ -f "$PUBKEY" ] || die "release public key not found: $PUBKEY"
grep -q 'PRIVATE' "$PUBKEY" && die "$PUBKEY contains a private key; pass the PUBLIC key"
openssl pkey -pubin -in "$PUBKEY" -noout -text 2>/dev/null | grep -qi 'ED25519' || die "$PUBKEY is not an Ed25519 public key"
[ -z "$VERSION" ] || printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || die "--version is not a semantic version"
[ -z "$SET_SITE" ] || printf '%s' "$SET_SITE" | grep -Eq '^[a-z0-9][a-z0-9-]{0,63}$' || die "--set-site must be a site slug (lowercase letters, digits, hyphens)"
[ -z "$BUCKET" ] || printf '%s' "$BUCKET" | grep -Eq '^[a-z0-9][a-z0-9-]{2,62}$' || die "--bucket is not a valid R2 bucket name"

if [ -z "$CONFIG" ]; then
  if [ -f "$MANAGER/.deploy/wrangler.generated.toml" ]; then CONFIG="$MANAGER/.deploy/wrangler.generated.toml"; else CONFIG="$MANAGER/wrangler.toml"; fi
fi
[ -f "$CONFIG" ] || die "wrangler config not found: $CONFIG"
if [ -z "$BUCKET" ]; then
  BUCKET="$(sed -n 's/^bucket_name *= *"\([^"]*\)".*/\1/p' "$CONFIG" | head -n1)"
  [ -n "$BUCKET" ] || die "could not read bucket_name from $CONFIG; pass --bucket"
fi

# the key the manager (and every agent) trusts must be the key we verify with. Only a publish to the DEPLOYED manager is
# bound to that key: --local writes to a throwaway local D1/R2 whose pinned key is whatever the local dev instance is
# given (the end-to-end suite uses a throwaway release key while a stale .deploy/ may hold the production one).
if [ "$LOCAL" != 1 ] && [ -f "$MANAGER/.deploy/wrangler.generated.toml" ]; then
  deployed="$(sed -n 's/^RELEASE_PUBKEY_PEM *= *//p' "$MANAGER/.deploy/wrangler.generated.toml" | head -n1 | jq -r . 2>/dev/null || true)"
  if [ -n "$deployed" ]; then
    a="$(printf '%s' "$deployed" | tr -d '[:space:]')"; b="$(tr -d '[:space:]' < "$PUBKEY")"
    [ "$a" = "$b" ] || die "$PUBKEY differs from the RELEASE_PUBKEY_PEM the manager was deployed with (.deploy/wrangler.generated.toml); signatures would not verify in the field"
  fi
fi

# ---- locate manifest and signature ---------------------------------------------------------------------------
shopt -s nullglob
if [ -n "$VERSION" ]; then
  MANIFEST="$DIST/exp-$VERSION-manifest.json"
  [ -f "$MANIFEST" ] || die "no manifest $MANIFEST"
else
  ms=("$DIST"/exp-*-manifest.json)
  [ "${#ms[@]}" -eq 1 ] || die "found ${#ms[@]} manifests in $DIST; pass --version"
  MANIFEST="${ms[0]}"
fi
if [ -f "$MANIFEST.sig" ]; then SIGFILE="$MANIFEST.sig"; elif [ -f "${MANIFEST%.json}.sig" ]; then SIGFILE="${MANIFEST%.json}.sig"; else die "no signature next to $(basename "$MANIFEST") (expected $(basename "$MANIFEST").sig); unsigned builds cannot be published"; fi
[ "$(wc -c < "$MANIFEST")" -le 262144 ] || die "manifest is larger than 256 KiB"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/exp-publish.XXXXXX")"
chmod 700 "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT

# ---- 1. signature (Ed25519 over the exact manifest bytes) ---------------------------------------------------------
tr -d '[:space:]' < "$SIGFILE" | grep -Eq '^[A-Za-z0-9+/]{86}==$' || die "signature file is not base64 of a 64-byte Ed25519 signature"
tr -d '[:space:]' < "$SIGFILE" | openssl base64 -d -A > "$WORKDIR/sig.bin" 2>/dev/null || die "signature is not valid base64"
[ "$(wc -c < "$WORKDIR/sig.bin")" -eq 64 ] || die "signature is not 64 bytes"
openssl pkeyutl -verify -pubin -inkey "$PUBKEY" -rawin -in "$MANIFEST" -sigfile "$WORKDIR/sig.bin" >/dev/null 2>&1 \
  || die "the manifest signature does NOT verify against $PUBKEY. Nothing was uploaded."
SIG_B64="$(openssl base64 -A < "$WORKDIR/sig.bin")"
log "signature verifies against $PUBKEY"

# ---- 2. manifest content: strict validation BEFORE any value goes near SQL ------------------------------------------
SEMVER='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
jq -e . "$MANIFEST" >/dev/null 2>&1 || die "manifest is not valid JSON"
m() { jq -r "$1" "$MANIFEST"; }
[ "$(m '.schema // ""')" = "exp.manifest/1" ] || die "manifest schema is not exp.manifest/1"
V="$(m '.version // ""')";                  printf '%s' "$V" | grep -Eq "$SEMVER" && [ "${#V}" -le 64 ] || die "manifest version is not a semantic version"
MINAGENT="$(m '.min_agent_version // ""')"; printf '%s' "$MINAGENT" | grep -Eq "$SEMVER" && [ "${#MINAGENT}" -le 64 ] || die "manifest min_agent_version is not a semantic version"
CREATED="$(m '.created // ""')";            printf '%s' "$CREATED" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$' || die "manifest created is not an ISO-8601 UTC timestamp"
NOTES="$(m '.notes_url // ""')"
[ -z "$NOTES" ] || { printf '%s' "$NOTES" | grep -Eq '^https://[^[:space:]'"'"'"\\]{1,480}$' || die "manifest notes_url is not a plain https URL"; }
[ -z "$VERSION" ] || [ "$VERSION" = "$V" ] || die "--version $VERSION does not match the manifest version $V"
[ "$(basename "$MANIFEST")" = "exp-$V-manifest.json" ] || die "manifest file name does not match its version ($V)"
N="$(m '.artifacts | length')"
[ "$N" -ge 1 ] && [ "$N" -le 64 ] || die "manifest must list 1..64 artifacts"

NAME_RE="^exp-(agent|probe|collector|dashboard|runner|speedtest)-$(printf '%s' "$V" | sed 's/[.]/\\./g')-(amd64|arm64|noarch)\\.tar\\.gz$"
ART_TSV="$WORKDIR/artifacts.tsv"
jq -r '.artifacts[] | [.name, .component, .arch, .sha256, (.size | tostring)] | @tsv' "$MANIFEST" > "$ART_TSV" || die "manifest artifacts are malformed"
seen=""
while IFS=$'\t' read -r name comp arch sha size; do
  printf '%s' "$name" | grep -Eq "$NAME_RE" || die "artifact name '$name' is not exp-<component>-$V-<arch>.tar.gz"
  [ "$name" = "exp-$comp-$V-$arch.tar.gz" ] || die "artifact '$name' does not match its component/arch fields ($comp/$arch)"
  printf '%s' "$sha" | grep -Eq '^[0-9a-f]{64}$' || die "artifact $name: sha256 is not 64 lowercase hex characters"
  printf '%s' "$size" | grep -Eq '^[0-9]{1,9}$' || die "artifact $name: size is not an integer"
  [ "$size" -le 262144000 ] || die "artifact $name: larger than the 250 MiB limit"
  case " $seen " in *" $name "*) die "duplicate artifact $name" ;; esac
  seen="$seen $name"
  f="$DIST/$name"
  [ -f "$f" ] && [ ! -L "$f" ] || die "artifact file missing (or a symlink): $f"
  [ "$(wc -c < "$f")" -eq "$size" ] || die "artifact $name: size on disk differs from the signed manifest"
  got="$(openssl dgst -sha256 -r "$f" | cut -d' ' -f1)"
  [ "$got" = "$sha" ] || die "artifact $name: sha256 differs from the signed manifest ($got != $sha). Nothing was uploaded."
done < "$ART_TSV"
log "release $V: $N artifacts verified against the signed manifest"

# ---- 3. ids and keys (deterministic, so a re-run replaces instead of duplicating) ----------------------------------------
idpart() { printf '%s' "$1" | openssl dgst -sha256 -r | cut -c1-26 | tr 'a-f' 'A-F'; } # Crockford-safe: 0-9A-F
REL_ID="rel_$(idpart "release:$V")"
MANIFEST_KEY="releases/$V/$REL_ID/manifest.json"
SIG_KEY="$MANIFEST_KEY.sig"
NOW="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"

# ---- 4. SQL (every interpolated value matched a strict regex above; single quotes are impossible in them) -------------------------
SQL="$WORKDIR/publish.sql"
# defence in depth: every value below already matched a strict regex; a single quote (or newline) is refused outright
for v in V MINAGENT CREATED NOTES SIG_B64 REL_ID MANIFEST_KEY NOW SET_SITE; do
  case "${!v}" in *"'"*|*$'\n'*) die "refusing $v: it contains a quote or newline" ;; esac
done
q() { printf "'%s'" "$1"; }
{
  printf 'INSERT INTO releases (version, org_id, manifest_r2_key, signature, min_agent_version, verified_at, source, notes_url, rel_id, manifest_created, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ' \
    "$(q "$V")" "'default'" "$(q "$MANIFEST_KEY")" "$(q "$SIG_B64")" "$(q "$MINAGENT")" "$(q "$NOW")" "'upload'" "$([ -n "$NOTES" ] && q "$NOTES" || echo NULL)" "$(q "$REL_ID")" "$(q "$CREATED")" "$(q "$NOW")" "$(q "$NOW")"
  printf 'ON CONFLICT(version) DO UPDATE SET manifest_r2_key = excluded.manifest_r2_key, signature = excluded.signature, min_agent_version = excluded.min_agent_version, verified_at = excluded.verified_at, source = excluded.source, notes_url = excluded.notes_url, rel_id = excluded.rel_id, manifest_created = excluded.manifest_created, updated_at = excluded.updated_at;\n'
  while IFS=$'\t' read -r name comp arch sha size; do
    aid="art_$(idpart "artifact:$V:$name")"
    printf 'INSERT INTO artifacts (artifact_id, org_id, version, name, component, arch, sha256, size, r2_key, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ' \
      "$(q "$aid")" "'default'" "$(q "$V")" "$(q "$name")" "$(q "$comp")" "$(q "$arch")" "$(q "$sha")" "$size" "$(q "artifacts/$aid")" "$(q "$NOW")" "$(q "$NOW")"
    printf 'ON CONFLICT(artifact_id) DO UPDATE SET sha256 = excluded.sha256, size = excluded.size, r2_key = excluded.r2_key, updated_at = excluded.updated_at;\n'
  done < "$ART_TSV"
  printf 'INSERT OR REPLACE INTO audit (evt_id, org_id, ts, actor, action, resource, details_json, ip, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, NULL, %s, %s);\n' \
    "$(q "evt_$(idpart "publish:$V:$NOW")")" "'default'" "$(q "$NOW")" "'operator:publish-release.sh'" "'release.publish'" "$(q "release:$V")" "$(q "{\"artifacts\":$N,\"source\":\"upload\"}")" "$(q "$NOW")" "$(q "$NOW")"
  if [ -n "$SET_SITE" ]; then
    printf 'UPDATE sites SET release_version = %s, updated_at = %s WHERE site = %s;\n' "$(q "$V")" "$(q "$NOW")" "$(q "$SET_SITE")"
  fi
} > "$SQL"

# ---- 5. upload -----------------------------------------------------------------------------------------------------------------------
WR=(npx --no-install wrangler)
MODE=(--remote)
if [ "$LOCAL" = 1 ]; then MODE=(--local); [ -z "$PERSIST" ] || MODE+=(--persist-to "$PERSIST"); fi
[ "$LOCAL" = 1 ] || [ "$DRY" = 1 ] || { [ -n "${CLOUDFLARE_API_TOKEN:-}" ] && [ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]; } || die "set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID (or use --local / --dry-run)"

put() { # put KEY FILE CONTENT-TYPE
  if [ "$DRY" = 1 ]; then plan "wrangler r2 object put $BUCKET/$1 --file $2 --content-type $3 ${MODE[*]} -c $CONFIG"; return 0; fi
  (cd "$MANAGER" && "${WR[@]}" r2 object put "$BUCKET/$1" --file "$2" --content-type "$3" "${MODE[@]}" -c "$CONFIG" </dev/null >&2) || die "uploading $1 failed; the database was not changed"
}
while IFS=$'\t' read -r name comp arch sha size; do
  aid="art_$(idpart "artifact:$V:$name")"
  put "artifacts/$aid" "$DIST/$name" application/gzip
done < "$ART_TSV"
put "$MANIFEST_KEY" "$MANIFEST" application/json
put "$SIG_KEY" "$SIGFILE" text/plain

if [ "$DRY" = 1 ]; then
  plan "wrangler d1 execute DB ${MODE[*]} --file <generated.sql> --yes -c $CONFIG   (SQL below)"
  sed 's/^/[dry-run]   /' "$SQL" >&2
  log "dry run complete: verified locally, nothing uploaded"
  exit 0
fi
(cd "$MANAGER" && "${WR[@]}" d1 execute DB "${MODE[@]}" --file "$SQL" --yes -c "$CONFIG" </dev/null >&2) || die "writing the release rows failed (objects are uploaded; re-run to retry, it is idempotent)"
log "published $V ($N artifacts) to bucket $BUCKET${SET_SITE:+; site $SET_SITE now at $V}"
[ -n "$SET_SITE" ] || log "next: Settings -> Releases shows it; set it on a site with a canary host in the UI"
