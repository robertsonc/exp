#!/usr/bin/env bash
# exp-manager one-command deployment (docs/spec/05-manager.md section 12). Idempotent: re-running upgrades.
#
#   CLOUDFLARE_API_TOKEN=... ./deploy.sh --account-id <id> --domain exp-control.example.com \
#       --owner-email you@example.com --org-name "Example Org"
#
# Inputs (flag or environment; the API token is ENVIRONMENT ONLY, never a flag, never printed):
#   CLOUDFLARE_API_TOKEN   Account: Workers Scripts:Edit, D1:Edit, Workers R2 Storage:Edit, Access: Apps and Policies:Edit,
#                          Account Settings:Read.  Zone: Workers Routes:Edit, DNS:Edit, Zone:Read  (custom domain)
#   --account-id / CLOUDFLARE_ACCOUNT_ID
#   --domain / EXP_DOMAIN              custom domain for the Worker (default: <worker>.<subdomain>.workers.dev)
#   --owner-email / EXP_OWNER_EMAIL    the first owner; the only identity the Access policy admits initially
#   --org-name / ORG_NAME              organisation name shown in the UI
#   --release-pubkey FILE              Ed25519 release PUBLIC key PEM (default: <repo>/packaging/keys/release-pub.pem)
#   --worker-name (exp-manager)  --d1-name (exp-manager)  --r2-bucket (exp-artifacts)
#   --releases-repo owner/repo         optional: GitHub repo holding releases (release import)
#   --keep-workers-dev                 leave the *.workers.dev route enabled after the smoke tests
#   --dry-run                          print every API call and wrangler command; execute nothing, contact nothing
#
# Steps: (1) D1 + R2 (reuse or create), generated wrangler config; (2) migrations; (3) Cloudflare Access (app, owner
# policy, bypass apps) which yields the AUD tag; (4) UI build + wrangler deploy with all vars; (5) EXP_MASTER_KEY if
# absent (stdin, printed once); (6) smoke tests incl. enforcement by the Worker itself; (7) print the URL.
# It only ever touches the Worker, D1 database, R2 bucket and Access apps named here. No teardown on purpose.
#
# NOTE: written against the documented wrangler / Cloudflare API behaviour; the real-account path has not been exercised
# by the build that produced it (--dry-run and the offline rendering are tested). Read the output of the first run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
cd "$HERE"

CF_API="${CF_API_BASE:-https://api.cloudflare.com/client/v4}"
ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-}"
DOMAIN="${EXP_DOMAIN:-}"
OWNER_EMAIL="${EXP_OWNER_EMAIL:-}"
ORG_NAME="${ORG_NAME:-}"
PUBKEY_FILE=""
WORKER_NAME="exp-manager"
D1_NAME="exp-manager"
R2_BUCKET="exp-artifacts"
RELEASES_REPO="${RELEASES_REPO:-}"
KEEP_WORKERS_DEV=0
DRY=0
DEPLOY_DIR="$HERE/.deploy"
GEN="$DEPLOY_DIR/wrangler.generated.toml"

log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'deploy: WARNING: %s\n' "$*" >&2; }
die() { printf 'deploy: ERROR: %s\n' "$*" >&2; exit 1; }
plan() { printf '[dry-run] %s\n' "$*" >&2; }

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2; }

# ---- arguments -------------------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --account-id) ACCOUNT_ID="${2:?--account-id needs a value}"; shift 2 ;;
    --domain) DOMAIN="${2:?--domain needs a value}"; shift 2 ;;
    --owner-email) OWNER_EMAIL="${2:?--owner-email needs a value}"; shift 2 ;;
    --org-name) ORG_NAME="${2:?--org-name needs a value}"; shift 2 ;;
    --release-pubkey) PUBKEY_FILE="${2:?--release-pubkey needs a file}"; shift 2 ;;
    --worker-name) WORKER_NAME="${2:?--worker-name needs a value}"; shift 2 ;;
    --d1-name) D1_NAME="${2:?--d1-name needs a value}"; shift 2 ;;
    --r2-bucket) R2_BUCKET="${2:?--r2-bucket needs a value}"; shift 2 ;;
    --releases-repo) RELEASES_REPO="${2:?--releases-repo needs owner/repo}"; shift 2 ;;
    --keep-workers-dev) KEEP_WORKERS_DEV=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --api-token|--token|--cloudflare-api-token) die "the API token is read from CLOUDFLARE_API_TOKEN only (a flag would leak it into shell history and ps)" ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done

# ---- validation --------------------------------------------------------------------------------------
[ -n "${CLOUDFLARE_API_TOKEN:-}" ] || die "CLOUDFLARE_API_TOKEN is not set (environment only; see the header of deploy.sh for the permissions)"
printf '%s' "$CLOUDFLARE_API_TOKEN" | grep -Eq '^[A-Za-z0-9_.~+/=-]{8,256}$' || die "CLOUDFLARE_API_TOKEN has unexpected characters or length"
[ -n "$ACCOUNT_ID" ] || die "--account-id (or CLOUDFLARE_ACCOUNT_ID) is required"
printf '%s' "$ACCOUNT_ID" | grep -Eq '^[0-9a-f]{32}$' || die "account id must be 32 hex characters"
[ -n "$OWNER_EMAIL" ] || die "--owner-email (or EXP_OWNER_EMAIL) is required"
printf '%s' "$OWNER_EMAIL" | grep -Eq '^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$' || die "owner email does not look like an email address"
OWNER_EMAIL="$(printf '%s' "$OWNER_EMAIL" | tr 'A-Z' 'a-z')"
if [ -n "$DOMAIN" ]; then
  DOMAIN="$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z')"
  printf '%s' "$DOMAIN" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' || die "--domain must be a host name such as exp-control.example.com (no scheme, path or port)"
fi
for pair in "worker-name:$WORKER_NAME" "d1-name:$D1_NAME" "r2-bucket:$R2_BUCKET"; do
  printf '%s' "${pair#*:}" | grep -Eq '^[a-z0-9][a-z0-9-]{0,62}$' || die "--${pair%%:*} must be lowercase letters, digits and hyphens"
done
[ -z "$RELEASES_REPO" ] || printf '%s' "$RELEASES_REPO" | grep -Eq '^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$' || die "--releases-repo must look like owner/repo"
if [ -n "$ORG_NAME" ]; then
  [ "${#ORG_NAME}" -le 100 ] || die "--org-name is longer than 100 characters"
  printf '%s' "$ORG_NAME" | LC_ALL=C grep -q '[[:cntrl:]]' && die "--org-name contains control characters"
fi
[ -n "$PUBKEY_FILE" ] || PUBKEY_FILE="$REPO_ROOT/packaging/keys/release-pub.pem"

# ---- prerequisites -------------------------------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but was not found in PATH"; }
need node; need curl; need jq; need openssl; need npx
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 20 ] || die "Node 20 or newer is required (found $(node -v))"

[ -f "$PUBKEY_FILE" ] || die "release public key not found: $PUBKEY_FILE (pass --release-pubkey; generate a pair with packaging/gen-release-key.sh)"
grep -q 'PRIVATE' "$PUBKEY_FILE" && die "$PUBKEY_FILE contains a private key; deploy.sh only ever needs the PUBLIC key"
grep -q -- '-----BEGIN PUBLIC KEY-----' "$PUBKEY_FILE" || die "$PUBKEY_FILE is not a PEM public key"
openssl pkey -pubin -in "$PUBKEY_FILE" -noout -text 2>/dev/null | grep -qi 'ED25519' || die "$PUBKEY_FILE is not an Ed25519 public key"
RELEASE_PUBKEY_PEM="$(cat "$PUBKEY_FILE")"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/exp-deploy.XXXXXX")"
chmod 700 "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT

export CLOUDFLARE_ACCOUNT_ID="$ACCOUNT_ID" CLOUDFLARE_API_TOKEN WRANGLER_SEND_METRICS=false
WR=(npx --no-install wrangler)

# ---- helpers: Cloudflare REST API ------------------------------------------------------------------------
# cf METHOD PATH [JSON]  -> stdout: response body. Non-zero exit on transport error, HTTP error or success=false;
# the failing body is kept in $WORKDIR/last_error. The token travels on curl's stdin config, never in argv.
cf() {
  local method="$1" path="$2" body="${3:-}" out="$WORKDIR/resp"
  local args=(--silent --show-error --fail-with-body --max-time 30 --request "$method" --config - --output "$out")
  if [ -n "$body" ]; then
    printf '%s' "$body" > "$WORKDIR/req"
    args+=(--header 'Content-Type: application/json' --data "@$WORKDIR/req")
  fi
  local rc=0
  printf 'header = "Authorization: Bearer %s"\n' "$CLOUDFLARE_API_TOKEN" | curl "${args[@]}" "$CF_API$path" 2>"$WORKDIR/curl_err" || rc=$?
  if [ "$rc" -eq 0 ]; then
    if jq -e '.success == true' "$out" >/dev/null 2>&1; then cat "$out"; return 0; fi
    cp "$out" "$WORKDIR/last_error"
    return 22
  fi
  { cat "$out" 2>/dev/null; } > "$WORKDIR/last_error" || true
  [ -s "$WORKDIR/last_error" ] || cp "$WORKDIR/curl_err" "$WORKDIR/last_error"
  return "$rc"
}
cf_error() { # human-readable reason of the last failed cf call
  jq -r '[.errors[]? | "\(.code): \(.message)"] | join("; ") | select(length > 0)' "$WORKDIR/last_error" 2>/dev/null \
    || head -c 300 "$WORKDIR/last_error" 2>/dev/null || true
}
cf_must() { # cf or die with a message naming the call
  local what="$1"; shift
  local out
  if ! out="$(cf "$@")"; then
    local reason; reason="$(cf_error)"
    die "$what failed ($1 ${2%%\?*}): ${reason:-no detail from the API}. Check the token permissions (README)."
  fi
  printf '%s' "$out"
}
api_plan() { plan "API $1 /accounts/$ACCOUNT_ID${2}${3:+  $3}"; }

wr_run() { # wr_run <label> args... : run wrangler (or print it in dry-run)
  if [ "$DRY" = 1 ]; then plan "wrangler $*"; return 0; fi
  "${WR[@]}" "$@" </dev/null
}

# ---- resolve the public host -------------------------------------------------------------------------------
SUBDOMAIN=""
if [ "$DRY" = 1 ]; then
  api_plan GET "/workers/subdomain"
  SUBDOMAIN="<account-subdomain>"
else
  SUBDOMAIN="$(cf_must "reading the workers.dev subdomain" GET "/accounts/$ACCOUNT_ID/workers/subdomain" | jq -r '.result.subdomain // empty')"
fi
WORKERS_DEV_HOST="$WORKER_NAME.$SUBDOMAIN.workers.dev"
if [ -n "$DOMAIN" ]; then HOST="$DOMAIN"; else
  [ -n "$SUBDOMAIN" ] || die "this account has no workers.dev subdomain; pass --domain"
  HOST="$WORKERS_DEV_HOST"
  warn "no --domain: deploying to $HOST. A custom domain on a Cloudflare zone is strongly recommended (Access, enforcement test)."
fi
BASE="https://$HOST"
log "plan: worker=$WORKER_NAME host=$HOST owner=$OWNER_EMAIL d1=$D1_NAME r2=$R2_BUCKET dry_run=$DRY"

# ---- 1. D1 database and R2 bucket ---------------------------------------------------------------------------
d1_id() {
  cf_must "listing D1 databases" GET "/accounts/$ACCOUNT_ID/d1/database?name=$D1_NAME&per_page=100" \
    | jq -r --arg n "$D1_NAME" '[.result[]? | select(.name == $n)][0].uuid // empty'
}
r2_exists() {
  local resp
  resp="$(cf_must "listing R2 buckets" GET "/accounts/$ACCOUNT_ID/r2/buckets?per_page=1000")" || exit 1
  printf '%s' "$resp" | jq -e --arg n "$R2_BUCKET" '[.result.buckets[]? | select(.name == $n)] | length > 0' >/dev/null
}
log "1/7 D1 database and R2 bucket"
if [ "$DRY" = 1 ]; then
  api_plan GET "/d1/database?name=$D1_NAME"
  plan "wrangler d1 create $D1_NAME   (only if it does not exist)"
  api_plan GET "/r2/buckets"
  plan "wrangler r2 bucket create $R2_BUCKET   (only if it does not exist)"
  D1_ID="00000000-0000-0000-0000-000000000000"
else
  D1_ID="$(d1_id)"
  if [ -z "$D1_ID" ]; then
    log "creating D1 database $D1_NAME"
    "${WR[@]}" d1 create "$D1_NAME" </dev/null >&2 || die "wrangler d1 create $D1_NAME failed"
    D1_ID="$(d1_id)"
  else
    log "reusing D1 database $D1_NAME ($D1_ID)"
  fi
  printf '%s' "$D1_ID" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || die "could not determine the D1 database id for $D1_NAME"
  if r2_exists; then log "reusing R2 bucket $R2_BUCKET"; else
    log "creating R2 bucket $R2_BUCKET"
    "${WR[@]}" r2 bucket create "$R2_BUCKET" </dev/null >&2 || die "wrangler r2 bucket create $R2_BUCKET failed (is R2 enabled for the account?)"
  fi
fi

# ---- generated wrangler config (the committed wrangler.toml is never modified) ----------------------------------
tq() { jq -Rn --arg v "$1" '$v'; } # a JSON string is a valid TOML basic string

# render_config <ACCESS_AUD> <ACCESS_TEAM_DOMAIN>
render_config() {
  local aud="$1" team="$2"
  mkdir -p "$DEPLOY_DIR"; chmod 700 "$DEPLOY_DIR"
  local routes=""
  if [ -n "$DOMAIN" ]; then routes="[[routes]]
pattern = $(tq "$DOMAIN")
custom_domain = true
"; fi
  V_AUD="$(tq "$aud")" V_TEAM="$(tq "$team")" V_OWNER="$(tq "$OWNER_EMAIL")" V_ORG="$(tq "$ORG_NAME")" \
  V_PEM="$(tq "$RELEASE_PUBKEY_PEM")" V_REPO="$(tq "$RELEASES_REPO")" V_URL="$(tq "$BASE")" \
  V_NAME="$(tq "$WORKER_NAME")" V_DB="$(tq "$D1_NAME")" V_DBID="$(tq "$D1_ID")" V_BUCKET="$(tq "$R2_BUCKET")" V_ROUTES="$routes" \
  awk '
    function reroot(line,   k, v) { # key = "path"  ->  key = "../path"
      k = line; sub(/ *=.*/, "", k); v = line; sub(/^[^=]*= *"/, "", v); sub(/".*$/, "", v); sub(/^\.\//, "", v)
      return k " = \"../" v "\""
    }
    BEGIN { section = ""; extras = 0 }
    /^\[/ {
      if (!extras) { print "workers_dev = true  # enabled for the post-deploy smoke tests; deploy.sh disables it afterwards"; print ""; extras = 1 }
      section = $0
      if (section == "[vars]") { skip = 1; next } else { skip = 0 }
      print; next
    }
    skip { next }
    section == "" && /^name *=/ { print "name = " ENVIRON["V_NAME"]; next }
    section == "" && /^main *=/ { print reroot($0); next }
    section == "[[d1_databases]]" && /^database_name *=/ { print "database_name = " ENVIRON["V_DB"]; next }
    section == "[[d1_databases]]" && /^database_id *=/ { print "database_id = " ENVIRON["V_DBID"]; next }
    section == "[[d1_databases]]" && /^migrations_dir *=/ { print reroot($0); next }
    section == "[[r2_buckets]]" && /^bucket_name *=/ { print "bucket_name = " ENVIRON["V_BUCKET"]; next }
    section == "[assets]" && /^directory *=/ { print reroot($0); next }
    { print }
    END {
      print ""
      print "[vars]"
      print "ACCESS_TEAM_DOMAIN = " ENVIRON["V_TEAM"]
      print "ACCESS_AUD = " ENVIRON["V_AUD"]
      print "EXP_OWNER_EMAIL = " ENVIRON["V_OWNER"]
      print "ORG_NAME = " ENVIRON["V_ORG"]
      print "RELEASE_PUBKEY_PEM = " ENVIRON["V_PEM"]
      print "RELEASES_REPO = " ENVIRON["V_REPO"]
      print "MANAGER_URL = " ENVIRON["V_URL"]
      print ""
      if (ENVIRON["V_ROUTES"] != "") print ENVIRON["V_ROUTES"]
    }
  ' "$HERE/wrangler.toml" > "$GEN.tmp"
  mv "$GEN.tmp" "$GEN"
  log "rendered $GEN (the committed wrangler.toml is untouched)"
}

# ---- 2. migrations --------------------------------------------------------------------------------------------------
log "2/7 database migrations (forward-only)"
render_config "" ""  # bindings are enough for migrations; vars are filled in below
wr_run d1 migrations apply DB --remote -c "$GEN"

# ---- 3. Cloudflare Access --------------------------------------------------------------------------------------------
log "3/7 Cloudflare Access application, owner policy and bypass applications"
ACCESS_AUD=""
TEAM_DOMAIN=""
if [ "$DRY" = 1 ]; then
  api_plan GET "/access/organizations"
  api_plan GET "/access/apps?per_page=100"
  api_plan POST "/access/apps" "{\"name\":\"$WORKER_NAME\",\"domain\":\"$HOST\",\"type\":\"self_hosted\",\"session_duration\":\"24h\"}   (or PUT when an app for $HOST exists)"
  api_plan POST "/access/apps/<app-id>/policies" "{\"name\":\"$WORKER_NAME owner\",\"decision\":\"allow\",\"include\":[{\"email\":{\"email\":\"$OWNER_EMAIL\"}}],\"precedence\":1}"
  for p in /api/agent /install.sh /healthz; do
    api_plan POST "/access/apps" "{\"name\":\"$WORKER_NAME bypass $p\",\"domain\":\"$HOST$p\",\"type\":\"self_hosted\",\"session_duration\":\"24h\"}"
    api_plan POST "/access/apps/<app-id>/policies" "{\"name\":\"bypass everyone\",\"decision\":\"bypass\",\"include\":[{\"everyone\":{}}],\"precedence\":1}"
  done
  ACCESS_AUD="<access-aud-tag>"
  TEAM_DOMAIN="<team>.cloudflareaccess.com"
else
  TEAM_DOMAIN="$(cf_must "discovering the Access team domain" GET "/accounts/$ACCOUNT_ID/access/organizations" | jq -r '.result.auth_domain // empty')"
  [ -n "$TEAM_DOMAIN" ] || die "Cloudflare Access (Zero Trust) is not set up for this account: no team domain. Create the Zero Trust organisation in the dashboard once, then re-run."
  log "Access team domain: $TEAM_DOMAIN"

  APPS_JSON="$WORKDIR/apps.json"
  page=1
  printf '[]' > "$APPS_JSON"
  while :; do
    resp="$(cf_must "listing Access applications" GET "/accounts/$ACCOUNT_ID/access/apps?per_page=100&page=$page")"
    jq -s '.[0] + (.[1].result // [])' "$APPS_JSON" <(printf '%s' "$resp") > "$APPS_JSON.new" && mv "$APPS_JSON.new" "$APPS_JSON"
    [ "$(printf '%s' "$resp" | jq '.result | length')" -ge 100 ] || break
    page=$((page + 1)); [ "$page" -le 50 ] || die "too many Access applications to list"
  done

  # app_upsert NAME DOMAIN -> sets APP_ID and APP_AUD. Looks up by domain, then by name; existing settings are kept.
  app_upsert() {
    local name="$1" domain="$2" found payload body method path resp
    payload="$(jq -cn --arg n "$name" --arg d "$domain" '{name: $n, domain: $d, type: "self_hosted", session_duration: "24h", app_launcher_visible: false}')"
    found="$(jq -c --arg n "$name" --arg d "$domain" '([.[] | select(.domain == $d)][0]) // ([.[] | select(.name == $n)][0]) // empty' "$APPS_JSON")"
    if [ -n "$found" ]; then
      method=PUT; path="/accounts/$ACCOUNT_ID/access/apps/$(printf '%s' "$found" | jq -r '.id')"
      body="$(printf '%s' "$found" | jq -c --argjson new "$payload" 'del(.id, .uid, .aud, .created_at, .updated_at) + $new')"
      log "updating Access application '$name' ($domain)"
    else
      method=POST; path="/accounts/$ACCOUNT_ID/access/apps"; body="$payload"
      log "creating Access application '$name' ($domain)"
    fi
    resp="$(cf_must "saving the Access application '$name'" "$method" "$path" "$body")"
    APP_ID="$(printf '%s' "$resp" | jq -r '.result.id // empty')"
    APP_AUD="$(printf '%s' "$resp" | jq -r '.result.aud // empty')"
    [ -n "$APP_ID" ] && [ -n "$APP_AUD" ] || die "Access did not return an id and AUD tag for '$name'"
  }
  # policy_upsert APP_ID NAME DECISION INCLUDE_JSON [keep-existing-includes]
  policy_upsert() {
    local app="$1" pname="$2" decision="$3" include="$4" merge="${5:-}" list found pid body method path
    list="$(cf_must "listing policies of '$pname'" GET "/accounts/$ACCOUNT_ID/access/apps/$app/policies")"
    found="$(printf '%s' "$list" | jq -c --arg n "$pname" '[.result[]? | select(.name == $n)][0] // empty')"
    if [ -n "$found" ]; then
      pid="$(printf '%s' "$found" | jq -r '.id')"
      if [ -n "$merge" ]; then # never drop identities an admin added by hand: union of existing and wanted
        include="$(jq -cn --argjson have "$(printf '%s' "$found" | jq -c '.include // []')" --argjson want "$include" '$have + [$want[] | select(. as $w | $have | index($w) | not)]')"
      fi
      body="$(jq -cn --arg n "$pname" --arg d "$decision" --argjson i "$include" '{name: $n, decision: $d, include: $i, precedence: 1}')"
      method=PUT; path="/accounts/$ACCOUNT_ID/access/apps/$app/policies/$pid"
    else
      body="$(jq -cn --arg n "$pname" --arg d "$decision" --argjson i "$include" '{name: $n, decision: $d, include: $i, precedence: 1}')"
      method=POST; path="/accounts/$ACCOUNT_ID/access/apps/$app/policies"
    fi
    cf_must "saving policy '$pname'" "$method" "$path" "$body" >/dev/null
  }

  app_upsert "$WORKER_NAME" "$HOST"
  ACCESS_AUD="$APP_AUD"
  policy_upsert "$APP_ID" "$WORKER_NAME owner" allow "$(jq -cn --arg e "$OWNER_EMAIL" '[{email: {email: $e}}]')" merge
  for p in /api/agent /install.sh /healthz; do
    app_upsert "$WORKER_NAME bypass $p" "$HOST$p"
    policy_upsert "$APP_ID" "bypass everyone" bypass '[{"everyone":{}}]'
  done
fi

# guard: the custom domain must not already be served by a DIFFERENT Worker (we never take over other services)
if [ -n "$DOMAIN" ]; then
  if [ "$DRY" = 1 ]; then api_plan GET "/workers/domains?hostname=$HOST   (refuse if another Worker serves it)"; else
    other="$(cf_must "checking existing Workers custom domains" GET "/accounts/$ACCOUNT_ID/workers/domains?hostname=$HOST" | jq -r --arg w "$WORKER_NAME" --arg h "$HOST" '[.result[]? | select(.hostname == $h and .service != $w)][0].service // empty')"
    [ -z "$other" ] || die "$HOST is already attached to the Worker '$other'; refusing to take it over. Choose another --domain."
  fi
fi

# ---- 4. build and deploy ---------------------------------------------------------------------------------------------
log "4/7 build and deploy"
render_config "$ACCESS_AUD" "$TEAM_DOMAIN"
if [ "$DRY" = 1 ]; then
  plan "(cd $HERE && npm ci)   (only when node_modules is missing)"
  [ ! -f "$HERE/ui/package.json" ] || plan "(cd $HERE/ui && npm ci && npm run build)"
  plan "node scripts/prepare.mjs   (bundles agent/install/install.sh)"
  plan "wrangler deploy -c $GEN"
else
  [ -d "$HERE/node_modules" ] || { log "installing dependencies"; npm ci --no-audit --no-fund; }
  if [ -f "$HERE/ui/package.json" ]; then
    log "building the admin UI"
    (cd "$HERE/ui" && npm ci --no-audit --no-fund && npm run build) || die "the UI build failed"
  fi
  [ -d "$HERE/ui/dist" ] || die "ui/dist does not exist: the admin UI must be built (manager/ui) before deploying"
  node "$HERE/scripts/prepare.mjs" >&2
  "${WR[@]}" deploy -c "$GEN" </dev/null >&2 || die "wrangler deploy failed"
fi

# ---- 5. EXP_MASTER_KEY ------------------------------------------------------------------------------------------------
log "5/7 EXP_MASTER_KEY"
key_present() { # 0 = secret exists, 1 = definitely absent (or the Worker does not exist yet); anything unclear dies
  local out
  if out="$(cf GET "/accounts/$ACCOUNT_ID/workers/scripts/$WORKER_NAME/secrets")"; then
    printf '%s' "$out" | jq -e '[.result[]? | select(.name == "EXP_MASTER_KEY")] | length > 0' >/dev/null
    return
  fi
  grep -q '"code": *10007\|"code":10007' "$WORKDIR/last_error" && return 1
  die "could not tell whether EXP_MASTER_KEY already exists ($(cf_error)); NOT generating a new one, because replacing it would make stored secrets unrecoverable"
}
if [ "$DRY" = 1 ]; then
  api_plan GET "/workers/scripts/$WORKER_NAME/secrets   (EXP_MASTER_KEY present? never regenerated if it is)"
  plan "KEY=\$(openssl rand -base64 32)   (only if absent)"
  plan "printf '%s' \"\$KEY\" | wrangler secret put EXP_MASTER_KEY -c $GEN   (stdin, never argv)"
  plan "print the one-time 'BACK THIS UP OFFLINE' warning with the key to the terminal only"
else
  if key_present; then
    log "EXP_MASTER_KEY already set: left untouched"
  else
    MASTER_KEY="$(openssl rand -base64 32)"
    printf '%s' "$MASTER_KEY" | "${WR[@]}" secret put EXP_MASTER_KEY -c "$GEN" >&2 || die "storing EXP_MASTER_KEY failed; nothing was printed"
    TTY=/dev/stderr
    { : >/dev/tty; } 2>/dev/null && TTY=/dev/tty
    {
      echo
      echo "################################################################################"
      echo "#  EXP_MASTER_KEY WAS GENERATED. BACK THIS UP OFFLINE NOW. IT IS SHOWN ONCE.   #"
      echo "################################################################################"
      echo
      echo "    $MASTER_KEY"
      echo
      echo "  It encrypts every stored secret (ingest tokens, dashboard tokens, webhook URLs)."
      echo "  Without it those secrets cannot be recovered after a restore. It is not written"
      echo "  to any file by this script. Store it in a password manager or a safe, then clear"
      echo "  this terminal. Re-running deploy.sh never replaces it."
      echo
    } > "$TTY"
    [ "$TTY" != /dev/stderr ] || warn "no controlling terminal: the key above went to stderr; make sure stderr is not being logged"
    unset MASTER_KEY
  fi
fi

# ---- 6. smoke tests ------------------------------------------------------------------------------------------------------
log "6/7 smoke tests"
http() { # http OUTFILE CURL-ARGS... -> prints the status code (000 on transport failure)
  local out="$1"; shift
  curl --silent --show-error --max-time 20 --output "$out" --write-out '%{http_code}' "$@" 2>/dev/null || true
}
retry_http() { # retry_http OUTFILE EXPECT URL [curl args]: up to ~2 min for DNS / certificates to propagate
  local out="$1" want="$2" url="$3" i code=000; shift 3
  for i in $(seq 1 24); do
    code="$(http "$out" "$@" "$url")"
    [ "$code" = "$want" ] && { printf '%s' "$code"; return 0; }
    sleep 5
  done
  printf '%s' "$code"; return 1
}
if [ "$DRY" = 1 ]; then
  plan "GET $BASE/healthz == 200 'ok'"
  plan "GET https://$WORKERS_DEV_HOST/api/admin/v1/me (no JWT) == 401 from the Worker (direct, bypassing Access)"
  plan "GET https://$WORKERS_DEV_HOST/api/admin/v1/me (Cf-Access-Jwt-Assertion: forged) == 401 from the Worker"
  plan "GET $BASE/install.sh == 200 and a shell script"
  plan "POST $BASE/api/agent/v1/enrol (bogus token) == 401"
  if [ -n "$DOMAIN" ] && [ "$KEEP_WORKERS_DEV" = 0 ]; then api_plan POST "/workers/scripts/$WORKER_NAME/subdomain" '{"enabled":false,"previews_enabled":false}'; fi
else
  body="$WORKDIR/body"
  code="$(retry_http "$body" 200 "$BASE/healthz")" || die "GET $BASE/healthz answered $code (expected 200 ok). DNS or the certificate may still be propagating: re-run deploy.sh in a few minutes."
  [ "$(cat "$body")" = "ok" ] || die "GET /healthz returned an unexpected body"
  log "ok: $BASE/healthz"

  # enforcement by the Worker itself: a DIRECT request (workers.dev, which does not pass through Access)
  if [ -n "$DOMAIN" ]; then DIRECT="https://$WORKERS_DEV_HOST"; else DIRECT="$BASE"; fi
  code="$(retry_http "$body" 401 "$DIRECT/api/admin/v1/me")" || {
    if [ -z "$DOMAIN" ]; then warn "direct admin check answered $code: Access in front of workers.dev intercepts before the Worker, so Worker-side enforcement could not be observed (use --domain to test it)"; code=skip; else
      die "direct GET $DIRECT/api/admin/v1/me answered $code, expected 401 from the Worker: the Worker must refuse admin requests that carry no Access JWT"; fi; }
  if [ "$code" = 401 ]; then
    grep -q 'unauthenticated' "$body" || die "the 401 did not come from the exp Worker (body: $(head -c 120 "$body"))"
    code="$(http "$body" -H 'Cf-Access-Jwt-Assertion: eyJhbGciOiJSUzI1NiIsImtpZCI6ImZvcmdlZCJ9.eyJlbWFpbCI6ImF0dGFja2VyQGV4YW1wbGUuY29tIn0.forged' "$DIRECT/api/admin/v1/me")"
    [ "$code" = 401 ] && grep -q 'unauthenticated' "$body" || die "a forged Cf-Access-Jwt-Assertion was NOT refused with 401 by the Worker (got $code)"
    log "ok: the Worker refuses admin requests without a JWT and with a forged JWT (401)"
  fi

  code="$(http "$body" "$BASE/install.sh")"
  if [ "$code" = 503 ] && grep -q 'no valid release version is imported yet' "$body"; then
    # Expected on a first deploy: the installer is only served once a signed release is published
    # (scripts/publish-release.sh), because install.sh pins the agent version. Not a failure.
    warn "GET $BASE/install.sh answered 503 'no release imported yet': publish a release (scripts/publish-release.sh), then the installer is served"
  else
    [ "$code" = 200 ] && head -c 2 "$body" | grep -q '^#!' && head -n1 "$body" | grep -Eq 'sh' || die "GET $BASE/install.sh answered $code or is not a shell script (is RELEASE_PUBKEY_PEM valid?)"
    log "ok: $BASE/install.sh"
  fi

  bogus="expe_$(printf 'A%.0s' $(seq 1 43))"
  code="$(http "$body" --request POST --header 'Content-Type: application/json' --data "{\"token\":\"$bogus\",\"facts\":{\"hostname\":\"smoke-test\",\"arch\":\"amd64\"}}" "$BASE/api/agent/v1/enrol")"
  [ "$code" = 401 ] || die "POST /api/agent/v1/enrol with a bogus token answered $code, expected 401 (body: $(head -c 160 "$body")). If it is 3xx/403 the Access bypass for /api/agent did not apply."
  log "ok: enrol refuses a bogus token (401)"

  if [ -n "$DOMAIN" ] && [ "$KEEP_WORKERS_DEV" = 0 ]; then
    log "disabling the workers.dev route (Access does not protect it)"
    cf_must "disabling the workers.dev route" POST "/accounts/$ACCOUNT_ID/workers/scripts/$WORKER_NAME/subdomain" '{"enabled":false,"previews_enabled":false}' >/dev/null
  elif [ -n "$DOMAIN" ]; then
    warn "--keep-workers-dev: $WORKERS_DEV_HOST stays reachable outside Access (the Worker still enforces JWTs itself)"
  fi
fi

# ---- 7. done ------------------------------------------------------------------------------------------------------------------
log "7/7 done"
if [ "$DRY" = 1 ]; then
  printf 'dry-run complete: nothing was executed or contacted. Generated config: %s\n' "$GEN"
else
  printf 'exp-manager is live: %s\nsign in as %s (the first sign-in creates the owner)\n' "$BASE" "$OWNER_EMAIL"
fi
