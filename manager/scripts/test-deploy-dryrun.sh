#!/usr/bin/env bash
# Shell tests (no bats) for deploy.sh, publish-release.sh and backup.sh. NO NETWORK: the deploy/publish dry runs must
# not call curl (a shim that records and fails is first in PATH), and the local-publish test uses wrangler's local
# D1/R2 in a temp directory. Run: npm run test:deploy   (or bash scripts/test-deploy-dryrun.sh)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER="$(cd "$HERE/.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/exp-deploytest.XXXXXX")"
trap 'rm -rf "$T"' EXIT
FAILS=0; PASSES=0

ok() { PASSES=$((PASSES + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAILS=$((FAILS + 1)); printf '  FAIL %s\n' "$1" >&2; [ -z "${2:-}" ] || printf '%s\n' "$2" | head -n 12 | sed 's/^/       | /' >&2; }
has() { printf '%s' "$2" | grep -Fq -- "$1"; }
assert_has() { if has "$1" "$2"; then ok "$3"; else bad "$3 (missing: $1)" "$2"; fi; }
assert_lacks() { if has "$1" "$2"; then bad "$3 (found: $1)" "$2"; else ok "$3"; fi; }
assert_fails() { # assert_fails DESC EXPECTED-MESSAGE-FRAGMENT cmd...
  local desc="$1" frag="$2"; shift 2
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ] && has "$frag" "$out"; then ok "$desc"; else bad "$desc (rc=$rc, wanted: $frag)" "$out"; fi
}

for c in jq openssl; do command -v "$c" >/dev/null || { echo "test-deploy-dryrun: $c is required" >&2; exit 2; }; done

# ---- fixtures ---------------------------------------------------------------------------------------------------------
FAKE_TOKEN="faketokenAAAA1111BBBB2222"
ACCT="0123456789abcdef0123456789abcdef"
openssl genpkey -algorithm ed25519 -out "$T/priv.pem" 2>/dev/null
openssl pkey -in "$T/priv.pem" -pubout -out "$T/pub.pem"
openssl genpkey -algorithm ed25519 -out "$T/other-priv.pem" 2>/dev/null
openssl pkey -in "$T/other-priv.pem" -pubout -out "$T/other-pub.pem"

# curl shim: any call is a test failure (dry runs and verification must be offline)
mkdir -p "$T/bin"
cat > "$T/bin/curl" <<EOF
#!/bin/sh
echo "curl \$*" >> "$T/curl-calls"
exit 99
EOF
chmod +x "$T/bin/curl"

mkrelease() { # mkrelease DIR VERSION [notes_url]  -> signed release dir with two small artifacts
  local d="$1" v="$2" notes="${3:-}" a
  mkdir -p "$d"
  local arts="[]"
  for spec in "agent noarch" "probe noarch"; do
    set -- $spec
    a="exp-$1-$v-$2.tar.gz"
    head -c 3000 /dev/urandom > "$d/$a"
    arts="$(jq -c --arg n "$a" --arg c "$1" --arg ar "$2" --arg s "$(openssl dgst -sha256 -r "$d/$a" | cut -d' ' -f1)" --argjson z "$(wc -c < "$d/$a")" '. + [{name: $n, component: $c, arch: $ar, sha256: $s, size: $z}]' <<<"$arts")"
  done
  jq -n --arg v "$v" --argjson a "$arts" --arg notes "$notes" '{schema: "exp.manifest/1", version: $v, created: "2026-11-18T10:00:00Z", min_agent_version: "0.1.0", artifacts: $a} + (if $notes == "" then {} else {notes_url: $notes} end)' > "$d/exp-$v-manifest.json"
  sign "$d/exp-$v-manifest.json" "$T/priv.pem"
}
sign() { # sign MANIFEST PRIVKEY -> MANIFEST.sig (base64, no newline)
  openssl pkeyutl -sign -inkey "$2" -rawin -in "$1" -out "$T/sig.bin" 2>/dev/null
  openssl base64 -A < "$T/sig.bin" > "$1.sig"
}

DEPLOY=(env PATH="$T/bin:$PATH" CLOUDFLARE_API_TOKEN="$FAKE_TOKEN" HTTPS_PROXY=http://127.0.0.1:9 "$MANAGER/deploy.sh")
base_args=(--dry-run --account-id "$ACCT" --domain exp-control.example.com --owner-email Owner@Example.com --org-name "Example Org" --release-pubkey "$T/pub.pem")

# ---- deploy.sh --dry-run ---------------------------------------------------------------------------------------------------
echo "deploy.sh --dry-run"
sum_before="$(openssl dgst -sha256 -r "$MANAGER/wrangler.toml")"
out="$("${DEPLOY[@]}" "${base_args[@]}" 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "exits 0" || bad "exits 0 (rc=$rc)" "$out"
assert_has "[dry-run] wrangler d1 migrations apply DB --remote" "$out" "plans the remote migrations"
assert_has "wrangler d1 create exp-manager" "$out" "plans creating the D1 database when absent"
assert_has "wrangler r2 bucket create exp-artifacts" "$out" "plans creating the R2 bucket when absent"
assert_has "API GET /accounts/$ACCT/access/organizations" "$out" "discovers the Access team domain"
assert_has '"domain":"exp-control.example.com","type":"self_hosted","session_duration":"24h"' "$out" "plans the self-hosted Access app with a 24h session"
assert_has '"decision":"allow","include":[{"email":{"email":"owner@example.com"}}]' "$out" "plans the owner allow policy (email lower-cased)"
for p in /api/agent /install.sh /healthz; do
  assert_has "\"domain\":\"exp-control.example.com$p\"" "$out" "plans a bypass application for $p"
done
assert_has '"decision":"bypass","include":[{"everyone":{}}]' "$out" "bypass policies include everyone"
assert_has "wrangler deploy -c" "$out" "plans wrangler deploy with the generated config"
assert_has "printf '%s' \"\$KEY\" | wrangler secret put EXP_MASTER_KEY" "$out" "master key goes through stdin, not argv"
assert_has "never regenerated if it is" "$out" "master key is checked before generating"
assert_has "GET https://exp-control.example.com/healthz == 200" "$out" "plans the healthz smoke test"
assert_has "(no JWT) == 401 from the Worker" "$out" "plans the direct no-JWT enforcement test"
assert_has "(Cf-Access-Jwt-Assertion: forged) == 401" "$out" "plans the forged-JWT enforcement test"
assert_has "install.sh == 200" "$out" "plans the install.sh test"
assert_has "enrol (bogus token) == 401" "$out" "plans the bogus enrol test"
assert_has '"enabled":false' "$out" "plans disabling the workers.dev route"
assert_lacks "$FAKE_TOKEN" "$out" "the API token is never printed"
assert_lacks "BEGIN PRIVATE" "$out" "no private key material in the output"
[ ! -f "$T/curl-calls" ] && ok "no curl was executed" || bad "no curl was executed" "$(cat "$T/curl-calls")"
[ "$sum_before" = "$(openssl dgst -sha256 -r "$MANAGER/wrangler.toml")" ] && ok "committed wrangler.toml untouched" || bad "committed wrangler.toml untouched"

GEN="$MANAGER/.deploy/wrangler.generated.toml"
if [ -f "$GEN" ]; then
  g="$(cat "$GEN")"
  assert_has 'custom_domain = true' "$g" "generated config has the Custom Domain route"
  assert_has 'pattern = "exp-control.example.com"' "$g" "route pattern is the domain"
  assert_has 'EXP_OWNER_EMAIL = "owner@example.com"' "$g" "owner var rendered"
  assert_has 'ORG_NAME = "Example Org"' "$g" "org name var rendered"
  assert_has 'MANAGER_URL = "https://exp-control.example.com"' "$g" "manager url var rendered"
  assert_has 'RELEASE_PUBKEY_PEM = "-----BEGIN PUBLIC KEY-----\n' "$g" "release public key rendered"
  assert_lacks "PRIVATE" "$g" "no private key in the generated config"
  assert_has 'main = "../worker/src/index.ts"' "$g" "paths are re-rooted for the .deploy directory"
  git -C "$MANAGER" check-ignore -q .deploy/wrangler.generated.toml && ok ".deploy/ is gitignored" || bad ".deploy/ is gitignored"
  if [ -x "$MANAGER/node_modules/.bin/wrangler" ] && [ -d "$MANAGER/ui/dist" ]; then
    wout="$(cd "$MANAGER" && ./node_modules/.bin/wrangler deploy --dry-run -c "$GEN" --outdir "$T/bundle" 2>&1)"; wrc=$?
    [ "$wrc" -eq 0 ] && ok "wrangler accepts the generated config (offline deploy --dry-run)" || bad "wrangler accepts the generated config" "$wout"
  else
    echo "  skip wrangler offline validation (node_modules or ui/dist missing)"
  fi
else
  bad "generated config exists"
fi

# no custom domain: workers.dev mode, routes absent
"${DEPLOY[@]}" --dry-run --account-id "$ACCT" --owner-email o@example.com --release-pubkey "$T/pub.pem" >"$T/wd.out" 2>&1
assert_has "no --domain: deploying to" "$(cat "$T/wd.out")" "warns when deploying to workers.dev"
assert_lacks "custom_domain" "$(cat "$GEN")" "no custom-domain route without --domain"

echo "deploy.sh --embed-ui"
[ -f "$GEN" ] && assert_has "[assets]" "$(cat "$GEN")" "default render still contains the [assets] section"
[ -f "$GEN" ] && assert_has 'binding = "ASSETS"' "$(cat "$GEN")" "default render still has the ASSETS binding"
eout="$("${DEPLOY[@]}" "${base_args[@]}" --embed-ui 2>&1)"; erc=$?
[ "$erc" -eq 0 ] && ok "--dry-run --embed-ui exits 0" || bad "--dry-run --embed-ui exits 0 (rc=$erc)" "$eout"
assert_has "ui=embedded-in-worker" "$eout" "dry-run prints the embedded mode"
assert_has "EXP_EMBED_UI=1 node scripts/prepare.mjs" "$eout" "dry-run plans the embedding prepare step"
eg="$(cat "$GEN")"
assert_lacks "[assets]" "$eg" "embedded render has no [assets] section"
assert_lacks "ASSETS" "$eg" "embedded render has no ASSETS binding"
assert_lacks "run_worker_first" "$eg" "embedded render has no run_worker_first"
assert_has "[[d1_databases]]" "$eg" "embedded render keeps the D1 binding"
assert_has "[vars]" "$eg" "embedded render keeps the vars"
"${DEPLOY[@]}" "${base_args[@]}" >/dev/null 2>&1
assert_has "[assets]" "$(cat "$GEN")" "re-running without the flag restores the [assets] section"

echo "deploy.sh refusals"
assert_fails "refuses a missing API token" "CLOUDFLARE_API_TOKEN is not set" env -u CLOUDFLARE_API_TOKEN "$MANAGER/deploy.sh" "${base_args[@]}"
assert_fails "refuses the token as a flag" "CLOUDFLARE_API_TOKEN only" "${DEPLOY[@]}" --api-token abc "${base_args[@]}"
assert_fails "refuses a bad account id" "32 hex" "${DEPLOY[@]}" --dry-run --account-id nope --owner-email o@example.com --release-pubkey "$T/pub.pem"
assert_fails "refuses a bad domain" "must be a host name" "${DEPLOY[@]}" --dry-run --account-id "$ACCT" --domain "https://x.example.com/a" --owner-email o@example.com --release-pubkey "$T/pub.pem"
assert_fails "refuses a bad owner email" "email" "${DEPLOY[@]}" --dry-run --account-id "$ACCT" --owner-email nope --release-pubkey "$T/pub.pem"
assert_fails "refuses a private key as the release key" "contains a private key" "${DEPLOY[@]}" --dry-run --account-id "$ACCT" --owner-email o@example.com --release-pubkey "$T/priv.pem"
assert_fails "refuses a missing release key" "release public key not found" "${DEPLOY[@]}" --dry-run --account-id "$ACCT" --owner-email o@example.com --release-pubkey "$T/none.pem"
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$T/ec.pem" 2>/dev/null && openssl pkey -in "$T/ec.pem" -pubout -out "$T/ecpub.pem"
assert_fails "refuses a non-Ed25519 release key" "not an Ed25519" "${DEPLOY[@]}" --dry-run --account-id "$ACCT" --owner-email o@example.com --release-pubkey "$T/ecpub.pem"
assert_fails "refuses a bad worker name" "worker-name" "${DEPLOY[@]}" "${base_args[@]}" --worker-name "Bad Name"

echo "deploy.sh --kiosk-allow-ip"
assert_lacks "bypass /kiosk" "$out" "no kiosk Access app without --kiosk-allow-ip"
kout="$("${DEPLOY[@]}" "${base_args[@]}" --kiosk-allow-ip 37.34.66.15/32 --kiosk-allow-ip 2001:db8:10::/48,37.34.66.15/32 2>&1)"; krc=$?
[ "$krc" -eq 0 ] && ok "kiosk dry run exits 0" || bad "kiosk dry run exits 0 (rc=$krc)" "$kout"
assert_has '"name":"exp-manager bypass /kiosk","domain":"exp-control.example.com/kiosk"' "$kout" "plans the kiosk bypass application on /kiosk only"
assert_has '"decision":"bypass","include":[{"ip":{"ip":"37.34.66.15/32"}},{"ip":{"ip":"2001:db8:10::/48"}}]' "$kout" "kiosk bypass includes exactly the given sources (deduplicated), never everyone"
assert_has "/kiosk/api/devices (direct, bypassing Access) == 403" "$kout" "plans the Worker-side kiosk refusal check"
assert_has 'KIOSK_ALLOW_CIDRS = "37.34.66.15/32,2001:db8:10::/48"' "$(cat "$GEN")" "generated config carries KIOSK_ALLOW_CIDRS"
"${DEPLOY[@]}" "${base_args[@]}" >/dev/null 2>&1
assert_has 'KIOSK_ALLOW_CIDRS = ""' "$(cat "$GEN")" "re-running without --kiosk-allow-ip disables the kiosk in the Worker"
for badc in 0.0.0.0/0 10.0.0.0/8 37.34.66.15 37.34.66.256/32 ::/0 2001:db8::/16 "37.34.66.15/32;x" example.com/32; do
  assert_fails "refuses kiosk source $badc" "--kiosk-allow-ip" "${DEPLOY[@]}" "${base_args[@]}" --kiosk-allow-ip "$badc"
done

echo "deploy.sh takeover guards (ordering, foreign Access apps, policy preservation)"
# dry-run order: the Workers custom-domain guard and the Access reads come before ANY Access app/policy call
gline="$(printf '%s\n' "$out" | grep -n 'workers/domains?hostname=exp-control.example.com' | head -n1 | cut -d: -f1)"
aline="$(printf '%s\n' "$out" | grep -n '/access/' | head -n1 | cut -d: -f1)"
wline="$(printf '%s\n' "$out" | grep -nE 'API (POST|PUT) /accounts/[0-9a-f]+/access/' | head -n1 | cut -d: -f1)"
{ [ -n "$gline" ] && [ -n "$aline" ] && [ "$gline" -lt "$aline" ]; } && ok "dry-run: the custom-domain guard is planned before any Access call" || bad "dry-run: guard before Access (guard=$gline access=$aline)" "$out"
{ [ -n "$aline" ] && [ -n "$wline" ] && [ "$aline" -lt "$wline" ]; } && ok "dry-run: Access reads (and the foreign-app guard) precede the first Access write" || bad "dry-run: reads before writes"
assert_has "refuse an existing app for exp-control.example.com" "$out" "dry-run documents the foreign-app guard"
assert_has "--adopt-access-apps" "$out" "dry-run documents the adopt flag"

# a tiny local mock of the Cloudflare API (stdlib only, loopback only) records every request
cat > "$T/mock-cf.py" <<'PYEOF'
import json, re, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
scenario, portfile, logfile = sys.argv[1], sys.argv[2], sys.argv[3]
HOST = "exp-control.example.com"
UUID = "11111111-2222-3333-4444-555555555555"
OWNER_POLICY = {"id": "p1", "name": "exp-manager owner", "decision": "allow", "precedence": 3, "session_duration": "1h",
                "approval_required": True, "purpose_justification_required": True,
                "include": [{"email": {"email": "admin@example.com"}}],
                "require": [{"email_domain": {"domain": "example.com"}}],
                "exclude": [{"email": {"email": "intern@example.com"}}], "created_at": "x", "updated_at": "y"}
APPS = []
if scenario == "foreign_app": APPS = [{"id": "f1", "name": "someone-elses-app", "domain": HOST, "type": "self_hosted"}]
if scenario == "foreign_bypass_path": APPS = [{"id": "f2", "name": "legacy", "domain": HOST + "/healthz", "type": "self_hosted"}]
if scenario == "name_other_host": APPS = [{"id": "o1", "name": "exp-manager", "domain": "other.example.com", "type": "self_hosted"}]
if scenario == "preserve": APPS = [{"id": "a1", "name": "exp-manager", "domain": HOST, "type": "self_hosted", "session_duration": "12h"}]
n = [0]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, result):
        b = json.dumps({"success": True, "errors": [], "result": result}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def handle_any(self):
        ln = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(ln).decode() if ln else ""
        with open(logfile, "a") as f: f.write("%s %s\t%s\n" % (self.command, self.path, body))
        p, m = self.path, self.command
        if p.endswith("/workers/subdomain"): return self.reply({"subdomain": "acct"})
        if "/d1/database" in p: return self.reply([{"name": "exp-manager", "uuid": UUID}])
        if "/r2/buckets" in p: return self.reply({"buckets": [{"name": "exp-artifacts"}]})
        if "/workers/domains" in p:
            return self.reply([{"hostname": HOST, "service": "other-worker"}] if scenario == "foreign_domain" else [])
        if p.endswith("/access/organizations"): return self.reply({"auth_domain": "team.cloudflareaccess.com"})
        if re.search(r"/access/apps\?", p) and m == "GET": return self.reply(APPS)
        if re.search(r"/access/apps/[^/]+/policies$", p) and m == "GET":
            return self.reply([OWNER_POLICY] if (scenario == "preserve" and "/apps/a1/" in p) else [])
        if re.search(r"/access/apps(/[^/]+)?$", p) and m in ("POST", "PUT"):
            n[0] += 1; return self.reply({"id": p.rsplit("/", 1)[-1] if m == "PUT" else "new%d" % n[0], "aud": "aud%d" % n[0]})
        if "/policies" in p and m in ("POST", "PUT"): return self.reply({"id": "p9"})
        self.reply([])
    do_GET = do_POST = do_PUT = do_DELETE = handle_any
srv = HTTPServer(("127.0.0.1", 0), H)
open(portfile, "w").write(str(srv.server_address[1]))
srv.serve_forever()
PYEOF
# shims so a non-dry run stops right after the Access steps: wrangler/npm/prepare do nothing, `wrangler deploy` fails
mkdir -p "$T/mbin"; REAL_NODE="$(command -v node)"
printf '#!/bin/sh\ncase " $* " in *" deploy "*) exit 1;; esac\nexit 0\n' > "$T/mbin/npx"
printf '#!/bin/sh\nexit 0\n' > "$T/mbin/npm"
printf '#!/bin/sh\ncase "$*" in *prepare.mjs*) exit 0;; esac\nexec "%s" "$@"\n' "$REAL_NODE" > "$T/mbin/node"
chmod +x "$T/mbin/npx" "$T/mbin/npm" "$T/mbin/node"
mock_run() { # mock_run SCENARIO [extra deploy args] -> sets MOUT, MRC, MLOG (recorded requests)
  local sc="$1"; shift
  rm -f "$T/mock.port" "$T/mock.log"; : > "$T/mock.log"
  python3 -I "$T/mock-cf.py" "$sc" "$T/mock.port" "$T/mock.log" & local pid=$!
  local i; for i in $(seq 1 50); do [ -s "$T/mock.port" ] && break; sleep 0.1; done
  MRC=0
  MOUT="$(env -u http_proxy -u HTTP_PROXY -u https_proxy -u HTTPS_PROXY NO_PROXY=127.0.0.1 PATH="$T/mbin:$PATH" CLOUDFLARE_API_TOKEN="$FAKE_TOKEN" \
    CF_API_BASE="http://127.0.0.1:$(cat "$T/mock.port")" "$MANAGER/deploy.sh" --account-id "$ACCT" --domain exp-control.example.com --owner-email Owner@Example.com \
    --release-pubkey "$T/pub.pem" "$@" 2>&1)" || MRC=$?
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  MLOG="$(cat "$T/mock.log")"
}
access_writes() { printf '%s\n' "$MLOG" | grep -E '^(POST|PUT|DELETE) .*/access/' || true; }

if command -v python3 >/dev/null; then
  mock_run foreign_domain
  [ "$MRC" -ne 0 ] && has "already attached to the Worker 'other-worker'" "$MOUT" && ok "refuses a domain served by a different Worker" || bad "refuses a domain served by a different Worker (rc=$MRC)" "$MOUT"
  [ -z "$(printf '%s\n' "$MLOG" | grep '/access/')" ] && ok "domain refusal happens before ANY Access call" || bad "no Access call before the domain guard" "$MLOG"

  mock_run foreign_app
  [ "$MRC" -ne 0 ] && has "not managed by this script" "$MOUT" && has "someone-elses-app" "$MOUT" && ok "refuses an existing foreign Access app for the host" || bad "refuses a foreign Access app (rc=$MRC)" "$MOUT"
  [ -z "$(access_writes)" ] && ok "foreign app: no Access write of any kind was attempted" || bad "foreign app: no Access write" "$(access_writes)"
  gi="$(printf '%s\n' "$MLOG" | grep -n 'workers/domains' | head -n1 | cut -d: -f1)"; ai="$(printf '%s\n' "$MLOG" | grep -n '/access/' | head -n1 | cut -d: -f1)"
  { [ -n "$gi" ] && [ -n "$ai" ] && [ "$gi" -lt "$ai" ]; } && ok "real run: the Workers-domain guard call precedes every Access call" || bad "real run order (guard=$gi access=$ai)" "$MLOG"

  mock_run foreign_bypass_path
  [ "$MRC" -ne 0 ] && has "not managed by this script" "$MOUT" && [ -z "$(access_writes)" ] && ok "refuses a foreign app on a bypass path (HOST/healthz), no write" || bad "refuses a foreign bypass-path app (rc=$MRC)" "$MOUT"

  mock_run foreign_app --adopt-access-apps
  has "--adopt-access-apps: taking over" "$MOUT" && printf '%s\n' "$MLOG" | grep -q '^PUT .*/access/apps/f1' && ok "--adopt-access-apps allows taking over the foreign app (explicit opt-in)" || bad "--adopt-access-apps adopts" "$MOUT"

  mock_run name_other_host
  [ "$MRC" -ne 0 ] && has "different host" "$MOUT" && has "Refusing to repoint" "$MOUT" && ok "refuses to repoint an app named like ours that protects another host" || bad "refuses to repoint by name (rc=$MRC)" "$MOUT"
  [ -z "$(access_writes)" ] && ok "repoint refusal: no Access write was attempted" || bad "repoint refusal: no write" "$(access_writes)"
  mock_run name_other_host --adopt-access-apps
  [ "$MRC" -ne 0 ] && has "Refusing to repoint" "$MOUT" && [ -z "$(access_writes)" ] && ok "--adopt-access-apps does NOT override the by-name repoint refusal" || bad "adopt must not repoint by name" "$MOUT"

  mock_run preserve
  put="$(printf '%s\n' "$MLOG" | grep '^PUT .*/access/apps/a1/policies/p1' | cut -f2)"
  [ -n "$put" ] && ok "an existing owner policy is updated in place (PUT)" || bad "owner policy PUT happened" "$MLOG"
  printf '%s' "$put" | jq -e '.require == [{"email_domain":{"domain":"example.com"}}] and .exclude == [{"email":{"email":"intern@example.com"}}]' >/dev/null 2>&1 && ok "policy update keeps the admin's require and exclude rules" || bad "policy update keeps require/exclude" "$put"
  printf '%s' "$put" | jq -e '.approval_required == true and .purpose_justification_required == true and .session_duration == "1h" and .precedence == 3' >/dev/null 2>&1 && ok "policy update keeps approval/purpose/session_duration/precedence" || bad "policy update keeps other fields" "$put"
  printf '%s' "$put" | jq -e '(.include | length) == 2 and (.include | any(.email.email == "admin@example.com")) and (.include | any(.email.email == "owner@example.com")) and (has("id") | not)' >/dev/null 2>&1 && ok "policy update unions the includes and sends no read-only ids" || bad "policy include union" "$put"
else
  echo "  skip mock-API guard tests (python3 missing)"
fi

# ---- publish-release.sh ----------------------------------------------------------------------------------------------------------
echo "publish-release.sh --dry-run"
PUB=(env PATH="$T/bin:$PATH" "$MANAGER/scripts/publish-release.sh")
mkrelease "$T/dist" 0.1.0 "https://github.com/example/exp/releases/tag/v0.1.0"
out="$("${PUB[@]}" --dist "$T/dist" --pubkey "$T/pub.pem" --set-site hall-b --bucket exp-artifacts --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "exits 0 for a good release" || bad "exits 0 for a good release (rc=$rc)" "$out"
assert_has "signature verifies" "$out" "verifies the manifest signature locally"
assert_has "2 artifacts verified against the signed manifest" "$out" "verifies every sha256 and size"
assert_has "wrangler r2 object put exp-artifacts/artifacts/art_" "$out" "plans one R2 put per artifact"
assert_has "wrangler r2 object put exp-artifacts/releases/0.1.0/rel_" "$out" "plans the manifest and signature puts"
assert_has "manifest.json.sig --file" "$out" "plans the signature put"
assert_has "--remote" "$out" "targets the remote account by default"
assert_has "INSERT INTO releases" "$out" "plans the releases row"
assert_has "ON CONFLICT(version) DO UPDATE" "$out" "release upsert is idempotent"
assert_has "ON CONFLICT(artifact_id) DO UPDATE" "$out" "artifact upserts are idempotent"
assert_has "UPDATE sites SET release_version = '0.1.0'" "$out" "--set-site updates the site"
assert_has "'https://github.com/example/exp/releases/tag/v0.1.0'" "$out" "notes_url stored"
[ ! -f "$T/curl-calls" ] && ok "no curl was executed" || bad "no curl was executed" "$(cat "$T/curl-calls")"
out2="$("${PUB[@]}" --dist "$T/dist" --pubkey "$T/pub.pem" --dry-run 2>&1)"
ids1="$(printf '%s' "$out" | grep -o 'art_[0-9A-F]\{26\}' | sort -u)"; ids2="$(printf '%s' "$out2" | grep -o 'art_[0-9A-F]\{26\}' | sort -u)"
[ -n "$ids1" ] && [ "$ids1" = "$ids2" ] && ok "artifact ids are deterministic (re-runs replace, never duplicate)" || bad "artifact ids are deterministic"

echo "publish-release.sh refusals"
assert_fails "refuses a wrong public key" "differs from the RELEASE_PUBKEY_PEM" "${PUB[@]}" --dist "$T/dist" --pubkey "$T/other-pub.pem" --dry-run
cp -r "$T/dist" "$T/tampered"; head -c 3000 /dev/urandom > "$T/tampered/exp-agent-0.1.0-noarch.tar.gz"
assert_fails "refuses a tampered artifact (sha256 differs from the signed manifest)" "sha256 differs" "${PUB[@]}" --dist "$T/tampered" --pubkey "$T/pub.pem" --dry-run
cp -r "$T/dist" "$T/short"; truncate -s 100 "$T/short/exp-probe-0.1.0-noarch.tar.gz"
assert_fails "refuses a truncated artifact" "size on disk differs" "${PUB[@]}" --dist "$T/short" --pubkey "$T/pub.pem" --dry-run
cp -r "$T/dist" "$T/badman"; jq '.min_agent_version = "9.9.9"' "$T/badman/exp-0.1.0-manifest.json" > "$T/m.json" && mv "$T/m.json" "$T/badman/exp-0.1.0-manifest.json"
assert_fails "refuses a manifest changed after signing" "does NOT verify" "${PUB[@]}" --dist "$T/badman" --pubkey "$T/pub.pem" --dry-run
cp -r "$T/dist" "$T/nosig"; rm "$T/nosig/exp-0.1.0-manifest.json.sig"
assert_fails "refuses an unsigned release" "no signature" "${PUB[@]}" --dist "$T/nosig" --pubkey "$T/pub.pem" --dry-run
cp -r "$T/dist" "$T/missing"; rm "$T/missing/exp-probe-0.1.0-noarch.tar.gz"
assert_fails "refuses a missing artifact file" "artifact file missing" "${PUB[@]}" --dist "$T/missing" --pubkey "$T/pub.pem" --dry-run
# validly SIGNED manifests with hostile values: the strict regexes must stop them before SQL is built
mkrelease "$T/inj1" 0.1.0
jq '.notes_url = "https://example.com/x'"'"'; DROP TABLE releases;--"' "$T/inj1/exp-0.1.0-manifest.json" > "$T/m.json" && mv "$T/m.json" "$T/inj1/exp-0.1.0-manifest.json"; sign "$T/inj1/exp-0.1.0-manifest.json" "$T/priv.pem"
assert_fails "refuses a signed manifest with a single quote in notes_url" "notes_url is not a plain https URL" "${PUB[@]}" --dist "$T/inj1" --pubkey "$T/pub.pem" --dry-run
mkrelease "$T/inj2" 0.1.0
jq '.artifacts[0].sha256 = "ABCDEF"' "$T/inj2/exp-0.1.0-manifest.json" > "$T/m.json" && mv "$T/m.json" "$T/inj2/exp-0.1.0-manifest.json"; sign "$T/inj2/exp-0.1.0-manifest.json" "$T/priv.pem"
assert_fails "refuses a signed manifest with a malformed sha256" "64 lowercase hex" "${PUB[@]}" --dist "$T/inj2" --pubkey "$T/pub.pem" --dry-run
mkrelease "$T/inj3" 0.1.0
jq '.artifacts[0].name = "exp-agent-0.1.0-noarch.tar.gz'"'"' OR 1=1"' "$T/inj3/exp-0.1.0-manifest.json" > "$T/m.json" && mv "$T/m.json" "$T/inj3/exp-0.1.0-manifest.json"; sign "$T/inj3/exp-0.1.0-manifest.json" "$T/priv.pem"
assert_fails "refuses a signed manifest with a hostile artifact name" "is not exp-<component>" "${PUB[@]}" --dist "$T/inj3" --pubkey "$T/pub.pem" --dry-run
mkrelease "$T/inj4" 0.1.0
jq '.artifacts[0].size = "12; DROP TABLE x"' "$T/inj4/exp-0.1.0-manifest.json" > "$T/m.json" && mv "$T/m.json" "$T/inj4/exp-0.1.0-manifest.json"; sign "$T/inj4/exp-0.1.0-manifest.json" "$T/priv.pem"
assert_fails "refuses a signed manifest with a non-integer size" "size is not an integer" "${PUB[@]}" --dist "$T/inj4" --pubkey "$T/pub.pem" --dry-run
assert_fails "refuses a hostile --set-site" "site slug" "${PUB[@]}" --dist "$T/dist" --pubkey "$T/pub.pem" --set-site "x'; DROP TABLE sites;--" --dry-run

# ---- publish-release.sh --local: a real end state in a local D1 / R2 ----------------------------------------------------------------
echo "publish-release.sh --local (wrangler local state)"
if [ -x "$MANAGER/node_modules/.bin/wrangler" ]; then
  P="$T/persist"
  (cd "$MANAGER" && npx --no-install wrangler d1 migrations apply DB --local --persist-to "$P" </dev/null) >"$T/mig.out" 2>&1 || bad "local migrations" "$(tail -5 "$T/mig.out")"
  (cd "$MANAGER" && npx --no-install wrangler d1 execute DB --local --persist-to "$P" --yes --command "INSERT INTO sites (site, name, created_at, updated_at) VALUES ('hall-b','Hall B','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')" </dev/null) >/dev/null 2>&1
  for run in 1 2; do
    out="$("${PUB[@]}" --dist "$T/dist" --pubkey "$T/pub.pem" --set-site hall-b --local --persist-to "$P" --config "$MANAGER/wrangler.toml" 2>&1)"; rc=$?
    [ "$rc" -eq 0 ] && ok "local publish run $run succeeds" || bad "local publish run $run" "$out"
  done
  q="$(cd "$MANAGER" && npx --no-install wrangler d1 execute DB --local --persist-to "$P" --json --command "SELECT (SELECT count(*) FROM releases) AS r, (SELECT count(*) FROM artifacts) AS a, (SELECT release_version FROM sites WHERE site='hall-b') AS s, (SELECT count(*) FROM audit WHERE action='release.publish') AS e, (SELECT length(signature) FROM releases) AS l" </dev/null 2>/dev/null)"
  row="$(printf '%s' "$q" | jq -c '.[0].results[0]' 2>/dev/null)"
  [ "$row" = '{"r":1,"a":2,"s":"0.1.0","e":2,"l":88}' ] && ok "end state: 1 release, 2 artifacts, site at 0.1.0, one audit event per run (2), after TWO runs (idempotent rows)" || bad "end state in local D1" "$row"
  # regression (e2e m2): the "deployed key" check is for the DEPLOYED manager; --local must not be bound to a stale .deploy/ config
  out3="$("${PUB[@]}" --dist "$T/dist" --pubkey "$T/other-pub.pem" --local --persist-to "$P" --config "$MANAGER/wrangler.toml" 2>&1)" || true
  case "$out3" in
    *"differs from the RELEASE_PUBKEY_PEM"*) bad "--local ignores the deployed key of .deploy/ (it only checks the signature against --pubkey)" "$out3" ;;
    *"does NOT verify"*) ok "--local ignores the deployed key of .deploy/ (it only checks the signature against --pubkey)" ;;
    *) bad "--local with a key that did not sign the manifest is refused by the signature check" "$out3" ;;
  esac
  aid="$(printf '%s' "$out" | head -c0; cd "$MANAGER" && npx --no-install wrangler d1 execute DB --local --persist-to "$P" --json --command "SELECT artifact_id FROM artifacts WHERE name='exp-agent-0.1.0-noarch.tar.gz'" </dev/null 2>/dev/null | jq -r '.[0].results[0].artifact_id')"
  if [ -n "$aid" ] && (cd "$MANAGER" && npx --no-install wrangler r2 object get "exp-artifacts/artifacts/$aid" --file "$T/got.bin" --local --persist-to "$P" </dev/null) >/dev/null 2>&1; then
    cmp -s "$T/got.bin" "$T/dist/exp-agent-0.1.0-noarch.tar.gz" && ok "end state: the R2 object holds exactly the artifact bytes" || bad "R2 object differs from the artifact"
  else
    bad "R2 object exists for $aid"
  fi
else
  echo "  skip local publish test (node_modules/.bin/wrangler missing: run npm ci)"
fi

# ---- backup.sh -------------------------------------------------------------------------------------------------------------------------
echo "backup.sh"
assert_fails "refuses an output directory inside the repository" "outside it" env CLOUDFLARE_API_TOKEN="$FAKE_TOKEN" CLOUDFLARE_ACCOUNT_ID="$ACCT" "$MANAGER/scripts/backup.sh" --out-dir "$MANAGER/backups-test"
rmdir "$MANAGER/backups-test" 2>/dev/null || true
assert_fails "requires credentials" "CLOUDFLARE_API_TOKEN" env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_ACCOUNT_ID "$MANAGER/scripts/backup.sh" --out-dir "$T/b"

# ---- rotate-master-key.sh ---------------------------------------------------------------------------------------------------------------
echo "rotate-master-key.sh"
OLDK="$(openssl rand -base64 32)"; NEWK="$(openssl rand -base64 32)"
printf '%s\n' "$OLDK" > "$T/old.key"; printf '%s\n' "$NEWK" > "$T/new.key"
mkdir -p "$T/rbin"
# wrangler shim: records argv (one line per call) and stdin (one file per call); never touches the network
cat > "$T/rbin/npx" <<SHIM
#!/bin/sh
mkdir -p "$T/npx-in"
n=\$(ls "$T/npx-in" | wc -l | tr -d ' ')
echo "\$*" >> "$T/npx-args"
cat > "$T/npx-in/\$n"
exit 0
SHIM
chmod +x "$T/rbin/npx"
cp "$T/bin/curl" "$T/rbin/curl"
ROT=(env PATH="$T/rbin:$PATH" "$MANAGER/scripts/rotate-master-key.sh" -c "$MANAGER/wrangler.toml")
rout="$("${ROT[@]}" --old-key-file "$T/old.key" --new-key-file "$T/new.key" --dry-run 2>&1)"; rrc=$?
[ "$rrc" -eq 0 ] && ok "dry-run exits 0" || bad "dry-run exits 0 (rc=$rrc)" "$rout"
assert_has "[dry-run] would run: wrangler secret put EXP_MASTER_KEY_PREVIOUS" "$rout" "dry-run plans setting the previous key"
assert_has "[dry-run] would run: wrangler secret put EXP_MASTER_KEY " "$rout" "dry-run plans setting the new key"
assert_has "wrangler secret delete EXP_MASTER_KEY_PREVIOUS" "$rout" "dry-run explains when to delete the previous key"
assert_has "nothing was changed" "$rout" "dry-run says nothing was changed"
assert_lacks "$OLDK" "$rout" "dry-run never prints the old key"
assert_lacks "$NEWK" "$rout" "dry-run never prints the new key"
if [ ! -f "$T/npx-args" ] && [ ! -f "$T/curl-calls" ]; then ok "dry-run ran no wrangler and no curl"; else bad "dry-run ran no wrangler and no curl" "$(cat "$T/npx-args" 2>/dev/null)"; fi
rout="$("${ROT[@]}" --old-key-stdin --dry-run <<<"$OLDK" 2>&1)"; rrc=$?
if [ "$rrc" -eq 0 ]; then ok "dry-run with stdin old key and a to-be-generated new key exits 0"; else bad "dry-run with stdin old key (rc=$rrc)" "$rout"; fi
assert_lacks "$OLDK" "$rout" "stdin old key is not echoed"
assert_fails "refuses identical keys" "identical" "${ROT[@]}" --old-key-file "$T/old.key" --new-key-file "$T/old.key" --dry-run
assert_fails "refuses a key given as an argument" "never accepted as arguments" "${ROT[@]}" --old-key "$OLDK" --dry-run
assert_fails "requires the old key" "OLD key must be supplied" "${ROT[@]}" --dry-run
assert_fails "refuses a malformed key" "not base64 of exactly 32 bytes" "${ROT[@]}" --old-key-file "$T/priv.pem" --dry-run
assert_fails "refuses two stdin keys" "only one key can come from stdin" "${ROT[@]}" --old-key-stdin --new-key-stdin --dry-run
# real run against the recording shim: keys travel on stdin only, PREVIOUS is set before the new current key
rm -f "$T/npx-args"; rm -rf "$T/npx-in"
rout="$("${ROT[@]}" --old-key-file "$T/old.key" --new-key-file "$T/new.key" 2>&1)"; rrc=$?
[ "$rrc" -eq 0 ] && ok "rotation run exits 0 (wrangler shim)" || bad "rotation run exits 0 (rc=$rrc)" "$rout"
rargs="$(cat "$T/npx-args" 2>/dev/null)"
assert_has "secret put EXP_MASTER_KEY_PREVIOUS" "$(sed -n 1p "$T/npx-args" 2>/dev/null)" "first call sets EXP_MASTER_KEY_PREVIOUS"
assert_has "secret put EXP_MASTER_KEY -c" "$(sed -n 2p "$T/npx-args" 2>/dev/null)" "second call sets EXP_MASTER_KEY"
assert_lacks "$OLDK" "$rargs$rout" "no key material in wrangler argv or script output (old)"
assert_lacks "$NEWK" "$rargs$rout" "no key material in wrangler argv or script output (new)"
if [ "$(cat "$T/npx-in/0" 2>/dev/null)" = "$OLDK" ] && [ "$(cat "$T/npx-in/1" 2>/dev/null)" = "$NEWK" ]; then ok "old key then new key are passed on stdin"; else bad "keys passed on stdin in order"; fi
assert_has "safe_to_remove_previous" "$rout" "explains how to watch progress"

# ---- shellcheck (when available) ---------------------------------------------------------------------------------------------------------
echo "shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  for f in deploy.sh scripts/publish-release.sh scripts/backup.sh scripts/rotate-master-key.sh scripts/test-deploy-dryrun.sh; do
    if shellcheck -S warning "$MANAGER/$f" >"$T/sc.out" 2>&1; then ok "shellcheck $f"; else bad "shellcheck $f" "$(cat "$T/sc.out")"; fi
  done
else
  echo "  skip (shellcheck not installed)"
  for f in deploy.sh scripts/publish-release.sh scripts/backup.sh scripts/rotate-master-key.sh scripts/test-deploy-dryrun.sh; do bash -n "$MANAGER/$f" && ok "bash -n $f" || bad "bash -n $f"; done
fi

printf '\n%d passed, %d failed\n' "$PASSES" "$FAILS"
[ "$FAILS" -eq 0 ]
