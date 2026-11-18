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
    out="$("${PUB[@]}" --dist "$T/dist" --pubkey "$T/pub.pem" --set-site hall-b --local --persist-to "$P" 2>&1)"; rc=$?
    [ "$rc" -eq 0 ] && ok "local publish run $run succeeds" || bad "local publish run $run" "$out"
  done
  q="$(cd "$MANAGER" && npx --no-install wrangler d1 execute DB --local --persist-to "$P" --json --command "SELECT (SELECT count(*) FROM releases) AS r, (SELECT count(*) FROM artifacts) AS a, (SELECT release_version FROM sites WHERE site='hall-b') AS s, (SELECT count(*) FROM audit WHERE action='release.publish') AS e, (SELECT length(signature) FROM releases) AS l" </dev/null 2>/dev/null)"
  row="$(printf '%s' "$q" | jq -c '.[0].results[0]' 2>/dev/null)"
  [ "$row" = '{"r":1,"a":2,"s":"0.1.0","e":2,"l":88}' ] && ok "end state: 1 release, 2 artifacts, site at 0.1.0, one audit event per run (2), after TWO runs (idempotent rows)" || bad "end state in local D1" "$row"
  # regression (e2e m2): the "deployed key" check is for the DEPLOYED manager; --local must not be bound to a stale .deploy/ config
  out3="$("${PUB[@]}" --dist "$T/dist" --pubkey "$T/other-pub.pem" --local --persist-to "$P" 2>&1)" || true
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

# ---- shellcheck (when available) ---------------------------------------------------------------------------------------------------------
echo "shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  for f in deploy.sh scripts/publish-release.sh scripts/backup.sh scripts/test-deploy-dryrun.sh; do
    if shellcheck -S warning "$MANAGER/$f" >"$T/sc.out" 2>&1; then ok "shellcheck $f"; else bad "shellcheck $f" "$(cat "$T/sc.out")"; fi
  done
else
  echo "  skip (shellcheck not installed)"
  for f in deploy.sh scripts/publish-release.sh scripts/backup.sh scripts/test-deploy-dryrun.sh; do bash -n "$MANAGER/$f" && ok "bash -n $f" || bad "bash -n $f"; done
fi

printf '\n%d passed, %d failed\n' "$PASSES" "$FAILS"
[ "$FAILS" -eq 0 ]
