# Deployment record: exp-control.harnessed.cloud

The production manager (control panel) for this organization. No secrets in this file. The API token,
`EXP_MASTER_KEY` and the release private key are held by the owner, offline.

| Item | Value |
|---|---|
| URL | https://exp-control.harnessed.cloud |
| Owner (first sign-in creates it) | the address in the Access owner policy (`EXP_OWNER_EMAIL`) |
| Org name | HPE EXP |
| Worker | `exp-manager` (Custom Domain `exp-control.harnessed.cloud`; `workers.dev` route disabled) |
| UI mode | `--embed-ui` (admin SPA bundled into the Worker; see `manager/README.md`) |
| D1 | `exp-manager` |
| R2 | `exp-artifacts` |
| Access team domain | `robertsonfamily.cloudflareaccess.com` (identity provider: one-time PIN) |
| Access apps | `exp-manager` (allow: owner email), `exp-manager bypass /api/agent`, `… /install.sh`, `… /healthz` |
| Release public key | `packaging/keys/release-pub.pem` (Ed25519) |
| Releases published | `0.1.0` (agent, probe, collector amd64+arm64, dashboard) |
| First deployed | 2026-11-18 |

Verified after deploy (`deploy.sh` step 6 and manual checks): `/healthz` → `ok`; the Worker itself answers
401 to `/api/admin/v1/me` without a JWT and with a forged JWT (direct request, bypassing Access); `/` redirects to the
Access login; `/install.sh` → 200, `text/x-shellscript`, manager URL + agent version + the pinned release public key
substituted; `POST /api/agent/v1/enrol` with a bogus token → 401 `invalid_token`; agent manifest without a secret → 401.

## Redeploy / upgrade the manager

From a checkout of `main`, with an API token in the environment (permissions: `manager/README.md`):

```bash
CLOUDFLARE_API_TOKEN=… manager/deploy.sh --account-id <account id> --domain exp-control.harnessed.cloud \
  --owner-email <owner email> --org-name "HPE EXP" --release-pubkey packaging/keys/release-pub.pem
```

Idempotent: it reuses D1, R2 and the Access apps, applies new migrations, never replaces `EXP_MASTER_KEY`, and keeps
any `require`/`exclude` rules added to the Access policies. Add `--embed-ui` only when deploying through a proxy that
rewrites `Authorization` headers to `api.cloudflare.com` (it was needed for the first deploy).

## Publish a release

```bash
EXP_RELEASE_KEY=/secure/exp-release.pem packaging/build.sh --release X.Y.Z --out dist
packaging/verify-release.sh dist packaging/keys/release-pub.pem
CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=<account id> manager/scripts/publish-release.sh --dist dist \
  --pubkey packaging/keys/release-pub.pem
```
Then set the version on a site (with a canary host) in the UI.

## Rotating the initial keys BEFORE the first host enrols

Both rotations are free now because nothing depends on them yet: no host has pinned the release key, and no secret
is encrypted with the master key. **After the first host enrols this changes** — the release key then rotates only
through a release signed by the current key (SR-10), and the master key needs a re-encryption of every stored secret
(not built yet; tracked for M3). Do both rotations before adding hosts.

**Release key**
1. `packaging/gen-release-key.sh /secure/exp-release.pem` (outside the repo; prints the public key path).
2. Copy the new public key over `packaging/keys/release-pub.pem`, commit.
3. Re-sign the release: `EXP_RELEASE_KEY=/secure/exp-release.pem packaging/build.sh --release 0.1.0 --out dist`
   (tarballs are byte-identical for the same commit; only the signature changes).
4. Redeploy with the new key (`deploy.sh … --release-pubkey packaging/keys/release-pub.pem`), then re-publish
   (`publish-release.sh --dist dist --pubkey packaging/keys/release-pub.pem`; it upserts the signature).
5. Check: `curl -fsSL https://exp-control.harnessed.cloud/install.sh | grep -A1 'BEGIN PUBLIC KEY'` shows the new key.

**EXP_MASTER_KEY**
```bash
NEWKEY="$(openssl rand -base64 32)"      # record it offline FIRST
printf '%s' "$NEWKEY" | CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=<account id> \
  npx --prefix manager wrangler secret put EXP_MASTER_KEY --name exp-manager
unset NEWKEY
```
(stdin, never argv). Then discard the old key.

## First hosts

1. Open https://exp-control.harnessed.cloud and sign in through Access (one-time PIN). The first sign-in of the owner
   email creates the owner account.
2. **Sites** → create a site (name, slug, timezone, edge label) and set its release to `0.1.0`.
3. **Hosts → Add host**: name, site, shapes. Copy the one-liner and run it on an Ubuntu 22.04/24.04 host:
   `curl -fsSL https://exp-control.harnessed.cloud/install.sh | sudo bash -s -- expe_…` (single use, 1 hour).
4. Add the **collector** first (it must report its TLS fingerprint before probes are wired), then dashboards, then
   probes (pick test ports in the interface picker; the management interface is refused).
5. Open the dashboard from the manager (SSO handoff); create local users / a NOC token for wall screens.
