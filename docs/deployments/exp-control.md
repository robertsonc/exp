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
| Access apps | `exp-manager` (allow: owner email), `exp-manager bypass /api/agent`, `… /install.sh`, `… /healthz`, `… /kiosk` (bypass: IP 37.34.66.15/32 only) |
| Release public key | `packaging/keys/release-pub.pem` (Ed25519) |
| Releases published | `0.1.0`, `0.1.1`, `0.2.0`, `0.3.0`. New sites: use `0.3.0` (site lines board, heartbeat cadence, cr-lab fixes; agent, probe, collector amd64+arm64, dashboard, runner, speedtest). 0.3.0 was published to exp-control on 2026-11-25 from the GitHub Release `v0.3.0` assets (tag at `000b626`, built and signed by `release.yml`), after `verify-release.sh` against `packaging/keys/release-pub.pem`, so exp-control and GitHub carry the same bytes. A first `v0.3.0` tag at `6d5b05a` failed its release tests (a spool test fixture with a fixed date, fixed in #22) and published nothing. The 0.2.0 artifacts on exp-control were built from `42ee902` and the GitHub Release `v0.2.0` from `4fe89df`: identical contents, different embedded file times, so their tarball sha256 differ |
| First deployed | 2026-11-18 |
| Last redeployed | 2026-11-28 from `8fb428c` (Worker version `749be544`): Ops board and read-only kiosk with the down-device list (#24, #25), migrations `0006_ops_devices` and `0007_ops_down_devices`, new Access app `exp-manager bypass /kiosk`. Before that: 2026-11-25, twice, no migrations: from `d8bd917` (Worker version `f38c9282`: heartbeat cadence, probe Test ports panel, M4 notes) and then from `92137b4` (Worker version `2546bb3b`: probe port Network / Out-of-band reference fields for the site lines board); release 0.3.0 published. Before that: 2026-11-21, M6 + Debian 12 hosts (`42ee902`, Worker `e6c9b34a`), migration `0005_speedtest`, release 0.2.0 |

Verified after deploy (`deploy.sh` step 6 and manual checks): `/healthz` → `ok`; the Worker itself answers
401 to `/api/admin/v1/me` without a JWT and with a forged JWT (direct request, bypassing Access); `/` redirects to the
Access login; `/install.sh` → 200, `text/x-shellscript`, manager URL + agent version + the pinned release public key
substituted; `POST /api/agent/v1/enrol` with a bogus token → 401 `invalid_token`; agent manifest without a secret → 401.

## Redeploy / upgrade the manager

From a checkout of `main`, with an API token in the environment (permissions: `manager/README.md`):

```bash
CLOUDFLARE_API_TOKEN=… manager/deploy.sh --account-id <account id> --domain exp-control.harnessed.cloud \
  --owner-email <owner email> --org-name "HPE EXP" --release-pubkey packaging/keys/release-pub.pem \
  --embed-ui --kiosk-allow-ip 37.34.66.15/32
```

`--kiosk-allow-ip 37.34.66.15/32` (from the first deploy that carries the Ops board, migration `0006`): the management network's
egress may open https://exp-control.harnessed.cloud/kiosk, a read-only page of Mist / Central device counts and the devices
that are down (name, type, site, since), without signing in. It creates the Access app `exp-manager bypass /kiosk` (bypass,
include IP 37.34.66.15/32 only) and sets `KIOSK_ALLOW_CIDRS`. **Keep the flag on every redeploy**; dropping it turns the kiosk
off in the Worker. Deployed 2026-11-28; checked from a non-kiosk source: `/kiosk` and `/kiosk/api/devices` → 403 at Access,
and the Worker answers 403 to `/kiosk/api/devices` on a direct request.

**Change who may open the kiosk with `--kiosk-allow-ip` (repeatable), never in the Zero Trust dashboard.** On 2026-11-28 the
`exp-manager` app was replaced by hand with an app `exp-control` whose allow policy listed IPs including `0.0.0.0/0`; the next
deploy refused to overwrite an Access app it does not manage (takeover guard). It was deleted and the deploy recreated
`exp-manager` (owner email only) and the `/kiosk` bypass.

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
Then set the version on a site (with a canary host) in the UI. Relative paths are fine: `deploy.sh` resolves `--release-pubkey`
against the directory it is called from.

## Rotating keys

**Release key.** Free before the first host enrols (no host has pinned it yet). After that it rotates only through a
release signed by the current key (SR-10).

**EXP_MASTER_KEY** rotates at any time, with re-encryption (see "Master key rotation" below); before the first host
enrols you may simply `wrangler secret put` a new key, because nothing is encrypted with it yet.

**Release key**
1. `packaging/gen-release-key.sh /secure/exp-release.pem` (outside the repo; prints the public key path).
2. Copy the new public key over `packaging/keys/release-pub.pem`, commit.
3. Re-sign each published release from its own commit, e.g. `EXP_RELEASE_KEY=/secure/exp-release.pem packaging/build.sh --release 0.1.1 --out dist`
   (tarballs are byte-identical for the same commit; only the signature changes).
4. Redeploy with the new key (`deploy.sh … --release-pubkey packaging/keys/release-pub.pem`), then re-publish
   (`publish-release.sh --dist dist --pubkey packaging/keys/release-pub.pem`; it upserts the signature).
5. Check: `curl -fsSL https://exp-control.harnessed.cloud/install.sh | grep -A1 'BEGIN PUBLIC KEY'` shows the new key.

## Master key rotation (with re-encryption)

Every stored secret (SSO secrets, ingest/dashboard tokens, webhook URLs, credentials inside compiled desired state) is
sealed with AES-256-GCM and stamped with the **key id** of the key that sealed it (`key_id` = first 16 hex of
`sha256("exp-key-id/v1|" + key)`; not secret). The Worker takes two secrets:

- `EXP_MASTER_KEY`: the current key. Everything is written with it.
- `EXP_MASTER_KEY_PREVIOUS`: optional, only while a rotation is being re-encrypted. Values stamped with its id still decrypt.

A value stamped with any other key id fails closed (`unknown_key_id`, 503 on the operations that need it); nothing tries keys
by guessing. Rows written before migration `0003_master_key_rotation.sql` carry no key id and are defined as "sealed by the key
that was current when the migration was applied": they are read with `EXP_MASTER_KEY` (then `EXP_MASTER_KEY_PREVIOUS`, the
only other key ever tried) and the cron stamps them. **Deploy (apply migrations) before the first rotation.**

Procedure:

1. Have the OLD key at hand (your offline backup). The script cannot read it back from Cloudflare.
2. Rehearse: `manager/scripts/rotate-master-key.sh --old-key-file /secure/old.key --dry-run`.
3. Rotate (the new key is generated and shown ONCE on the terminal, or supply `--new-key-file` / `--new-key-stdin`):
   ```bash
   export CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=<account id>
   manager/scripts/rotate-master-key.sh --old-key-file /secure/old.key -c manager/.deploy/wrangler.generated.toml
   ```
   It sets `EXP_MASTER_KEY_PREVIOUS` = old, then `EXP_MASTER_KEY` = new, both over stdin (never argv), refuses identical keys and
   never logs key material. Write the new key into your offline backup now; keep the old one until step 5.
4. Watch the progress: admin UI **Settings -> Master key**, or `GET /api/admin/v1/settings/master-key`
   (`{current_key_id, previous_key_id, remaining_previous, unknown_key_rows, safe_to_remove_previous}`). The 5-minute cron re-seals
   up to 200 rows per run (secrets, their rotation-grace `previous_*` values, and the credentials inside desired documents; each
   update is guarded per row) until `remaining_previous` is 0. Agents see no change: served desired documents are identical.
5. When `safe_to_remove_previous` is `true`: `npx --prefix manager wrangler secret delete EXP_MASTER_KEY_PREVIOUS --name exp-manager`,
   then retire the old key from the backup. **Never delete it earlier**: values still sealed by it become unreadable.

The dashboard launch nonce (30 s) stays valid across a rotation (the previous key is also accepted while it is configured).
Re-encryption audit events (`master_key.reencrypt`) carry counts and key ids only.

## First hosts

1. Open https://exp-control.harnessed.cloud and sign in through Access (one-time PIN). The first sign-in of the owner
   email creates the owner account.
2. **Sites** → create a site (name, slug, timezone, edge label) and set its release to `0.1.1`.
3. **Hosts → Add host**: name, site, shapes. Copy the one-liner and run it on an Ubuntu 22.04/24.04 host:
   `curl -fsSL https://exp-control.harnessed.cloud/install.sh | sudo bash -s -- expe_…` (single use, 1 hour).
4. Add the **collector** first (it must report its TLS fingerprint before probes are wired), then dashboards, then
   probes (pick test ports in the interface picker; the management interface is refused).
5. Open the dashboard from the manager (SSO handoff); create local users / a NOC token for wall screens.
