# CR-m3-master-key-rotation

Status: informational + one additive endpoint. Raised by the M3 k1 step (manager secrets/cron).

## What

1. **New admin endpoint** `GET /api/admin/v1/settings/master-key` (role `admin`, includes `owner`) returns
   `{current_key_id, previous_key_id|null, remaining_previous, unknown_key_rows, safe_to_remove_previous}`. Read-only.
   Listed in `shared/openapi/admin.yaml` (`getMasterKeyStatus`, schema `MasterKeyStatus`, 503 `unavailable` on a misconfigured
   key ring), `01-contracts.md` §13 and `test/fakes/mock_admin` (M3 integration). The manager UI Settings page reads it.
2. **Storage:** migration `0003_master_key_rotation.sql` adds `secrets.key_id`, `secrets.previous_key_id`, `desired_docs.key_id`.
   Credentials inside desired documents use the envelope `enc2:<key_id>:<nonce>:<ct>` (legacy `enc1:` still read). Agents are
   unaffected: documents are decrypted at serve time and re-sealing never changes `content_hash` or `version`.
3. **Legacy rows** (`key_id` NULL) mean "sealed by the key current at migration time"; tried with `EXP_MASTER_KEY`, then
   `EXP_MASTER_KEY_PREVIOUS` (never other keys), stamped by the cron. Operators must deploy before the first rotation.
4. **SSO launch nonce** derivation is unchanged (HMAC keyed from `EXP_MASTER_KEY`); verification additionally accepts a nonce made
   with `EXP_MASTER_KEY_PREVIOUS` while it is configured (30 s life).
5. New Worker secret `EXP_MASTER_KEY_PREVIOUS` (optional, only during a rotation).

## Decision

Applied in the manager (`worker/src/secrets/`, `cron/`, `admin/`), `05-manager.md` section 6, deployment docs, and the contract
(`admin.yaml`, `01-contracts.md` §13, mock admin).
