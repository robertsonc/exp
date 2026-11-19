-- exp-manager: EXP_MASTER_KEY rotation with re-encryption (docs/spec/05-manager.md section 6).
-- Forward-only. Records WHICH master key sealed each stored value (key_id = first 16 hex of
-- sha256("exp-key-id/v1|" + the base64 key text)), so a rotation can decrypt by key id and the 5-minute cron
-- can re-seal old rows under the new key.
--
-- LEGACY ROWS: rows written before this migration have key_id NULL. SQL cannot know the key id, so NULL is defined as
-- "sealed by the master key that was current when this migration was applied". At read time NULL means: try
-- EXP_MASTER_KEY, then EXP_MASTER_KEY_PREVIOUS if one is configured (only those two keys are ever tried). The cron
-- re-seals NULL rows under the current key and stamps them, so after a few runs no NULL remains.
-- OPERATOR RULE: apply this migration (deploy) BEFORE the first rotation.

ALTER TABLE secrets ADD COLUMN key_id TEXT;
ALTER TABLE secrets ADD COLUMN previous_key_id TEXT;
ALTER TABLE desired_docs ADD COLUMN key_id TEXT;
