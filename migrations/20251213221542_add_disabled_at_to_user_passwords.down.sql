BEGIN;

ALTER TABLE user_passwords DROP COLUMN disabled_at;
ALTER TABLE user_sessions RENAME COLUMN disabled_at TO deleted_at;

COMMIT;
