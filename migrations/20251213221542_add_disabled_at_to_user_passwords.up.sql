BEGIN;

ALTER TABLE user_passwords ADD COLUMN disabled_at TIMESTAMP;
ALTER TABLE user_sessions RENAME COLUMN deleted_at TO disabled_at;

COMMIT;
