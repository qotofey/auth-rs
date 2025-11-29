CREATE TABLE user_sessions (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  refresh_token CHAR(64) UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMP,
  user_credential_id UUID NOT NULL REFERENCES user_credentials(id) ON DELETE CASCADE
);
