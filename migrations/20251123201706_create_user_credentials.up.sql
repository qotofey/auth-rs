CREATE TABLE user_credentials (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  kind VARCHAR(32),
  value VARCHAR(255) UNIQUE NOT NULL,
  confirmed_at TIMESTAMP,
  login_attempts SMALLINT DEFAULT(0),
  locked_until TIMESTAMP,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE user_passwords (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  password_digest VARCHAR(255),
  salt VARCHAR(255),
  expires_in TIMESTAMP,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

