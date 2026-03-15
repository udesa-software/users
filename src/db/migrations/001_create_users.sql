CREATE TABLE IF NOT EXISTS users (
  id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  username         VARCHAR(15)  NOT NULL,
  email            VARCHAR(255) NOT NULL,
  password_hash    VARCHAR(255) NOT NULL,
  is_verified      BOOLEAN      NOT NULL DEFAULT FALSE,
  verify_token     UUID,
  token_expires_at TIMESTAMPTZ,
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Unique username (case-sensitive as per CA.3)
CREATE UNIQUE INDEX IF NOT EXISTS users_username_idx ON users (username);

-- Case-insensitive unique email (CA.7)
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (LOWER(email));
