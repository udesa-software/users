CREATE TABLE IF NOT EXISTS users (
  id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  username         VARCHAR(15)  NOT NULL,
  email            VARCHAR(255) NOT NULL,
  password_hash    VARCHAR(255) NOT NULL,
  is_verified      BOOLEAN      NOT NULL DEFAULT FALSE,
  verify_token     UUID,
  token_expires_at TIMESTAMPTZ,
  accepted_terms       BOOLEAN      NOT NULL DEFAULT FALSE,
  accepted_terms_at    TIMESTAMPTZ,
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  failed_login_attempts INT         NOT NULL DEFAULT 0,
  locked_until          TIMESTAMPTZ,
  is_suspended          BOOLEAN     NOT NULL DEFAULT FALSE,
  deleted_at            TIMESTAMPTZ,
  password_reset_token      UUID,
  password_reset_expires_at TIMESTAMPTZ,
  last_reset_request_at     TIMESTAMPTZ,
  token_version             INT         NOT NULL DEFAULT 1,
  role_                     VARCHAR(20) NOT NULL DEFAULT 'user'
);

-- Case-insensitive unique username (CA.3)
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users (LOWER(username));

-- Case-insensitive unique email (CA.7)
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (LOWER(email));

-- TABLA 2: User Preferences e info 
CREATE TABLE IF NOT EXISTS preferences (
  id                        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                   UUID        NOT NULL UNIQUE,
  search_radius_km          INT         NOT NULL DEFAULT 25,
  location_update_frequency INT         NOT NULL DEFAULT 5, 
  created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  biography   TEXT,
  CONSTRAINT fk_user_preferences_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS preferences_user_id_idx ON preferences (user_id);
