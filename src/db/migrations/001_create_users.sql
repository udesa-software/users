CREATE TABLE IF NOT EXISTS users (
  id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  username         VARCHAR(15)  NOT NULL,
  email            VARCHAR(255) NOT NULL,
  password_hash    VARCHAR(255) NOT NULL,
  is_verified      BOOLEAN      NOT NULL DEFAULT FALSE,
  verify_token     UUID,
  token_expires_at TIMESTAMPTZ,
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  failed_login_attempts INT         NOT NULL DEFAULT 0,
  locked_until          TIMESTAMPTZ,
  is_suspended          BOOLEAN     NOT NULL DEFAULT FALSE,
  deleted_at            TIMESTAMPTZ
);

-- Unique username (case-sensitive as per CA.3)
CREATE UNIQUE INDEX IF NOT EXISTS users_username_idx ON users (username);

-- Case-insensitive unique email (CA.7)
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (LOWER(email));

-- TABLA 2: User Preferences
CREATE TABLE IF NOT EXISTS user_preferences (
  id                        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                   UUID        NOT NULL UNIQUE,
  search_radius_km          INT         NOT NULL DEFAULT 25,
  search_radius_min         INT         NOT NULL DEFAULT 1,
  search_radius_max         INT         NOT NULL DEFAULT 50,
  location_update_frequency VARCHAR(50) NOT NULL DEFAULT 'weekly',
  created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_user_preferences_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS user_preferences_user_id_idx ON user_preferences (user_id);

-- TABLA 3: User Profiles
CREATE TABLE IF NOT EXISTS user_profiles (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL UNIQUE,
  biography   TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_user_profiles_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS user_profiles_user_id_idx ON user_profiles (user_id);
