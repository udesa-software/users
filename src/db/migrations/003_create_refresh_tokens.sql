CREATE TABLE user_refresh_tokens (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(64)  NOT NULL UNIQUE, -- SHA-256 hex del token opaco
  expires_at TIMESTAMPTZ  NOT NULL,
  created_at TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX user_refresh_tokens_user_id_idx ON user_refresh_tokens(user_id);

CREATE TABLE admin_refresh_tokens (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id   UUID         NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  token_hash VARCHAR(64)  NOT NULL UNIQUE, -- SHA-256 hex del token opaco
  expires_at TIMESTAMPTZ  NOT NULL,
  created_at TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX admin_refresh_tokens_admin_id_idx ON admin_refresh_tokens(admin_id);
