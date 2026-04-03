CREATE TABLE IF NOT EXISTS admins (
  id                       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  email                    VARCHAR(255) NOT NULL,
  password_hash            VARCHAR(255) NOT NULL,
  role                     VARCHAR(20)  NOT NULL DEFAULT 'moderator', -- 'superadmin' | 'moderator'
  must_change_password     BOOLEAN      NOT NULL DEFAULT TRUE,
  temp_password_expires_at TIMESTAMPTZ,
  failed_login_attempts    INT          NOT NULL DEFAULT 0,
  locked_until             TIMESTAMPTZ,
  token_version            INT          NOT NULL DEFAULT 1,
  created_by               UUID         REFERENCES admins(id) ON DELETE SET NULL,
  created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS admins_email_lower_idx ON admins (LOWER(email));
