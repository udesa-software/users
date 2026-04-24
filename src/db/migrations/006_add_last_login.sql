-- H9 CA.1: registrar fecha y hora de la última sesión iniciada exitosamente
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
