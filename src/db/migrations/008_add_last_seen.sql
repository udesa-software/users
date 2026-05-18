-- H10 CA.1: registrar la última vez que el usuario interactuó con la app (heartbeat)
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
