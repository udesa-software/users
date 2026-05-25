-- H9 CA.2: columna para marcar cuentas en revisión por reportes de otros usuarios.
-- Se diferencia de is_suspended (acción de admin) para facilitar el flujo de moderación.
ALTER TABLE users ADD COLUMN IF NOT EXISTS under_review BOOLEAN NOT NULL DEFAULT FALSE;
