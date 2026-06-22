-- H9: timestamp de la última vez que un admin resolvió una revisión por denuncias.
-- NULL = nunca fue resuelto -> countDistinctReporters (friends) cuenta todo el historial.
ALTER TABLE users ADD COLUMN IF NOT EXISTS under_review_resolved_at TIMESTAMPTZ;
