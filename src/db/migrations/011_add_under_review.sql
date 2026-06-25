-- H9 (friends): estado temporal "En revisión" cuando un usuario acumula más de 5 denuncias
ALTER TABLE users ADD COLUMN IF NOT EXISTS under_review BOOLEAN NOT NULL DEFAULT FALSE;
