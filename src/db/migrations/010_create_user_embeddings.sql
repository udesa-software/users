CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS user_embeddings (
  user_id    UUID         PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  bio_hash   TEXT         NOT NULL,
  embedding  vector(768)  NOT NULL,
  updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_embeddings_embedding_hnsw
  ON user_embeddings
  USING hnsw (embedding vector_cosine_ops);
