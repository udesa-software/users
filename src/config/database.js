const { Pool } = require('pg');
const { env } = require('./env');

const SSL_CONFIG = { rejectUnauthorized: false };

// Pool privilegiado para migraciones (CREATE TABLE, etc.)
// En Supabase se usa el mismo usuario para todo
const migrationPool = new Pool({
  host: env.DB_HOST,
  port: parseInt(env.DB_PORT, 10),
  database: env.DB_NAME,
  user: env.DB_USER,
  password: env.DB_PASSWORD,
  ssl: SSL_CONFIG,
});

// Pool de la app (SELECT, INSERT, UPDATE, DELETE)
const pool = new Pool({
  host: env.DB_HOST,
  port: parseInt(env.DB_PORT, 10),
  database: env.DB_NAME,
  user: env.DB_USER,
  password: env.DB_PASSWORD,
  ssl: SSL_CONFIG,
});

async function query(text, params) {
  return pool.query(text, params);
}

// Ejecuta fn(client) dentro de una transacción; hace rollback automático si lanza.
async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, migrationPool, query, withTransaction };
