const { Pool } = require('pg');
const { env } = require('./env');

// Pool privilegiado para migraciones (CREATE TABLE, GRANT, etc.)
const migrationPool = new Pool({
  host: env.DB_HOST,
  port: parseInt(env.DB_PORT, 10),
  database: env.DB_NAME,
  user: env.DB_ADMIN_USER || env.DB_USER,
  password: env.DB_ADMIN_PASSWORD || env.DB_PASSWORD,
});

// Pool de la app con privilegios limitados (SELECT, INSERT, UPDATE, DELETE)
const pool = new Pool({
  host: env.DB_HOST,
  port: parseInt(env.DB_PORT, 10),
  database: env.DB_NAME,
  user: env.DB_USER,
  password: env.DB_PASSWORD,
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
