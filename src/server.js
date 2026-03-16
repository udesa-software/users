require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { env } = require('./config/env');
const { pool } = require('./config/database');
const app = require('./app');

async function runMigrations() {
  const migrationPath = path.join(__dirname, '..', 'src', 'db', 'migrations', '001_create_users.sql');
  const sql = fs.readFileSync(migrationPath, 'utf-8');
  await pool.query(sql);
  console.log('Migrations applied.');
}

async function start() {
  await runMigrations();

  const port = parseInt(env.PORT, 10);
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
