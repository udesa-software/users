require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { env } = require('./config/env');
const { migrationPool } = require('./config/database');
const app = require('./app');

async function runMigrations() {
  const migrationsDir = path.join(__dirname, 'db', 'migrations');
  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql') || f.endsWith('.js'))
    .sort();

  for (const file of files) {
    const filePath = path.join(migrationsDir, file);

    if (file.endsWith('.sql')) {
      const sql = fs.readFileSync(filePath, 'utf-8');
      await migrationPool.query(sql);
    } else {
      const migration = require(filePath);
      await migration(migrationPool);
    }

    console.log(`Migration applied: ${file}`);
  }
}

async function start() {
  await runMigrations();
  await migrationPool.end();

  const port = parseInt(env.PORT, 10);
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
