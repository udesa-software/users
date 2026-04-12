const { env } = require('../../config/env');

module.exports = async function createApiUser(pool) {
  // Si DB_ADMIN_USER no está definido, la app ya corre como el único usuario 
  // esto es para q sea compatible con lo anterior pero quizas lo podemos borrar despues
  if (!env.DB_ADMIN_USER) return;

  const apiUser = env.DB_USER;
  const apiPassword = env.DB_PASSWORD;

  const { rows } = await pool.query(
    `SELECT 1 FROM pg_roles WHERE rolname = $1`,
    [apiUser]
  );

  if (rows.length === 0) {
    await pool.query(`CREATE USER "${apiUser}" WITH PASSWORD '${apiPassword}'`);
    console.log(`Usuario de base de datos creado: ${apiUser}`);
  }

  // Poner permisos al usuario
  await pool.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "${apiUser}"`);
  await pool.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${apiUser}"`); // por si en el uturo se crean mas migraciones
  await pool.query(`GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO "${apiUser}"`);
  await pool.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO "${apiUser}"`);
};
