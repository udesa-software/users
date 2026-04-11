const bcrypt = require('bcryptjs');
const { env } = require('../../config/env');

module.exports = async function seedSuperAdmin(pool) {
  if (!env.INITIAL_SUPERADMIN_EMAIL || !env.INITIAL_SUPERADMIN_TEMP_PASSWORD) return;

  const { rows } = await pool.query('SELECT COUNT(*) FROM admins');
  if (parseInt(rows[0].count, 10) > 0) return;

  const passwordHash = await bcrypt.hash(env.INITIAL_SUPERADMIN_TEMP_PASSWORD, 12);
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + 24);

  await pool.query(
    `INSERT INTO admins (email, password_hash, role, must_change_password, temp_password_expires_at)
     VALUES (LOWER($1), $2, 'superadmin', TRUE, $3)`,
    [env.INITIAL_SUPERADMIN_EMAIL, passwordHash, expiresAt]
  );

  console.log(`SuperAdmin inicial creado: ${env.INITIAL_SUPERADMIN_EMAIL}`);
};
