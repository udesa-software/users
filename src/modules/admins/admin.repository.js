const { query } = require('../../config/database');

const adminRepository = {
  async findByEmail(email) {
    const result = await query(
      'SELECT * FROM admins WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    return result.rows[0] ?? null;
  },

  async findById(id) {
    const result = await query(
      'SELECT * FROM admins WHERE id = $1',
      [id]
    );
    return result.rows[0] ?? null;
  },

  async create({ email, passwordHash, role, tempPasswordExpiresAt, createdBy }) {
    const result = await query(
      `INSERT INTO admins (email, password_hash, role, must_change_password, temp_password_expires_at, created_by)
       VALUES (LOWER($1), $2, $3, TRUE, $4, $5)
       RETURNING id, email, role, must_change_password, created_at`,
      [email, passwordHash, role, tempPasswordExpiresAt, createdBy ?? null]
    );
    return result.rows[0];
  },

  async incrementFailedAttempts(adminId, threshold) {
    await query(
      `UPDATE admins
       SET failed_login_attempts = failed_login_attempts + 1,
           locked_until = CASE
             WHEN failed_login_attempts + 1 >= $1 THEN NOW() + INTERVAL '30 minutes'
             ELSE locked_until
           END,
           updated_at = NOW()
       WHERE id = $2`,
      [threshold, adminId]
    );
  },

  async resetFailedAttempts(adminId) {
    await query(
      `UPDATE admins
       SET failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
       WHERE id = $1`,
      [adminId]
    );
  },

  async incrementTokenVersion(adminId) {
    await query(
      `UPDATE admins SET token_version = token_version + 1, updated_at = NOW() WHERE id = $1`,
      [adminId]
    );
  },

  async updatePassword(adminId, passwordHash) {
    await query(
      `UPDATE admins
       SET password_hash = $1,
           must_change_password = FALSE,
           temp_password_expires_at = NULL,
           token_version = token_version + 1,
           updated_at = NOW()
       WHERE id = $2`,
      [passwordHash, adminId]
    );
  },

  async updateTempPassword(adminId, passwordHash, expiresAt) {
    await query(
      `UPDATE admins
       SET password_hash = $1,
           must_change_password = TRUE,
           temp_password_expires_at = $2,
           token_version = token_version + 1,
           updated_at = NOW()
       WHERE id = $3`,
      [passwordHash, expiresAt, adminId]
    );
  },
};

module.exports = { adminRepository };
