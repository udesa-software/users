const { query, withTransaction } = require('../../config/database');
const { hashToken } = require('../../utils/tokenHash');

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

  async createRefreshToken(adminId, token, expiresAt) {
    await query(
      `INSERT INTO admin_refresh_tokens (admin_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [adminId, hashToken(token), expiresAt]
    );
  },

  async rotateRefreshToken(oldToken, newToken, expiresAt) {
    const oldHash = hashToken(oldToken);
    const newHash = hashToken(newToken);

    return withTransaction(async (client) => {
      const { rows } = await client.query(
        `DELETE FROM admin_refresh_tokens WHERE token_hash = $1 AND expires_at > NOW() RETURNING admin_id`,
        [oldHash]
      );

      if (rows.length === 0) return null;

      const { admin_id } = rows[0];
      await client.query(
        `INSERT INTO admin_refresh_tokens (admin_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
        [admin_id, newHash, expiresAt]
      );

      return admin_id;
    });
  },

  async deleteRefreshToken(token) {
    await query(`DELETE FROM admin_refresh_tokens WHERE token_hash = $1`, [hashToken(token)]);
  },

  async deleteAllRefreshTokensForAdmin(adminId) {
    await query(`DELETE FROM admin_refresh_tokens WHERE admin_id = $1`, [adminId]);
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
