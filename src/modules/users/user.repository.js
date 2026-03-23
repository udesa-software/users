const { query } = require('../../config/database');

const userRepository = {
  // CA.7: lookup uses LOWER() for case-insensitive comparison
  async findByEmail(email) {
    const result = await query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    return result.rows[0] ?? null;
  },

  async findById(id) {
    const result = await query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );
    return result.rows[0] ?? null;
  },

  async findByUsername(username) {
    const result = await query(
      'SELECT * FROM users WHERE LOWER(username) = LOWER($1)',
      [username]
    );
    return result.rows[0] ?? null;
  },

  // Only returns unexpired tokens (CA.6)
  async findByVerifyToken(token) {
    const result = await query(
      'SELECT * FROM users WHERE verify_token = $1 AND token_expires_at > NOW()',
      [token]
    );
    return result.rows[0] ?? null;
  },

  async findByPasswordResetToken(token) {
    const result = await query(
      'SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_expires_at > NOW()',
      [token]
    );
    return result.rows[0] ?? null;
  },

  async create({ username, email, passwordHash, verifyToken, tokenExpiresAt, acceptedTerms, acceptedTermsAt }) {
    const result = await query(
      `INSERT INTO users (username, email, password_hash, verify_token, token_expires_at, accepted_terms, accepted_terms_at)
       VALUES (LOWER($1), LOWER($2), $3, $4, $5, $6, $7)
       RETURNING id, username, email, is_verified, created_at, accepted_terms, accepted_terms_at`,
      [username, email, passwordHash, verifyToken, tokenExpiresAt, acceptedTerms, acceptedTermsAt]
    );
    return result.rows[0];
  },

  async updateVerifyToken(userId, token, expiresAt) {
    await query(
      `UPDATE users SET verify_token = $1, token_expires_at = $2, updated_at = NOW()
       WHERE id = $3`,
      [token, expiresAt, userId]
    );
  },

  async markVerified(userId) {
    await query(
      `UPDATE users
       SET is_verified = TRUE, verify_token = NULL, token_expires_at = NULL, updated_at = NOW()
       WHERE id = $1`,
      [userId]
    );
  },

  async updatePasswordResetToken(userId, token, expiresAt) {
    await query(
      `UPDATE users
       SET password_reset_token = $1, password_reset_expires_at = $2, updated_at = NOW()
       WHERE id = $3`,
      [token, expiresAt, userId]
    );
  },

  async updateLastResetRequest(userId) {
    await query(
      `UPDATE users SET last_reset_request_at = NOW(), updated_at = NOW() WHERE id = $1`,
      [userId]
    );
  },

  async updatePasswordAndInvalidateResetToken(userId, passwordHash) {
    await query(
      `UPDATE users
       SET password_hash = $1, password_reset_token = NULL, password_reset_expires_at = NULL,
           token_version = token_version + 1, updated_at = NOW()
       WHERE id = $2`,
      [passwordHash, userId]
    );
  },

  async incrementTokenVersion(userId) {
    await query(
      `UPDATE users SET token_version = token_version + 1, updated_at = NOW() WHERE id = $1`,
      [userId]
    );
  },

  async markDeleted(userId) {
    await query(
      `UPDATE users
       SET deleted_at = NOW()
       WHERE id = $1`,
      [userId]
    );
  },

  // CA.2: incrementa el contador de intentos fallidos y bloquea si llega al threshold
  async incrementFailedAttempts(userId) {
    await query(
      `UPDATE users
       SET failed_login_attempts = failed_login_attempts + 1,
           locked_until = CASE
             WHEN failed_login_attempts + 1 >= $1 THEN NOW() + INTERVAL '15 minutes'
             ELSE locked_until
           END,
           updated_at = NOW()
       WHERE id = $2`,
      [threshold, userId]
    );
  },

  // CA.2: resetea el contador al iniciar sesión correctamente
  async resetFailedAttempts(userId) {
    await query(
      `UPDATE users
       SET failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
       WHERE id = $1`,
      [userId]
    );
  },
};

module.exports = { userRepository };
