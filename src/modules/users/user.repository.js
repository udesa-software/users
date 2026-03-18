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

  async findByUsername(username) {
    const result = await query(
      'SELECT * FROM users WHERE username = $1',
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

  async create({ username, email, passwordHash, verifyToken, tokenExpiresAt }) {
    const result = await query(
      `INSERT INTO users (username, email, password_hash, verify_token, token_expires_at)
       VALUES ($1, LOWER($2), $3, $4, $5)
       RETURNING id, username, email, is_verified, created_at`,
      [username, email, passwordHash, verifyToken, tokenExpiresAt]
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

  async markDeleted(userId) {
    await query(
      `UPDATE users
       SET is_deleted = TRUE, updated_at = NOW()
       WHERE id = $1`,
      [userId]
    );
  },
};

module.exports = { userRepository };
