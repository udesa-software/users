const jwt = require('jsonwebtoken');
const { env } = require('../config/env');
const { AppError } = require('./errorHandler');

async function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return next(new AppError(401, 'Token de autenticación requerido'));
  }

  try {
    const payload = jwt.verify(token, env.JWT_SECRET);
    
    // CA.7: Verify session is not revoked (token_version must match)
    const { pool } = require('../config/database');
    const result = await pool.query('SELECT token_version FROM users WHERE id = $1', [payload.sub]);
    const user = result.rows[0];

    if (!user || user.token_version !== payload.token_version) {
      return next(new AppError(401, 'Sesión expirada o revocada. Por favor, iniciá sesión de nuevo.'));
    }

    req.user = payload;
    next();
  } catch {
    next(new AppError(401, 'Token inválido o expirado'));
  }
}

module.exports = { authenticate };
