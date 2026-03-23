const jwt = require('jsonwebtoken');
const { env } = require('../config/env');
const { AppError } = require('./errorHandler');
const { userRepository } = require('../modules/users/user.repository');

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
    const user = await userRepository.findById(payload.sub);

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
