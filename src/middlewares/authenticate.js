const jwt = require('jsonwebtoken');
const { env } = require('../config/env');
const { AppError } = require('./errorHandler');
const { redisClient } = require('../config/redis');

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

    // Verificar si el token fue revocado consultando Redis (O(1))
    try {
      const revokedVersion = await redisClient.get(`revoked:${payload.sub}`);
      if (revokedVersion !== null && payload.token_version < parseInt(revokedVersion, 10)) {
        return next(new AppError(401, 'Sesión expirada o revocada. Por favor, iniciá sesión de nuevo.'));
      }
    } catch {
      // Redis no disponible — fail open, el JWT expira en 15 min
    }

    req.user = payload;
    next();
  } catch {
    next(new AppError(401, 'Token inválido o expirado'));
  }
}

module.exports = { authenticate };
