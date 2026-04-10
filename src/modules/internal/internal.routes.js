const { Router } = require('express');
const jwt = require('jsonwebtoken');
const { env } = require('../../config/env');
const { userRepository } = require('../users/user.repository');
const { authenticateInternal } = require('../../middlewares/authenticateInternal');

const router = Router();

// GET /api/internal/validate-token
// Llamado por el gateway para verificar que el JWT no fue revocado (token_version)
// Requiere: Authorization: Bearer <jwt>  +  x-internal-secret: <secret>
router.get('/validate-token', authenticateInternal, async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({ error: 'Token requerido' });
    }

    let payload;
    try {
      payload = jwt.verify(token, env.JWT_SECRET);
    } catch {
      return res.status(401).json({ error: 'Token inválido o expirado' });
    }

    const user = await userRepository.findById(payload.sub);
    if (!user || user.token_version !== payload.token_version) {
      return res.status(401).json({ error: 'Sesión revocada' });
    }

    res.json({ valid: true, userId: payload.sub });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
