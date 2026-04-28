const { userRepository } = require('./user.repository');
const { redisClient } = require('../../config/redis');
const { AppError } = require('../../middlewares/errorHandler');

const REVOKED_TTL_SEC = 15 * 60;

const internalController = {
  // H4: listado de usuarios con búsqueda parcial y paginación
  async listUsers(req, res, next) {
    try {
      const { search = '', page = '1', limit = '20' } = req.query;
      const result = await userRepository.searchUsers({
        search,
        page: parseInt(page, 10),
        limit: Math.min(parseInt(limit, 10), 100),
      });
      res.json(result);
    } catch (err) {
      next(err);
    }
  },

  // H4 CA.1: detalle completo de un usuario
  async getUser(req, res, next) {
    try {
      const user = await userRepository.getUserDetail(req.params.id);
      if (!user) throw new AppError(404, 'Usuario no encontrado');
      res.json(user);
    } catch (err) {
      next(err);
    }
  },

  // H5: suspender usuario — invalida la sesión activa inmediatamente (CA.2)
  async suspendUser(req, res, next) {
    try {
      const { id } = req.params;
      const user = await userRepository.findById(id);
      if (!user) throw new AppError(404, 'Usuario no encontrado');
      if (user.is_suspended) throw new AppError(400, 'El usuario ya está suspendido');

      const { token_version } = await userRepository.suspendUser(id);
      await userRepository.deleteAllRefreshTokensForUser(id);

      // Publica la revocación en Redis para que el gateway invalide el AT activo
      redisClient.set(`revoked:${id}`, token_version, 'EX', REVOKED_TTL_SEC)
        .catch((err) => console.error('[Redis] suspend revocation failed:', err));

      res.json({ message: 'Usuario suspendido. Su sesión fue invalidada.' });
    } catch (err) {
      next(err);
    }
  },

  // H5: levantar suspensión
  async unsuspendUser(req, res, next) {
    try {
      const { id } = req.params;
      const user = await userRepository.findById(id);
      if (!user) throw new AppError(404, 'Usuario no encontrado');
      if (!user.is_suspended) throw new AppError(400, 'El usuario no está suspendido');

      await userRepository.unsuspendUser(id);
      res.json({ message: 'Suspensión levantada. El usuario puede volver a iniciar sesión.' });
    } catch (err) {
      next(err);
    }
  },

  // H5-friends: devuelve username de un batch de userIds (para el radar de descubrimiento en location)
  async getBatchProfiles(req, res, next) {
    try {
      const { userIds } = req.body;
      if (!Array.isArray(userIds)) {
        throw new AppError(400, 'userIds debe ser un array');
      }
      const users = await userRepository.findProfilesByIds(userIds);
      res.json({ users });
    } catch (err) {
      next(err);
    }
  },

  // H3: métricas para el dashboard del backoffice
  async getMetrics(req, res, next) {
    try {
      const metrics = await userRepository.getMetrics();
      res.json(metrics);
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { internalController };
