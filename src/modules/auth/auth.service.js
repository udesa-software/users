const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { userRepository } = require('../users/user.repository');
const { AppError } = require('../../middlewares/errorHandler');
const { env } = require('../../config/env');

const authService = {
  async login({ email, password }) {
    const user = await userRepository.findByEmail(email.toLowerCase());

    // CA.3: mismo mensaje genérico para "no existe" y "contraseña incorrecta"
    if (!user) {
      throw new AppError(401, 'Credenciales inválidas');
    }

    // CA.5: cuenta eliminada (soft-delete) o suspendida por admin
    if (user.deleted_at || user.is_suspended) {
      throw new AppError(403, 'Cuenta suspendida');
    }

    // CA.2: cuenta bloqueada por demasiados intentos fallidos
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      throw new AppError(423, 'Cuenta bloqueada temporalmente. Intentá de nuevo en 15 minutos.');
    }

    // CA.4: email no verificado
    if (!user.is_verified) {
      throw new AppError(403, 'Debés verificar tu email antes de iniciar sesión. Revisá tu casilla de correo.');
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      // CA.2: incrementa el contador; si llega a 5 se bloquea automáticamente en la DB
      await userRepository.incrementFailedAttempts(user.id);
      throw new AppError(401, 'Credenciales inválidas');
    }

    // Login exitoso: resetea el contador de intentos fallidos
    await userRepository.resetFailedAttempts(user.id);

    // CA.1: genera JWT con expiración definida
    const token = jwt.sign(
      { sub: user.id, username: user.username, email: user.email },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN }
    );

    return {
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        is_verified: user.is_verified,
        created_at: user.created_at,
      },
    };
  },
};

module.exports = { authService };
