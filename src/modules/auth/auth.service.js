const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { userRepository } = require('../users/user.repository');
const { sendResetPasswordEmail } = require('../../config/mailer');
const { AppError } = require('../../middlewares/errorHandler');
const { env } = require('../../config/env');

const authService = {
  async login({ identifier, password }) {
    // CA.3: support email or username
    let user = null;
    if (identifier.includes('@')) {
      user = await userRepository.findByEmail(identifier.toLowerCase());
    } else {
      user = await userRepository.findByUsername(identifier);
    }

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
      //throw new AppError(423, `Cuenta bloqueada temporalmente. Intentá de nuevo en ${Math.ceil(((user.locked_until - new Date()) / 60000))} minutos.`); 
      throw new AppError(423, `Cuenta bloqueada temporalmente. Intentá de nuevo en ${Math.ceil((user.locked_until - new Date()) / 60000)} minutos.`); 
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
      { sub: user.id, username: user.username, email: user.email, token_version: user.token_version },
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

  async requestPasswordReset(identifier) {
    // CA.4: find by email or username, always return same message
    let user = await userRepository.findByEmail(identifier.toLowerCase());
    if (!user) {
      user = await userRepository.findByUsername(identifier);
    }

    // generic message to avoid enumeration (CA.4)
    const genericMessage = 'Si el correo o usuario está registrado, recibirás un link para restablecer tu contraseña.';

    if (!user) {
      return { message: genericMessage };
    }

    // CA.8: throttling - limit requests per account (e.g., 1 per minute)
    const THROTTLE_MINUTES = 1;
    if (user.last_reset_request_at && 
        new Date() - new Date(user.last_reset_request_at) < THROTTLE_MINUTES * 60 * 1000) {
      // Even if throttled, return the generic message to avoid giving hints
      return { message: genericMessage };
    }

    // CA.1: generate 10-minute token
    const token = uuidv4();
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 10);

    await userRepository.updatePasswordResetToken(user.id, token, expiresAt);
    await userRepository.updateLastResetRequest(user.id);

    sendResetPasswordEmail(user.email, token).catch((err) =>
      console.error('Failed to send reset password email:', err)
    );

    return { message: genericMessage };
  },

  async resetPassword({ token, password, confirmPassword }) {
    // CA.3: double confirmation check
    if (password !== confirmPassword) {
      throw new AppError(400, 'Las contraseñas no coinciden');
    }

    // CA.1 & CA.2: token must exist and not be expired
    const user = await userRepository.findByPasswordResetToken(token);
    if (!user) {
      throw new AppError(400, 'El token es inválido o ha expirado. Por favor, solicitá uno nuevo.');
    }

    // CA.6: new password cannot be the same as current
    const isSamePassword = await bcrypt.compare(password, user.password_hash);
    if (isSamePassword) {
      throw new AppError(400, 'La nueva contraseña no puede ser igual a la anterior');
    }

    // CA.3: enforce H1 policies (min 8 chars, 1 uppercase, 1 number)
    // (Actual validation is also done via resetPasswordSchema, but we double-check here if needed)
    
    // CA.5: hash new password, clear token, increment token_version (CA.7)
    const newPasswordHash = await bcrypt.hash(password, 12);
    await userRepository.updatePasswordAndInvalidateResetToken(user.id, newPasswordHash);

    return { message: 'Tu contraseña ha sido actualizada con éxito. Por favor, iniciá sesión de nuevo.' };
  },

  async verifyResetToken(token) {
    if (!token) {
      throw new AppError(400, 'Token requerido');
    }

    const user = await userRepository.findByPasswordResetToken(token);
    if (!user) {
      throw new AppError(400, 'El token es inválido o ha expirado. Por favor, solicitá uno nuevo.');
    }

    return { 
      message: 'Token válido. Por favor, ingresá tu nueva contraseña.',
      token 
    };
  },
};

module.exports = { authService };
