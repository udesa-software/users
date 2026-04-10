const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { userRepository } = require('../users/user.repository');
const { sendResetPasswordEmail, sendPasswordChangedEmail, sendVerificationEmail } = require('../../config/mailer');
const { AppError } = require('../../middlewares/errorHandler');
const { env } = require('../../config/env');

const TOKEN_EXPIRY_HOURS = 24;

function tokenExpiresAt() {
  const date = new Date();
  date.setHours(date.getHours() + TOKEN_EXPIRY_HOURS);
  return date;
}
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const authService = {
  async login({ identifier, password }) {
    // CA.3: support email or username
    let user = null;
    if (identifier.includes('@')) {
      user = await userRepository.findByEmail(identifier.toLowerCase());
    } else {
      user = await userRepository.findByUsername(identifier.toLowerCase());
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
      throw new AppError(423, `Cuenta bloqueada temporalmente. Intentá de nuevo en ${Math.ceil((user.locked_until - new Date()) / 60000)} minutos.`);
    }

    // CA.4: email no verificado
    if (!user.is_verified) {
      throw new AppError(403, 'Debés verificar tu email antes de iniciar sesión. Revisá tu casilla de correo.');
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      // CA.2: incrementa el contador; si llega a 5 se bloquea automáticamente en la DB
      await userRepository.incrementFailedAttempts(user.id, 5);
      throw new AppError(401, 'Credenciales inválidas');
    }

    // Login exitoso: resetea el contador de intentos fallidos
    await userRepository.resetFailedAttempts(user.id);

    // CA.1: access token JWT (corta duración)
    const accessToken = jwt.sign(
      { sub: user.id, username: user.username, email: user.email, token_version: user.token_version, type: 'access' },
      env.JWT_SECRET,
      { expiresIn: env.ACCESS_TOKEN_EXPIRES_IN }
    );

    // Refresh token opaco (UUID) guardado en BD
    const refreshToken = uuidv4();
    const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
    await userRepository.createRefreshToken(user.id, refreshToken, refreshExpiresAt);

    return {
      accessToken,
      refreshToken,
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
      user = await userRepository.findByUsername(identifier.toLowerCase());
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

    // CA.5: hash new password, clear token, increment token_version (CA.7)
    const newPasswordHash = await bcrypt.hash(password, 12);
    await userRepository.updatePasswordAndInvalidateResetToken(user.id, newPasswordHash);
    // CA.7: revocar todas las sesiones activas (H5)
    await userRepository.deleteAllRefreshTokensForUser(user.id);

    return { message: 'Tu contraseña ha sido actualizada con éxito. Por favor, iniciá sesión de nuevo.' };
  },

  async refreshToken(currentRefreshToken) {
    const newRefreshToken = uuidv4();
    const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

    // Rotación atómica en transacción: invalida el token viejo y crea el nuevo en un solo paso.
    // Si dos requests usan el mismo token simultáneamente, solo uno obtiene el user_id.
    const userId = await userRepository.rotateRefreshToken(currentRefreshToken, newRefreshToken, refreshExpiresAt);
    if (!userId) {
      throw new AppError(401, 'Refresh token inválido o expirado');
    }

    const user = await userRepository.findById(userId);
    if (!user) {
      throw new AppError(401, 'Sesión revocada. Por favor, iniciá sesión de nuevo.');
    }

    if (user.deleted_at || user.is_suspended) {
      throw new AppError(403, 'Cuenta suspendida');
    }

    const accessToken = jwt.sign(
      { sub: user.id, username: user.username, email: user.email, token_version: user.token_version, type: 'access' },
      env.JWT_SECRET,
      { expiresIn: env.ACCESS_TOKEN_EXPIRES_IN }
    );

    return { accessToken, newRefreshToken };
  },

  async logout(userId, refreshToken = null) {
    if (refreshToken) {
      await userRepository.deleteRefreshToken(refreshToken);
    }
    // Invalida el access token actual inmediatamente (H3 CA.1)
    await userRepository.incrementTokenVersion(userId);
    return { message: 'Sesión cerrada exitosamente.' };
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
      token,
    };
  },

  async changePassword(userId, { currentPassword, newPassword }) {
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new AppError(404, 'Usuario no encontrado');
    }

    // CA.4: Check lockout
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      throw new AppError(423, `Cuenta bloqueada temporalmente. Intentá de nuevo en ${Math.ceil((user.locked_until - new Date()) / 60000)} minutos.`);
    }

    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!passwordMatch) {
      // CA.4: 3 failed attempts for change password
      await userRepository.incrementFailedAttempts(user.id, 3);
      throw new AppError(401, 'La contraseña actual es incorrecta');
    }

    // CA.2: new password cannot be the same as current
    const isSamePassword = await bcrypt.compare(newPassword, user.password_hash);
    if (isSamePassword) {
      throw new AppError(400, 'La nueva contraseña no puede ser igual a la anterior');
    }

    // Success: update password (token_version++), reset attempts, revocar todas las sesiones
    const newPasswordHash = await bcrypt.hash(newPassword, 12);
    await userRepository.updatePasswordAndInvalidateResetToken(user.id, newPasswordHash);
    await userRepository.deleteAllRefreshTokensForUser(user.id);
    await userRepository.resetFailedAttempts(user.id);

    // CA.5: Send email notification
    sendPasswordChangedEmail(user.email).catch((err) =>
      console.error('Failed to send password changed email:', err)
    );

    return { message: 'Tu contraseña ha sido cambiada con éxito. Por seguridad, se han cerrado todas tus sesiones activas.' };
  },

  async verifyEmail(token) {
    if (!token) {
      throw new AppError(400, 'Token requerido');
    }
    // CA.6: token must exist and not be expired
    const user = await userRepository.findByVerifyToken(token);
    if (!user) {
      throw new AppError(400, 'El token es inválido o ha expirado');
    }

    await userRepository.markVerified(user.id);
  },

  async resendVerification(email) {
    const user = await userRepository.findByEmail(email.toLowerCase());
    if (!user) {
      throw new AppError(404, 'No existe una cuenta con ese email');
    }

    if (user.is_verified) {
      throw new AppError(400, 'La cuenta ya fue verificada');
    }

    // CA.6: fresh token with new 24h window
    const newToken = uuidv4();
    const newExpiresAt = tokenExpiresAt();

    await userRepository.updateVerifyToken(user.id, newToken, newExpiresAt);

    sendVerificationEmail(email.toLowerCase(), newToken).catch((err) =>
      console.error('Failed to resend verification email:', err)
    );
  },
};

module.exports = { authService };
