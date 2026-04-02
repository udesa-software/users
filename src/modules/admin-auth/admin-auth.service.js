const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { adminRepository } = require('../admins/admin.repository');
const { sendPasswordChangedEmail } = require('../../config/mailer');
const { AppError } = require('../../middlewares/errorHandler');
const { env } = require('../../config/env');

// H2 CA.3: 3 intentos fallidos → 30 minutos de bloqueo
const LOGIN_MAX_ATTEMPTS = 3;

const adminAuthService = {
  // H2: Login de administrador
  async login({ email, password }) {
    const admin = await adminRepository.findByEmail(email.toLowerCase());

    if (!admin) {
      throw new AppError(401, 'Credenciales inválidas');
    }

    // H2 CA.3: verificar bloqueo por intentos fallidos
    if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
      const mins = Math.ceil((new Date(admin.locked_until) - new Date()) / 60000);
      throw new AppError(423, `Cuenta bloqueada temporalmente. Intentá de nuevo en ${mins} minutos.`);
    }

    const passwordMatch = await bcrypt.compare(password, admin.password_hash);
    if (!passwordMatch) {
      await adminRepository.incrementFailedAttempts(admin.id, LOGIN_MAX_ATTEMPTS);
      throw new AppError(401, 'Credenciales inválidas');
    }

    // H1 CA.3: contraseña temporal expirada → no dejar entrar
    if (admin.must_change_password && admin.temp_password_expires_at) {
      if (new Date(admin.temp_password_expires_at) < new Date()) {
        throw new AppError(403, 'Tu contraseña temporal expiró. Contactá al SuperAdmin para obtener una nueva.');
      }
    }

    await adminRepository.resetFailedAttempts(admin.id);

    // H2 CA.1: JWT con rol incluido
    const token = jwt.sign(
      {
        sub: admin.id,
        email: admin.email,
        role: admin.role,
        token_version: admin.token_version,
        must_change_password: admin.must_change_password,
      },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN }
    );

    return {
      token,
      admin: {
        id: admin.id,
        email: admin.email,
        role: admin.role,
        must_change_password: admin.must_change_password,
      },
    };
  },

  async logout(adminId) {
    await adminRepository.incrementTokenVersion(adminId);
    return { message: 'Sesión cerrada exitosamente.' };
  },

  // H1 CA.1: cambio de contraseña forzado en primer login
  async changePassword(adminId, { currentPassword, newPassword }) {
    const admin = await adminRepository.findById(adminId);
    if (!admin) {
      throw new AppError(404, 'Administrador no encontrado');
    }

    const passwordMatch = await bcrypt.compare(currentPassword, admin.password_hash);
    if (!passwordMatch) {
      throw new AppError(401, 'La contraseña actual es incorrecta');
    }

    const isSamePassword = await bcrypt.compare(newPassword, admin.password_hash);
    if (isSamePassword) {
      throw new AppError(400, 'La nueva contraseña no puede ser igual a la anterior');
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 12);
    await adminRepository.updatePassword(adminId, newPasswordHash);

    sendPasswordChangedEmail(admin.email).catch((err) =>
      console.error('Failed to send password changed email:', err)
    );

    return { message: 'Contraseña actualizada exitosamente. Por favor, iniciá sesión de nuevo.' };
  },
};

module.exports = { adminAuthService };
