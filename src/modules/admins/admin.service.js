const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { adminRepository } = require('./admin.repository');
const { sendTempPasswordEmail } = require('../../config/mailer');
const { AppError } = require('../../middlewares/errorHandler');
const { env } = require('../../config/env');

const TEMP_PASSWORD_EXPIRY_HOURS = 24;

function tempPasswordExpiresAt() {
  const date = new Date();
  date.setHours(date.getHours() + TEMP_PASSWORD_EXPIRY_HOURS);
  return date;
}

function generateTempPassword() {
  return uuidv4().replace(/-/g, '').slice(0, 10);
}

const adminService = {
  // H1: SuperAdmin crea un nuevo administrador
  async createAdmin({ email, role }, createdById) {
    // CA.4: validar dominio de email si está configurado
    if (env.ALLOWED_EMAIL_DOMAIN) {
      if (!email.toLowerCase().endsWith(`@${env.ALLOWED_EMAIL_DOMAIN}`)) {
        throw new AppError(400, `El email debe pertenecer al dominio @${env.ALLOWED_EMAIL_DOMAIN}`);
      }
    }

    const existing = await adminRepository.findByEmail(email);
    if (existing) {
      throw new AppError(409, 'Ya existe un administrador con ese email');
    }

    // CA.1: contraseña temporal + forzar cambio en primer login
    const tempPassword = generateTempPassword();
    const passwordHash = await bcrypt.hash(tempPassword, 12);
    const expiresAt = tempPasswordExpiresAt();

    const admin = await adminRepository.create({
      email,
      passwordHash,
      role,
      tempPasswordExpiresAt: expiresAt,
      createdBy: createdById,
    });

    sendTempPasswordEmail(email, tempPassword).catch((err) =>
      console.error('Failed to send temp password email:', err)
    );

    return {
      ...admin,
      temp_password: tempPassword,
      temp_password_expires_at: expiresAt,
    };
  },

  // H1 CA.3: SuperAdmin regenera contraseña temporal expirada
  async resetAdminPassword(targetAdminId, requestingAdminId) {
    const admin = await adminRepository.findById(targetAdminId);
    if (!admin) {
      throw new AppError(404, 'Administrador no encontrado');
    }

    if (targetAdminId === requestingAdminId) {
      throw new AppError(400, 'Usá el endpoint de cambio de contraseña para tu propia cuenta');
    }

    const tempPassword = generateTempPassword();
    const passwordHash = await bcrypt.hash(tempPassword, 12);
    const expiresAt = tempPasswordExpiresAt();

    await adminRepository.updateTempPassword(targetAdminId, passwordHash, expiresAt);

    sendTempPasswordEmail(admin.email, tempPassword).catch((err) =>
      console.error('Failed to send temp password email:', err)
    );

    return {
      message: 'Contraseña temporal regenerada exitosamente.',
      temp_password: tempPassword,
      temp_password_expires_at: expiresAt,
    };
  },
};

module.exports = { adminService };
