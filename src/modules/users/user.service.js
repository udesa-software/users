const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { userRepository } = require('./user.repository');
const { sendVerificationEmail } = require('../../config/mailer');
const { AppError } = require('../../middlewares/errorHandler');

const TOKEN_EXPIRY_HOURS = 24;

function tokenExpiresAt() {
  const date = new Date();
  date.setHours(date.getHours() + TOKEN_EXPIRY_HOURS);
  return date;
}

const userService = {
  async register(input) {
    // CA.7: normalize email and username to lowercase before any lookup
    const email = input.email.toLowerCase();
    const username = input.username.toLowerCase();

    // CA.2: no duplicate emails (case-insensitive)
    const existingEmail = await userRepository.findByEmail(email);
    if (existingEmail) {
      throw new AppError(409, 'El email ya está registrado');
    }

    // CA.3: no duplicate usernames
    const existingUsername = await userRepository.findByUsername(input.username);
    if (existingUsername) {
      throw new AppError(409, 'El nombre de usuario ya está en uso');
    }

    if (!input.acceptedTerms) {
      throw new AppError(400, 'Se deben leer y aceptar los Términos y Condiciones y la Política de Privacidad');
    }

    // CA.4: hash password
    const passwordHash = await bcrypt.hash(input.password, 12);

    // CA.6: generate token with expiry
    const verifyToken = uuidv4();
    const expiresAt = tokenExpiresAt();

    const acceptedTermsAt = new Date();

    const user = await userRepository.create({
      username,
      email,
      passwordHash,
      verifyToken,
      tokenExpiresAt: expiresAt,
      acceptedTerms: input.acceptedTerms,
      acceptedTermsAt,
    });

    // Send email fire-and-forget (don't block registration on mail failure)
    sendVerificationEmail(email, verifyToken).catch((err) =>
      console.error('Failed to send verification email:', err)
    );

    return user;
  },

  async verifyEmail(token) {
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

  // CA.3: userId viene del JWT (req.user.sub), password es solo la confirmación
  async delete(userId, password) {
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new AppError(404, 'Usuario no encontrado');
    }

    // CA.3: confirmar identidad con contraseña antes de borrar
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      throw new AppError(401, 'Contraseña incorrecta');
    }

    // CA.1: soft-delete — no borra la fila, solo marca deleted_at
    await userRepository.markDeleted(userId);
  },

  async getPreferences(userId) {
    const prefs = await userRepository.getPreferences(userId);
    if (!prefs) {
      throw new AppError(404, 'Preferencias no encontradas');
    }
    return prefs;
  },

  async updatePreferences(userId, updateData) {
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new AppError(404, 'Usuario no encontrado');
    }
    
    const updates = {};

    if (updateData.search_radius_km !== undefined) {
      const updatedPref = await userRepository.updateSearchRadius(userId, updateData.search_radius_km);
      updates.search_radius_km = updatedPref.search_radius_km;
    }

    if (updateData.location_update_frequency !== undefined) {
      const updatedPref = await userRepository.updateLocationFrequency(userId, updateData.location_update_frequency);
      updates.location_update_frequency = updatedPref.location_update_frequency;
    }

    if (Object.keys(updates).length === 0) {
      throw new AppError(400, 'No se enviaron datos para actualizar');
    }

    return updates;
  },

};

module.exports = { userService };
