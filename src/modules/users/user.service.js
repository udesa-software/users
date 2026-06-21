const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { userRepository } = require('./user.repository');
const { sendVerificationEmail } = require('../../config/mailer');
const { AppError } = require('../../middlewares/errorHandler');
const { friendsClient } = require('../../clients/friendsClient');
const { aiClient } = require('../../clients/aiClient');
const { notificationsClient } = require('../../clients/notificationsClient');

const { logger } = require('../../observability/logger');

const TOKEN_EXPIRY_HOURS = 24;

function tokenExpiresAt() {
  const date = new Date();
  date.setHours(date.getHours() + TOKEN_EXPIRY_HOURS);
  return date;
}

function isValidMagicNumber(buffer) {
  if (!buffer || buffer.length < 4) return false;
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return true;
  }
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return true;
  }
  return false;
}

const path = require('path');
const Busboy = require('busboy');
const { PassThrough } = require('stream');
const { supabase } = require('../../config/supabase');
const { env } = require('../../config/env');

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
      logger.error({ err: err.message, event: 'user.verification_email_failed', userId: user.id }, 'user.verification_email_failed')
    );

    logger.info({ event: 'user.registered', userId: user.id }, 'user.registered');

    return user;
  },


  // CA.3: userId viene del JWT (req.user.sub), password es solo la confirmación
  async delete(userId, password) {
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new AppError(410, 'Usuario no encontrado');
    }

    // CA.3: confirmar identidad con contraseña antes de borrar
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      throw new AppError(401, 'Contraseña incorrecta');
    }

    // CA.1: soft-delete — no borra la fila, solo marca deleted_at
    await userRepository.markDeleted(userId);

    // CA.2/CA.4: eliminar todas las relaciones de amistad en el servicio friends
    if (process.env.FRIENDS_SERVICE_URL) {
      await friendsClient.deleteUserRelationships(userId);
    }

    // Cleanup: Limpiar token de notificaciones push
    notificationsClient.clearToken(userId);
    logger.info({ event: 'user.deleted', userId }, 'user.deleted');
  },


  async getPreferences(userId) {
    const prefs = await userRepository.getPreferences(userId);
    if (!prefs) {
      throw new AppError(410, 'Preferencias no encontradas');
    }
    return prefs;
  },

  async updatePreferences(userId, updateData) {
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new AppError(410, 'Usuario no encontrado');
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

  async verifyEmail(token) {
    const user = await userRepository.findByVerifyToken(token);
    if (!user) {
      throw new AppError(400, 'Token inválido o expirado');
    }
    await userRepository.markVerified(user.id);
  },

  async resendVerification(email) {
    const normalizedEmail = email.toLowerCase();
    const user = await userRepository.findByEmail(normalizedEmail);
    const genericMessage = 'Si el correo está registrado y aún no fue verificado, recibirás un nuevo email pronto.';

    if (!user || user.is_verified) {
      return { message: genericMessage };
    }
    const newToken = uuidv4();
    const expiresAt = tokenExpiresAt();
    await userRepository.updateVerifyToken(user.id, newToken, expiresAt);
    sendVerificationEmail(normalizedEmail, newToken).catch((err) =>
      logger.error({ err: err.message, event: 'user.verification_email_failed', userId: user.id }, 'user.verification_email_failed')
    );

    return { message: genericMessage };
  },

  async updateProfile(userId, { username, biography }) {
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new AppError(410, 'Usuario no encontrado');
    }

    const updates = {};

    if (username !== undefined) {
      // CA.5: no puede quedar vacío ni ser solo espacios
      const trimmed = username.trim();
      if (trimmed.length === 0) {
        throw new AppError(400, 'El nombre de usuario no puede estar vacío');
      }

      // Verificar que no esté tomado por otro usuario
      const existing = await userRepository.findByUsername(trimmed);
      if (existing && existing.id !== userId) {
        throw new AppError(409, 'El nombre de usuario ya está en uso');
      }

      const updatedUser = await userRepository.updateUsername(userId, trimmed);
      updates.username = updatedUser.username;
    }

    if (biography !== undefined) {
      // CA.4: sanitizar HTML/scripts (eliminar tags)
      const sanitized = biography.replace(/<[^>]*>/g, '').trim();

      const updatedPref = await userRepository.updateBiography(userId, sanitized);
      updates.biography = updatedPref.biography;

      // Pre-compute embedding en ai-service (fire-and-forget: no bloquea la respuesta)
      aiClient.updateBiographyEmbedding(userId, sanitized).catch((err) =>
        console.error('[UserService] Failed to trigger embedding update:', err.message)
      );
    }

    return updates; // CA.6: retorna los nuevos valores para actualizar el estado global
  },

  // H1 E.2: búsqueda de usuarios públicos para la app móvil (no muestra privados)
  async searchUsers(requesterId, { q = '', page = 1, limit = 20 }) {
    return userRepository.searchPublicUsers({
      search: q,
      page: parseInt(page, 10),
      limit: Math.min(parseInt(limit, 10), 50),
      excludeUserId: requesterId,
    });
  },

  async searchUsersPublic(query, excludeId) {
    if (!query) return [];
    const result = await userRepository.searchUsers({
      search: query,
      page: 1,
      limit: 10,
      excludeId,
      onlyActive: true
    });
    return result.users.map(u => ({
      id: u.id,
      username: u.username
    }));
  },

  // H10 CA.1: actualiza la última actividad del usuario
  async heartbeat(userId) {
    const user = await userRepository.getUserDetail(userId);
    if (user && !user.is_private) {
      await userRepository.updateLastSeen(userId);
    }
  },

  // H8 CA.7: procesa la subida en streaming con busboy — los chunks se
  // validan a medida que llegan y se rechazan antes de ocupar RAM si no pasan.
  // Solo el archivo válido y dentro del límite se sube a Supabase Storage.
  async uploadProfilePhoto(userId, req) {
    return new Promise((resolve, reject) => {
      let busboy;
      try {
        busboy = Busboy({
          headers: req.headers,
          limits: { files: 1, fileSize: 5 * 1024 * 1024 }, // CA.2: corta el stream si pasa 5MB
        });
      } catch (err) {
        return reject(new AppError(400, 'Fallo al inicializar parser: ' + err.message));
      }

      let fileEventFired = false;

      busboy.on('file', (name, file, info) => {
        fileEventFired = true;

        // CA.1: validar extensión
        const ext = path.extname(info.filename).toLowerCase();
        if (!['.png', '.jpg', '.jpeg'].includes(ext)) {
          file.resume();
          return reject(new AppError(400, 'Formato inválido. Solo JPG y PNG.'));
        }

        const uniqueFilename = `${userId}-${Date.now()}${ext}`;
        const mimeType = ext === '.png' ? 'image/png' : 'image/jpeg';
        let totalBytes = 0;
        let magicChecked = false;
        let validationError = null;

        // Create a PassThrough stream to pipe to Supabase
        const passThrough = new PassThrough();
        // Evitar unhandled 'error' event si se destruye el stream antes de que Supabase lo consuma
        passThrough.on('error', () => {});

        // Arrancar el upload a Supabase — los chunks llegan por passThrough en tiempo real.
        // El borrado de la foto vieja se hace DESPUÉS de que el upload termina exitosamente
        // para no perderla si la validación falla (tamaño, magic numbers, etc).
        const uploadPromise = supabase.storage
          .from(env.SUPABASE_STORAGE_BUCKET)
          .upload(uniqueFilename, passThrough, { contentType: mimeType, upsert: true, duplex: 'half' });

        uploadPromise.then(async ({ error: uploadErr }) => {
          if (uploadErr) {
            return reject(new AppError(500, 'Error al subir: ' + uploadErr.message));
          }

          const { data } = supabase.storage
            .from(env.SUPABASE_STORAGE_BUCKET)
            .getPublicUrl(uniqueFilename);

          // Borrar la foto vieja solo si el upload fue exitoso
          const user = await userRepository.findProfileById(userId);
          if (user?.profile_photo_url) {
            const old = path.basename(user.profile_photo_url.split('?')[0]);
            await supabase.storage.from(env.SUPABASE_STORAGE_BUCKET).remove([old]);
          }

          await userRepository.updateProfilePhoto(userId, data.publicUrl);
          resolve(data.publicUrl);
        }).catch(reject);


        file.on('data', (chunk) => {
          if (validationError) return;

          totalBytes += chunk.length;

          // CA.2: rechazar en tiempo real si supera 5MB
          if (totalBytes > 5 * 1024 * 1024) {
            validationError = new AppError(400, 'La imagen no debe superar los 5MB.');
            passThrough.destroy(validationError);
            file.resume();
            return reject(validationError);
          }

          // CA.3: validar magic numbers en el primer chunk
          if (!magicChecked) {
            magicChecked = true;
            if (!isValidMagicNumber(chunk)) {
              validationError = new AppError(400, 'El contenido real del archivo no es JPG ni PNG.');
              passThrough.destroy(validationError);
              file.resume();
              return reject(validationError);
            }
          }

          // Pass the chunk directly to the PassThrough stream
          passThrough.write(chunk);
        });

        file.on('limit', () => {
          validationError = validationError || new AppError(400, 'La imagen no debe superar los 5MB.');
          passThrough.destroy(validationError);
          file.resume();
          reject(validationError);
        });

        // 'end' se emite cuando el stream del archivo termina.
        file.on('end', () => {
          if (validationError) return;
          // Signal the end of the PassThrough stream so Supabase knows it's done
          passThrough.end();
        });
      });

      // 'finish' solo maneja el caso en que no llegó ningún archivo
      busboy.on('finish', () => {
        if (!fileEventFired) reject(new AppError(400, 'No se subió ningún archivo.'));
      });

      busboy.on('error', reject);
      req.pipe(busboy);
    });
  },

  // H8 CA.4/CA.6: elimina la foto de perfil de Supabase Storage y limpia la URL en DB
  async deleteProfilePhoto(userId) {
    const user = await userRepository.findProfileById(userId);
    if (!user) {
      throw new AppError(410, 'Usuario no encontrado');
    }

    if (user.profile_photo_url) {
      const filename = path.basename(user.profile_photo_url.split('?')[0]);
      await supabase.storage.from(env.SUPABASE_STORAGE_BUCKET).remove([filename]);
    }

    await userRepository.updateProfilePhoto(userId, null);
  },  // Devuelve el perfil público de cualquier usuario (sin información privada)
  async getPublicProfile(userId) {
    const result = await userRepository.getUserDetail(userId);
    if (!result || result.deleted_at || result.is_suspended) {
      throw new AppError(410, 'Usuario no encontrado');
    }
    const fiveMinutesMs = 5 * 60 * 1000;
    const isOnline = result.last_seen_at && !result.is_private
      ? (Date.now() - new Date(result.last_seen_at).getTime()) <= fiveMinutesMs
      : false;
    return {
      id: result.id,
      username: result.username,
      biography: result.biography || '',
      is_online: isOnline,
      last_seen_at: result.last_seen_at,
    };
  },
};

module.exports = { userService };
