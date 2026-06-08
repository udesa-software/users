const { userService } = require('./user.service');

const userController = {
  async register(req, res, next) {
    try {
      const user = await userService.register(req.body);
      res.status(201).json({
        message: 'Registro exitoso. Revisá tu email para verificar tu cuenta.',
        user,
      });
    } catch (err) {
      next(err);
    }
  },


  async delete(req, res, next) {
    try {
      // req.user.sub viene del JWT verificado por el middleware authenticate
      await userService.delete(req.user.sub, req.body.password);
      res.status(200).json({ message: 'Tu cuenta ha sido eliminada.' });
    } catch (err) {
      next(err);
    }
  },

  async getPreferences(req, res, next) {
    try {
      const prefs = await userService.getPreferences(req.user.sub);
      res.status(200).json(prefs);
    } catch (err) {
      next(err);
    }
  },

  async updatePreferences(req, res, next) {
    try {
      const prefs = await userService.updatePreferences(req.user.sub, req.body);
      res.status(200).json({
        message: 'Preferencias actualizadas correctamente',
        preferences: prefs,
      });
    }catch (err) {
      next(err);
    }
  },
  // H1 E.2: GET /api/users/search — buscador de usuarios públicos para la app móvil
  async searchUsers(req, res, next) {
    try {
      const { q = '', page = 1, limit = 20 } = req.query;
      const result = await userService.searchUsers(req.user.sub, { q, page, limit });
      res.json(result);
    } catch (err) {
      next(err);
    }
  },

  // H6: PATCH /api/users/profile
  async updateProfile(req, res, next) {
    try {
      // req.user.sub viene del JWT — no hace falta que el cliente mande su propio ID
      const updates = await userService.updateProfile(req.user.sub, req.body);
      res.status(200).json(updates);
    } catch (err) {
      next(err);
    }
  },

  async searchUsersPublic(req, res, next) {
    try {
      const { username } = req.query;
      const users = await userService.searchUsersPublic(username, req.user.sub);
      res.status(200).json(users);
    } catch (err) {
      next(err);
    }
  },

  // H10 CA.1: actualiza last_seen_at del usuario autenticado. Llamado por la app
  // en background cada ~60s mientras está en uso.
  async heartbeat(req, res, next) {
    try {
      await userService.heartbeat(req.user.sub);
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  },

  async uploadProfilePhoto(req, res, next) {
    try {
      const profilePhotoUrl = await userService.uploadProfilePhoto(req.user.sub, req);
      res.status(200).json({ profile_photo_url: profilePhotoUrl });
    } catch (err) {
      next(err);
    }
  },

  async deleteProfilePhoto(req, res, next) {
    try {
      await userService.deleteProfilePhoto(req.user.sub);
      res.status(200).json({ message: 'Foto de perfil eliminada correctamente.' });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/users/:id/profile — devuelve el perfil público de cualquier usuario
  async getPublicProfile(req, res, next) {
    try {
      const profile = await userService.getPublicProfile(req.params.id);
      res.json(profile);
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { userController };
