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
};

module.exports = { userController };
