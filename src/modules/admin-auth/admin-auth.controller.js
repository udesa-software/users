const { adminAuthService } = require('./admin-auth.service');

const adminAuthController = {
  async login(req, res, next) {
    try {
      const result = await adminAuthService.login(req.body);
      res.status(200).json({ message: 'Inicio de sesión exitoso.', ...result });
    } catch (err) {
      next(err);
    }
  },

  async logout(req, res, next) {
    try {
      const result = await adminAuthService.logout(req.admin.sub);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },

  async changePassword(req, res, next) {
    try {
      const result = await adminAuthService.changePassword(req.admin.sub, req.body);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { adminAuthController };
