const { authService } = require('./auth.service');

const authController = {
  async login(req, res, next) {
    try {
      const result = await authService.login(req.body);
      res.status(200).json({
        message: 'Inicio de sesión exitoso.',
        ...result,
      });
    } catch (err) {
      next(err);
    }
  },

  async forgotPassword(req, res, next) {
    try {
      const result = await authService.requestPasswordReset(req.body.identifier);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },

  async resetPassword(req, res, next) {
    try {
      const result = await authService.resetPassword(req.body);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },

  async verifyResetToken(req, res, next) {
    try {
      const token = req.query['token'];
      const result = await authService.verifyResetToken(token);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { authController };
