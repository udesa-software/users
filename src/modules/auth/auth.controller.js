const { authService } = require('./auth.service');
const { userService } = require('../users/user.service');

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

  async logout(req, res, next) {
    try {
      const result = await authService.logout(req.user.sub);
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

  async changePassword(req, res, next) {
    try {
      const userId = req.user.sub;
      const result = await authService.changePassword(userId, req.body);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },

  async resendVerification(req, res, next) {
    try {
      await userService.resendVerification(req.body.email);
      res.status(200).json({ message: 'Email de verificación reenviado.' });
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { authController };
