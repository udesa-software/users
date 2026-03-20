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

  async verifyEmail(req, res, next) {
    try {
      const token = req.query['token'];
      if (!token) {
        res.status(400).json({ error: 'Token requerido' });
        return;
      }

      await userService.verifyEmail(token);
      res.status(200).json({ message: 'Cuenta verificada exitosamente. Ya podés iniciar sesión.' });
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

  async delete(req, res, next) {
    try {
      // req.user.sub viene del JWT verificado por el middleware authenticate
      await userService.delete(req.user.sub, req.body.password);
      res.status(200).json({ message: 'Tu cuenta ha sido eliminada.' });
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { userController };
