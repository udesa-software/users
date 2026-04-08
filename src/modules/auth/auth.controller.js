const { authService } = require('./auth.service');
const { env } = require('../../config/env');

const REFRESH_COOKIE_NAME = 'refreshToken';

function getRefreshCookieOptions() {
  const isProduction = env.APP_URL.startsWith('https');
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'None' : 'Lax',
    path: '/api/auth',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
  };
}

const authController = {
  async login(req, res, next) {
    try {
      const { accessToken, refreshToken, user } = await authService.login(req.body);

      res.cookie(REFRESH_COOKIE_NAME, refreshToken, getRefreshCookieOptions());

      res.status(200).json({
        message: 'Inicio de sesión exitoso.',
        accessToken,
        user,
      });
    } catch (err) {
      next(err);
    }
  },

  async refresh(req, res, next) {
    try {
      const token = req.cookies[REFRESH_COOKIE_NAME];
      if (!token) {
        return res.status(401).json({ error: 'Refresh token requerido' });
      }

      const { accessToken, newRefreshToken } = await authService.refreshToken(token);
      res.cookie(REFRESH_COOKIE_NAME, newRefreshToken, getRefreshCookieOptions());
      res.status(200).json({ accessToken });
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
      const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
      const result = await authService.logout(req.user.sub, refreshToken);
      res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
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
      res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { authController };
