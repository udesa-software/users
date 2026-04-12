const { adminAuthService } = require('./admin-auth.service');
const { env } = require('../../config/env');

const REFRESH_COOKIE_NAME = 'adminRefreshToken';

function getRefreshCookieOptions() {
  const isProduction = env.APP_URL.startsWith('https');
  return {
    httpOnly: true,
    secure: true,
    sameSite: isProduction ? 'None' : 'Lax',
    path: '/api/admin/auth',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
  };
}

const adminAuthController = {
  async login(req, res, next) {
    try {
      const { accessToken, refreshToken, admin } = await adminAuthService.login(req.body);

      res.cookie(REFRESH_COOKIE_NAME, refreshToken, getRefreshCookieOptions());

      res.status(200).json({ message: 'Inicio de sesión exitoso.', accessToken, admin });
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

      const { accessToken, newRefreshToken } = await adminAuthService.refreshToken(token);
      res.cookie(REFRESH_COOKIE_NAME, newRefreshToken, getRefreshCookieOptions());
      res.status(200).json({ accessToken });
    } catch (err) {
      next(err);
    }
  },

  async logout(req, res, next) {
    try {
      const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
      const result = await adminAuthService.logout(req.admin.sub, refreshToken);
      res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/admin/auth' });
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },

  async changePassword(req, res, next) {
    try {
      const result = await adminAuthService.changePassword(req.admin.sub, req.body);
      res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/admin/auth' });
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { adminAuthController };
