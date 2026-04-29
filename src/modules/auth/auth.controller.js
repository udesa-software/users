const { authService } = require('./auth.service');

const authController = {
  async login(req, res, next) {
    try {
      const { accessToken, refreshToken, user } = await authService.login(req.body);

      // El refreshToken se devuelve en el body para que el cliente móvil
      // lo almacene en SecureStorage (no como cookie HttpOnly)
      res.status(200).json({
        message: 'Inicio de sesión exitoso.',
        accessToken,
        refreshToken,
        user,
      });
    } catch (err) {
      next(err);
    }
  },

  async refresh(req, res, next) {
    try {
      const token = req.body.refreshToken;
      if (!token) {
        return res.status(401).json({ error: 'Refresh token requerido' });
      }

      const { accessToken, newRefreshToken } = await authService.refreshToken(token);
      res.status(200).json({ accessToken, refreshToken: newRefreshToken });
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
      const refreshToken = req.body.refreshToken;
      const result = await authService.logout(req.user.sub, refreshToken);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  },

  async verifyResetToken(req, res, next) {
    try {
      const token = req.query['token'];
      await authService.verifyResetToken(token); // Valida internamente

      const { env } = require('../../config/env');

      // Intentamos usar la URL específica de reset, sino el scheme base
      const deepLinkBase = env.MOBILE_RESET_PASSWORD_URL || 'udesamigos://ResetPassword';
      // Si el link base ya contiene el esquema y el path, solo agregamos el token
      const deepLink = `${deepLinkBase}${deepLinkBase.includes('?') ? '&' : '?'}token=${token}`;

      res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>UdeSA-migos | Recuperar Contraseña</title>
          <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
          <style>
            :root {
              --primary: #4F46E5;
              --primary-dark: #4338CA;
              --bg: #F9FAFB;
              --text: #111827;
              --text-muted: #6B7280;
            }
            body {
              font-family: 'Inter', -apple-system, sans-serif;
              background-color: var(--bg);
              color: var(--text);
              margin: 0;
              display: flex;
              align-items: center;
              justify-content: center;
              height: 100vh;
              padding: 20px;
            }
            .card {
              background: white;
              padding: 40px;
              border-radius: 24px;
              box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
              max-width: 400px;
              width: 100%;
              text-align: center;
              transition: transform 0.3s ease;
            }
            .icon-container {
              width: 64px;
              height: 64px;
              background: #EEF2FF;
              border-radius: 16px;
              display: flex;
              align-items: center;
              justify-content: center;
              margin: 0 auto 24px;
            }
            .icon {
              color: var(--primary);
              font-size: 32px;
            }
            h1 {
              font-size: 24px;
              font-weight: 700;
              margin: 0 0 12px;
              color: var(--text);
            }
            p {
              color: var(--text-muted);
              font-size: 16px;
              line-height: 1.5;
              margin-bottom: 32px;
            }
            .btn {
              display: inline-block;
              background-color: var(--primary);
              color: white;
              padding: 14px 28px;
              border-radius: 12px;
              font-weight: 600;
              text-decoration: none;
              transition: all 0.2s ease;
              box-shadow: 0 4px 6px -1px rgba(79, 70, 229, 0.2);
            }
            .btn:hover {
              background-color: var(--primary-dark);
              transform: translateY(-2px);
              box-shadow: 0 10px 15px -3px rgba(79, 70, 229, 0.3);
            }
            .loader {
              width: 20px;
              height: 20px;
              border: 3px solid rgba(255,255,255,0.3);
              border-radius: 50%;
              border-top-color: #fff;
              animation: spin 1s ease-in-out infinite;
              display: inline-block;
              vertical-align: middle;
              margin-right: 10px;
            }
            @keyframes spin {
              to { transform: rotate(360deg); }
            }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="icon-container">
              <span class="icon">🚀</span>
            </div>
            <h1>Abriendo UdeSA-Migos</h1>
            <p>Estamos redirigiéndote a la aplicación para que puedas cambiar tu contraseña.</p>
            
            <a href="${deepLink}" id="open-btn" class="btn">
              Abrir App Manualmente
            </a>

            <script>
              const deepLink = "${deepLink}";
              
              // Intentar abrir automáticamente
              window.location.replace(deepLink);
              
              // Fallback para navegadores que bloquean el auto-redirect
              setTimeout(() => {
                const btn = document.getElementById('open-btn');
                btn.style.display = 'inline-block';
              }, 1000);
            </script>
          </div>
        </body>
        </html>
      `);
    } catch (err) {
      res.status(400).send(`
        <html>
          <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
              body { font-family: sans-serif; text-align: center; padding: 50px; background: #F9FAFB; }
              .error-card { background: white; padding: 40px; border-radius: 20px; max-width: 400px; margin: 0 auto; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
              h2 { color: #EF4444; }
              p { color: #6B7280; }
            </style>
          </head>
          <body>
            <div class="error-card">
              <h2>Enlace Inválido</h2>
              <p>${err.message || 'El enlace ha expirado o no es válido.'}</p>
              <p>Por favor, solicita uno nuevo desde la app.</p>
            </div>
          </body>
        </html>
      `);
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

  async verifyEmail(req, res, next) {
    try {
      const token = req.query['token'];
      await authService.verifyEmail(token);
      res.status(200).json({ message: 'Cuenta verificada exitosamente. Ya podés iniciar sesión.' });
    } catch (err) {
      next(err);
    }
  },

  async resendVerification(req, res, next) {
    try {
      await authService.resendVerification(req.body.identifier);
      res.status(200).json({ message: 'Email de verificación reenviado.' });
    } catch (err) {
      next(err);
    }
  },
};

module.exports = { authController };
