const { AppError } = require('./errorHandler');

// Verifica que el admin tenga el rol requerido.
// Uso: router.post('/admins', authenticateAdmin, authorize('superadmin'), ...)
function authorize(requiredRole) {
  return (req, _res, next) => {
    if (req.admin.role !== requiredRole) {
      return next(new AppError(403, 'No tenés permisos para realizar esta acción'));
    }
    next();
  };
}

// Bloquea acceso si el admin todavía no cambió su contraseña temporal.
function requirePasswordChanged(req, _res, next) {
  if (req.admin.must_change_password) {
    return next(new AppError(403, 'Debés cambiar tu contraseña temporal antes de continuar'));
  }
  next();
}

module.exports = { authorize, requirePasswordChanged };
