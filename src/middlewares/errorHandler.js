const { logger } = require('../observability/logger');

class AppError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
  }
}

function errorHandler(err, req, res, _next) {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ error: err.message });
    return;
  }

  // Errores inesperados (bugs reales) — estos son los que querés ver en Grafana
  const log = req.log ?? logger;
  log.error(
    { err: err.message, stack: err.stack, path: req.path, method: req.method },
    'unhandled_error',
  );
  res.status(500).json({ error: 'Internal server error' });
}

module.exports = { AppError, errorHandler };
