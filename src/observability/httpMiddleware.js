const { logger } = require('./logger');

// Rutas que no vale la pena loggear — son ruido puro
const SKIP_PATHS = new Set(['/health', '/healthcheck', '/favicon.ico']);

function httpLogger(req, res, next) {
  if (SKIP_PATHS.has(req.path)) return next();

  const start = Date.now();

  // Adjuntamos un logger hijo con el request_id (si el gateway lo propaga)
  // para poder correlacionar logs de un mismo request entre servicios
  req.log = logger.child({
    request_id: req.headers['x-request-id'] ?? undefined,
  });

  res.on('finish', () => {
    const duration_ms = Date.now() - start;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';

    req.log[level](
      {
        method: req.method,
        path: req.route?.path ?? req.path,
        status: res.statusCode,
        duration_ms,
      },
      `${res.statusCode} ${req.method} ${req.path}`,
    );
  });

  next();
}

module.exports = { httpLogger };
