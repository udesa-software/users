const { env } = require('../config/env');
const { AppError } = require('./errorHandler');

function authenticateInternal(req, _res, next) {
  const secret = req.headers['x-internal-secret'];
  if (!secret || secret !== env.INTERNAL_SECRET) {
    return next(new AppError(401, 'Forbidden'));
  }
  next();
}

module.exports = { authenticateInternal };
