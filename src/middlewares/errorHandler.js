class AppError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
  }
}

function errorHandler(err, _req, res, _next) {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ error: err.message });
    return;
  }

  console.error('Unexpected error:', err);
  res.status(500).json({ error: 'Internal server error' });
}

module.exports = { AppError, errorHandler };
