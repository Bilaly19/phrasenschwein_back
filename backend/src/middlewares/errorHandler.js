const { logger } = require('../utils/logger');

function notFoundHandler(req, _res, next) {
  next({ statusCode: 404, code: 'NOT_FOUND', message: 'Route nicht gefunden' });
}

function errorHandler(err, req, res, _next) {
  const statusCode = err.statusCode || 500;
  const code = err.code || 'INTERNAL_ERROR';
  const message = statusCode >= 500 ? 'Interner Fehler' : err.message;

  logger.error(
    {
      reqId: req.id,
      method: req.method,
      path: req.originalUrl,
      statusCode,
      code,
      error: err.message,
      details: err.details
    },
    'request_failed'
  );

  return res.status(statusCode).json({
    success: false,
    error: {
      code,
      message,
      details: err.details || undefined
    }
  });
}

module.exports = { notFoundHandler, errorHandler };
