const { AppError, sendError } = require('../utils/http');

function notFoundHandler(_req, _res, next) {
  next(new AppError(404, 'NOT_FOUND', 'Route nicht gefunden'));
}

function createErrorHandler({ logger }) {
  return (err, req, res, next) => {
    if (res.headersSent) {
      next(err);
      return;
    }

    const error = normalizeError(err);

    logger.error({
      err,
      requestId: req.id,
      method: req.method,
      path: req.originalUrl,
      statusCode: error.statusCode,
      code: error.code
    }, 'Request failed');

    sendError(res, error);
  };
}

function normalizeError(err) {
  if (err instanceof AppError) {
    return err;
  }

  if (typeof err?.message === 'string' && err.message.startsWith('CORS:')) {
    return new AppError(403, 'CORS_ORIGIN_DENIED', 'Origin nicht erlaubt');
  }

  return new AppError(500, 'INTERNAL_ERROR', 'Interner Fehler');
}

module.exports = {
  notFoundHandler,
  createErrorHandler
};
