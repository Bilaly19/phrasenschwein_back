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

    const error = err instanceof AppError
      ? err
      : new AppError(500, 'INTERNAL_ERROR', 'Interner Fehler');

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

module.exports = {
  notFoundHandler,
  createErrorHandler
};
