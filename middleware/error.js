const { logError } = require('../logger');

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    return next(err);
  }

  logError('Unhandled error', {
    method: req.method,
    path: req.originalUrl,
    statusCode: err.statusCode || 500,
    error: err.message
  });

  return res.status(500).json({ message: 'Interner Fehler' });
}

module.exports = {
  asyncHandler,
  errorHandler
};
