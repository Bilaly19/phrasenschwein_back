class AppError extends Error {
  constructor(statusCode, code, message, details) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function sendError(res, error) {
  return res.status(error.statusCode || 500).json({
    ok: false,
    error: {
      code: error.code || 'INTERNAL_ERROR',
      message: error.message || 'Interner Fehler',
      details: error.details || [],
      requestId: res.getHeader('x-request-id') || null
    }
  });
}

module.exports = {
  AppError,
  asyncHandler,
  sendError
};
