function logInfo(message, meta = {}) {
  console.info('[INFO]', message, meta);
}

function logWarn(message, meta = {}) {
  console.warn('[WARN]', message, meta);
}

function logError(message, meta = {}) {
  console.error('[ERROR]', message, meta);
}

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const durationMs = Date.now() - start;
    logInfo('HTTP Request', {
      method: req.method,
      path: req.originalUrl,
      statusCode: res.statusCode,
      ip: req.ip,
      durationMs
    });
  });

  next();
}

module.exports = {
  logInfo,
  logWarn,
  logError,
  requestLogger
};
