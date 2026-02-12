const crypto = require('node:crypto');

function baseLog(level, message, meta = {}) {
  const payload = {
    level,
    message,
    timestamp: new Date().toISOString(),
    ...meta
  };
  const output = JSON.stringify(payload);
  if (level === 'error') {
    console.error(output);
  } else if (level === 'warn') {
    console.warn(output);
  } else {
    console.info(output);
  }
}

function createLogger() {
  return {
    info(meta, message) {
      baseLog('info', message, sanitize(meta));
    },
    warn(meta, message) {
      baseLog('warn', message, sanitize(meta));
    },
    error(meta, message) {
      baseLog('error', message, sanitize(meta));
    }
  };
}

function sanitize(value) {
  if (!value || typeof value !== 'object') return value;
  const cloned = JSON.parse(JSON.stringify(value));
  if (cloned.password) cloned.password = '[REDACTED]';
  if (cloned.passwordHash) cloned.passwordHash = '[REDACTED]';
  if (cloned.authorization) cloned.authorization = '[REDACTED]';
  return cloned;
}

function createRequestLogger(logger) {
  return (req, res, next) => {
    const requestId = typeof req.headers['x-request-id'] === 'string' && req.headers['x-request-id'].trim()
      ? req.headers['x-request-id']
      : crypto.randomUUID();

    req.id = requestId;
    res.setHeader('x-request-id', requestId);

    const started = Date.now();

    res.on('finish', () => {
      logger.info({
        requestId,
        method: req.method,
        path: req.originalUrl,
        ip: req.ip,
        statusCode: res.statusCode,
        durationMs: Date.now() - started
      }, 'HTTP Request');
    });

    next();
  };
}

module.exports = {
  createLogger,
  createRequestLogger
};
