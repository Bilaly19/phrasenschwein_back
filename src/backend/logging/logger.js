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
  return sanitizeValue(value, new WeakSet(), '');
}

function sanitizeValue(value, seen, keyName) {
  if (isSensitiveKey(keyName)) {
    return '[REDACTED]';
  }

  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value !== 'object') {
    return value;
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack
    };
  }

  if (seen.has(value)) {
    return '[CIRCULAR]';
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item, seen, ''));
  }

  const result = {};
  for (const [key, child] of Object.entries(value)) {
    result[key] = sanitizeValue(child, seen, key);
  }
  return result;
}

function isSensitiveKey(keyName) {
  const key = String(keyName || '').toLowerCase();
  if (!key) return false;

  return key === 'password'
    || key === 'passwordhash'
    || key === 'authorization'
    || key === 'token'
    || key === 'session'
    || key === 'cookie';
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
