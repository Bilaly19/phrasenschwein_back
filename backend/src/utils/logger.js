const { randomUUID } = require('crypto');
const { env } = require('../config/env');

const levels = ['error', 'warn', 'info', 'debug'];
const currentLevelIndex = levels.indexOf(env.logLevel) >= 0 ? levels.indexOf(env.logLevel) : 2;

function shouldLog(level) {
  return levels.indexOf(level) <= currentLevelIndex;
}

function log(level, message, meta = {}) {
  if (!shouldLog(level)) {
    return;
  }

  const payload = {
    level,
    message,
    timestamp: new Date().toISOString(),
    ...meta
  };

  if (level === 'error') {
    console.error(JSON.stringify(payload));
  } else if (level === 'warn') {
    console.warn(JSON.stringify(payload));
  } else {
    console.log(JSON.stringify(payload));
  }
}

const logger = {
  info: (meta, message) => log('info', message, sanitize(meta)),
  warn: (meta, message) => log('warn', message, sanitize(meta)),
  error: (meta, message) => log('error', message, sanitize(meta))
};

function sanitize(meta) {
  const clone = { ...(meta || {}) };
  if (clone.password) {
    clone.password = '[REDACTED]';
  }
  if (clone.token) {
    clone.token = '[REDACTED]';
  }
  return clone;
}

function requestLogger(req, res, next) {
  req.id = req.headers['x-request-id'] || randomUUID();
  res.setHeader('x-request-id', req.id);
  const start = Date.now();

  res.on('finish', () => {
    logger.info(
      {
        reqId: req.id,
        method: req.method,
        path: req.originalUrl,
        statusCode: res.statusCode,
        durationMs: Date.now() - start,
        ip: req.ip
      },
      'http_request'
    );
  });

  next();
}

module.exports = { logger, requestLogger };
