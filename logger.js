const { loadEnv } = require('./src/backend/config/env');
const { createLogger, createRequestLogger } = require('./src/backend/logging/logger');

const logger = createLogger(loadEnv());

function logInfo(message, meta = {}) {
  logger.info(meta, message);
}

function logWarn(message, meta = {}) {
  logger.warn(meta, message);
}

function logError(message, meta = {}) {
  logger.error(meta, message);
}

function requestLogger(req, res, next) {
  return createRequestLogger(logger)(req, res, next);
}

module.exports = {
  logInfo,
  logWarn,
  logError,
  requestLogger
};
