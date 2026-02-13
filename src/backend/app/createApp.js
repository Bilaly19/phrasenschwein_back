const express = require('express');
const cors = require('cors');
const { loadEnv } = require('../config/env');
const { createCorsOptions } = require('../config/cors');
const { securityHeadersMiddleware } = require('../config/security');
const { createLogger, createRequestLogger } = require('../logging/logger');
const { createRateLimiter } = require('../middlewares/rateLimit');
const { createAuthMiddleware } = require('../middlewares/authSession');
const { createErrorHandler, notFoundHandler } = require('../middlewares/errorHandler');
const { JsonNamesRepository } = require('../repositories/namesRepository');
const { JsonUsersRepository } = require('../repositories/usersRepository');
const { NamesService } = require('../services/namesService');
const { AuthService } = require('../services/authService');
const { NamesController } = require('../controllers/namesController');
const { AuthController } = require('../controllers/authController');
const { createNamesRoutes } = require('../routes/namesRoutes');
const { createAuthRoutes } = require('../routes/authRoutes');

function buildContainer(overrides = {}) {
  const config = { ...loadEnv(), ...(overrides.config || {}) };
  const logger = overrides.logger || createLogger(config);

  const namesRepository = overrides.namesRepository || new JsonNamesRepository({ dataPath: config.dataPath });
  const usersRepository = overrides.usersRepository || new JsonUsersRepository({ usersPath: config.usersPath });

  const namesService = overrides.namesService || new NamesService({ namesRepository });
  const authService = overrides.authService || new AuthService({
    usersRepository,
    sessionTtlMinutes: config.sessionTtlMinutes,
    sessionRolling: config.sessionRolling,
    bcryptRounds: config.bcryptRounds
  });

  const namesController = overrides.namesController || new NamesController({ namesService, config });
  const authController = overrides.authController || new AuthController({ authService, logger });

  return {
    config,
    logger,
    namesRepository,
    usersRepository,
    namesService,
    authService,
    namesController,
    authController
  };
}

function createApp(overrides = {}) {
  const container = buildContainer(overrides);
  const app = express();

  app.use(securityHeadersMiddleware(container.config));
  app.use(cors(createCorsOptions(container.config)));
  app.use(express.json({ limit: '100kb' }));
  app.use(createRequestLogger(container.logger));

  const authRateLimit = createRateLimiter({
    windowMs: container.config.authRateLimitWindowMs,
    maxRequests: container.config.authRateLimitMax
  });
  const authAccountRateLimit = createRateLimiter({
    windowMs: container.config.authRateLimitWindowMs,
    maxRequests: container.config.authAccountRateLimitMax || container.config.authRateLimitMax,
    keyGenerator(req) {
      const username = typeof req.body?.username === 'string'
        ? req.body.username.trim().toLowerCase()
        : '';
      return username ? `acct:${username}` : null;
    },
    maxBuckets: 10000
  });
  const authMiddleware = createAuthMiddleware({ authService: container.authService });

  app.use('/api', createNamesRoutes({ namesController: container.namesController, authMiddleware }));
  app.use('/api', createAuthRoutes({
    authController: container.authController,
    authRateLimit,
    authAccountRateLimit,
    authMiddleware
  }));

  app.use(notFoundHandler);
  app.use(createErrorHandler({ logger: container.logger }));

  return { app, container };
}

module.exports = {
  createApp,
  buildContainer
};
