const express = require('express');
const cors = require('cors');
const { loadEnv } = require('../config/env');
const { createCorsOptions } = require('../config/cors');
const { securityHeadersMiddleware } = require('../config/security');
const { createLogger, createRequestLogger } = require('../logging/logger');
const { createRateLimiter } = require('../middlewares/rateLimit');
const { createAuthMiddleware } = require('../middlewares/authSession');
const { createErrorHandler, notFoundHandler } = require('../middlewares/errorHandler');
const { createDb } = require('../repositories/sqliteDb');
const { SqliteNamesRepository } = require('../repositories/sqliteNamesRepository');
const { SqliteUsersRepository } = require('../repositories/sqliteUsersRepository');
const { SqlitePigsRepository } = require('../repositories/sqlitePigsRepository');
const { NamesService } = require('../services/namesService');
const { AuthService } = require('../services/authService');
const { PigsService } = require('../services/pigsService');
const { AssistantService } = require('../services/assistantService');
const { NamesController } = require('../controllers/namesController');
const { AuthController } = require('../controllers/authController');
const { UsersController } = require('../controllers/usersController');
const { PigsController } = require('../controllers/pigsController');
const { InvitesController } = require('../controllers/invitesController');
const { AssistantController } = require('../controllers/assistantController');
const { createNamesRoutes } = require('../routes/namesRoutes');
const { createAuthRoutes } = require('../routes/authRoutes');
const { createUsersRoutes } = require('../routes/usersRoutes');
const { createPigsRoutes } = require('../routes/pigsRoutes');
const { createInvitesRoutes } = require('../routes/invitesRoutes');
const { createAssistantRoutes } = require('../routes/assistantRoutes');

function buildContainer(overrides = {}) {
  const config = { ...loadEnv(), ...(overrides.config || {}) };
  const logger = overrides.logger || createLogger(config);

  const db = overrides.db || createDb(config.dbPath);
  const namesRepository = overrides.namesRepository || new SqliteNamesRepository({ db });
  const usersRepository = overrides.usersRepository || new SqliteUsersRepository({ db });
  const pigsRepository = overrides.pigsRepository || new SqlitePigsRepository({ db });

  const namesService = overrides.namesService || new NamesService({ namesRepository });
  const authService = overrides.authService || new AuthService({
    usersRepository,
    namesRepository,
    sessionTtlMinutes: config.sessionTtlMinutes,
    sessionRolling: config.sessionRolling,
    bcryptRounds: config.bcryptRounds
  });
  const pigsService = overrides.pigsService || new PigsService({ pigsRepository });
  const assistantService = overrides.assistantService || new AssistantService({
    config,
    pigsService
  });

  const namesController = overrides.namesController || new NamesController({ namesService, config });
  const authController = overrides.authController || new AuthController({ authService, logger });
  const usersController = overrides.usersController || new UsersController({ authService, logger });
  const pigsController = overrides.pigsController || new PigsController({ pigsService, logger });
  const invitesController = overrides.invitesController || new InvitesController({ pigsService, logger });
  const assistantController = overrides.assistantController || new AssistantController({ assistantService });

  return {
    config,
    logger,
    db,
    namesRepository,
    usersRepository,
    pigsRepository,
    namesService,
    authService,
    pigsService,
    assistantService,
    namesController,
    authController,
    usersController,
    pigsController,
    invitesController,
    assistantController
  };
}

function createApp(overrides = {}) {
  const container = buildContainer(overrides);
  const app = express();
  const isProductionEnv = container.config.nodeEnv === 'production';

  app.use(securityHeadersMiddleware(container.config));
  app.use(cors(createCorsOptions(container.config)));
  app.use(express.json({ limit: '100kb' }));
  app.use(createRequestLogger(container.logger));

  app.get('/health', (req, res) => {
    const payload = { ok: true, status: 'ok' };
    if (req.id) {
      payload.requestId = req.id;
    }
    res.status(200).json(payload);
  });

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
  const effectiveAuthAccountRateLimit = isProductionEnv ? authAccountRateLimit : null;
  const authLogoutRateLimit = createRateLimiter({
    windowMs: container.config.authRateLimitWindowMs,
    maxRequests: container.config.authLogoutRateLimitMax || Math.max(container.config.authRateLimitMax, 60)
  });
  const authMiddleware = createAuthMiddleware({ authService: container.authService });

  app.use('/api', createNamesRoutes({ namesController: container.namesController, authMiddleware }));
  app.use('/api', createAuthRoutes({
    authController: container.authController,
    authRateLimit,
    authAccountRateLimit: effectiveAuthAccountRateLimit,
    authLogoutRateLimit,
    authMiddleware
  }));
  app.use('/api', createUsersRoutes({
    usersController: container.usersController,
    authMiddleware,
    authRateLimit
  }));
  app.use('/api', createPigsRoutes({
    pigsController: container.pigsController,
    authMiddleware
  }));
  app.use('/api', createInvitesRoutes({
    invitesController: container.invitesController,
    authMiddleware
  }));
  const assistantRoutes = createAssistantRoutes({
    assistantController: container.assistantController,
    authMiddleware
  });

  app.use('/api', assistantRoutes);
  app.use('/', assistantRoutes);

  app.use(notFoundHandler);
  app.use(createErrorHandler({ logger: container.logger }));

  return { app, container };
}

module.exports = {
  createApp,
  buildContainer
};
