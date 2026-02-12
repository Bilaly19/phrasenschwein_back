const express = require('express');
const cors = require('cors');

const { env } = require('./config/env');
const { corsOptions } = require('./config/cors');
const { securityMiddleware } = require('./config/security');
const { requestLogger, logger } = require('./utils/logger');
const { createRateLimiter } = require('./middlewares/rateLimiter');
const { notFoundHandler, errorHandler } = require('./middlewares/errorHandler');

const { InMemoryFileCounterRepository } = require('./repositories/counterRepository');
const { InMemoryFileAuthRepository } = require('./repositories/authRepository');

const { CounterService } = require('./services/counterService');
const { AuthService } = require('./services/authService');

const { buildCounterController } = require('./controllers/counterController');
const { buildAuthController } = require('./controllers/authController');

const { createCounterRoutes } = require('./routes/counterRoutes');
const { createAuthRoutes } = require('./routes/authRoutes');

function createApp() {
  const app = express();

  const counterRepository = new InMemoryFileCounterRepository(env.dataPath);
  const authRepository = new InMemoryFileAuthRepository(env.usersPath);

  const counterService = new CounterService(counterRepository);
  const authService = new AuthService(authRepository, {
    sessionTtlMinutes: env.sessionTtlMinutes,
    rollingSession: env.rollingSession,
    bcryptSaltRounds: env.bcryptSaltRounds
  });

  const counterController = buildCounterController(counterService, env);
  const authController = buildAuthController(authService, logger);

  const authRateLimiter = createRateLimiter({
    windowMs: env.loginRateLimitWindowMs,
    maxRequests: env.loginRateLimitMaxRequests,
    message: 'Zu viele Versuche, bitte später erneut.'
  });

  app.use(securityMiddleware());
  app.use(cors(corsOptions));
  app.use(express.json({ limit: '1mb' }));
  app.use(requestLogger);

  app.use('/api', createCounterRoutes(counterController, authService));
  app.use('/api', createAuthRoutes(authController, authService, authRateLimiter));

  app.use(notFoundHandler);
  app.use(errorHandler);

  setInterval(() => {
    authService.cleanupExpiredSessions().catch((error) => {
      logger.error({ error: error.message }, 'cleanup_expired_sessions_failed');
    });
  }, 5 * 60 * 1000).unref();

  return { app, env };
}

module.exports = { createApp };
