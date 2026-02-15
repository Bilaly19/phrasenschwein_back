const express = require('express');
const { asyncHandler } = require('../utils/http');
const { validateBody } = require('../validators/validate');
const { loginSchema, registerSchema, emptyBodySchema } = require('../validators/schemas');

function createAuthRoutes({
  authController,
  authRateLimit,
  authAccountRateLimit,
  authLogoutRateLimit,
  authMiddleware
}) {
  const router = express.Router();
  const accountLimiter = authAccountRateLimit || ((_req, _res, next) => next());
  const logoutLimiter = authLogoutRateLimit || authRateLimit || ((_req, _res, next) => next());

  router.post('/register', authRateLimit, accountLimiter, validateBody(registerSchema), asyncHandler(authController.register));
  router.post('/login', authRateLimit, accountLimiter, validateBody(loginSchema), asyncHandler(authController.login));
  router.post('/logout', logoutLimiter, authMiddleware, validateBody(emptyBodySchema), asyncHandler(authController.logout));
  router.get('/session', authMiddleware, asyncHandler(authController.whoAmI));

  return router;
}

module.exports = {
  createAuthRoutes
};
