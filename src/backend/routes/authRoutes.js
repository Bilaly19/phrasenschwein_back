const express = require('express');
const { asyncHandler } = require('../utils/http');
const { validateBody } = require('../validators/validate');
const { loginSchema, registerSchema, emptyBodySchema } = require('../validators/schemas');

function createAuthRoutes({ authController, authRateLimit, authMiddleware }) {
  const router = express.Router();

  router.post('/register', authRateLimit, validateBody(registerSchema), asyncHandler(authController.register));
  router.post('/login', authRateLimit, validateBody(loginSchema), asyncHandler(authController.login));
  router.post('/logout', validateBody(emptyBodySchema), asyncHandler(authController.logout));
  router.get('/session', authMiddleware, asyncHandler(authController.whoAmI));

  return router;
}

module.exports = {
  createAuthRoutes
};
