const express = require('express');
const { validateBody } = require('../middlewares/validate');
const { requireAuth } = require('../middlewares/authMiddleware');
const { validateRegister, validateLogin, validateEmptyObject } = require('../validators/schemas');

function createAuthRoutes(controller, authService, authRateLimiter) {
  const router = express.Router();

  router.post('/register', authRateLimiter, validateBody(validateRegister), controller.register);
  router.post('/login', authRateLimiter, validateBody(validateLogin), controller.login);
  router.post('/logout', validateBody(validateEmptyObject), controller.logout);
  router.get('/session', requireAuth(authService, { refresh: true }), controller.session);

  return router;
}

module.exports = { createAuthRoutes };
