const express = require('express');
const { asyncHandler } = require('../utils/http');
const { validateBody, validateParams } = require('../validators/validate');
const { registerSchema, roleUpdateSchema, usernameParamsSchema } = require('../validators/schemas');

function createUsersRoutes({ usersController, authMiddleware, authRateLimit }) {
  const router = express.Router();

  router.get('/users', authMiddleware, asyncHandler(usersController.listUsers));
  router.post('/users', authMiddleware, authRateLimit, validateBody(registerSchema), asyncHandler(usersController.createUser));
  router.patch('/users/:username/roles', authMiddleware, authRateLimit, validateParams(usernameParamsSchema), validateBody(roleUpdateSchema), asyncHandler(usersController.setRoles));

  return router;
}

module.exports = {
  createUsersRoutes
};
