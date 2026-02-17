const express = require('express');
const { asyncHandler } = require('../utils/http');
const { validateBody, validateParams } = require('../validators/validate');
const { createPigSchema, createInviteSchema, pigIdParamsSchema } = require('../validators/schemas');

function createPigsRoutes({ pigsController, authMiddleware }) {
  const router = express.Router();

  router.get('/pigs', authMiddleware, asyncHandler(pigsController.listPigs));
  router.post('/pigs', authMiddleware, validateBody(createPigSchema), asyncHandler(pigsController.createPig));
  router.post(
    '/pigs/:pigId/invites',
    authMiddleware,
    validateParams(pigIdParamsSchema),
    validateBody(createInviteSchema),
    asyncHandler(pigsController.createInvite)
  );

  return router;
}

module.exports = {
  createPigsRoutes
};

