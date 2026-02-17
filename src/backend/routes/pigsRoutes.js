const express = require('express');
const { asyncHandler } = require('../utils/http');
const { validateBody, validateParams } = require('../validators/validate');
const { createPigSchema, createInviteSchema, pigIdParamsSchema, configSchema, usernameParamsSchema, emptyBodySchema } = require('../validators/schemas');

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

  router.get('/pigs/:pigId/names', authMiddleware, validateParams(pigIdParamsSchema), asyncHandler(pigsController.getNames));
  router.get('/pigs/:pigId/config', authMiddleware, validateParams(pigIdParamsSchema), asyncHandler(pigsController.getConfig));
  router.post('/pigs/:pigId/config', authMiddleware, validateParams(pigIdParamsSchema), validateBody(configSchema), asyncHandler(pigsController.updateConfig));

  router.post(
    '/pigs/:pigId/increment/:username',
    authMiddleware,
    validateParams(pigIdParamsSchema),
    validateParams(usernameParamsSchema),
    asyncHandler(pigsController.incrementName)
  );
  router.post(
    '/pigs/:pigId/reset',
    authMiddleware,
    validateParams(pigIdParamsSchema),
    validateBody(emptyBodySchema),
    asyncHandler(pigsController.resetMine)
  );

  return router;
}

module.exports = {
  createPigsRoutes
};
