const express = require('express');
const { asyncHandler } = require('../utils/http');
const { validateBody, validateParams } = require('../validators/validate');
const { configSchema, addNameSchema, incrementParamsSchema, emptyBodySchema } = require('../validators/schemas');

function createNamesRoutes({ namesController, authMiddleware }) {
  const router = express.Router();

  router.get('/names', asyncHandler(namesController.getNames));
  router.get('/config', asyncHandler(namesController.getConfig));
  router.get('/donation-link', asyncHandler(namesController.getDonationLink));

  router.post('/config', authMiddleware, validateBody(configSchema), asyncHandler(namesController.updateConfig));
  router.post('/add', authMiddleware, validateBody(addNameSchema), asyncHandler(namesController.addName));
  router.post('/increment/:name', authMiddleware, validateParams(incrementParamsSchema), asyncHandler(namesController.incrementName));
  router.post('/reset', authMiddleware, validateBody(emptyBodySchema), asyncHandler(namesController.resetNames));
  router.delete('/delete/:name', authMiddleware, validateParams(incrementParamsSchema), asyncHandler(namesController.deleteName));

  return router;
}

module.exports = {
  createNamesRoutes
};
