const express = require('express');
const { validateBody, validateParams } = require('../middlewares/validate');
const { requireAuth } = require('../middlewares/authMiddleware');
const { validateConfig, validateNamePayload, validateNameParam, validateEmptyObject } = require('../validators/schemas');

function createCounterRoutes(controller, authService) {
  const router = express.Router();

  router.get('/names', controller.getNames);
  router.get('/config', controller.getConfig);
  router.get('/donation-link', controller.getDonationLink);

  router.post('/config', requireAuth(authService, { refresh: true }), validateBody(validateConfig), controller.setConfig);
  router.post('/add', requireAuth(authService, { refresh: true }), validateBody(validateNamePayload), controller.addName);
  router.post('/increment/:name', requireAuth(authService, { refresh: true }), validateParams(validateNameParam), controller.increment);
  router.post('/reset', requireAuth(authService, { refresh: true }), validateBody(validateEmptyObject), controller.reset);
  router.delete('/delete/:name', requireAuth(authService, { refresh: true }), validateParams(validateNameParam), controller.deleteName);

  return router;
}

module.exports = { createCounterRoutes };
