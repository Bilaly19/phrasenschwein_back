const express = require('express');
const { asyncHandler } = require('../utils/http');
const { validateBody } = require('../validators/validate');
const { assistantChatSchema } = require('../validators/schemas');

function createAssistantRoutes({ assistantController, authMiddleware }) {
  const router = express.Router();

  router.post(
    '/assistant/chat',
    authMiddleware,
    validateBody(assistantChatSchema),
    asyncHandler(assistantController.chat)
  );

  return router;
}

module.exports = {
  createAssistantRoutes
};
