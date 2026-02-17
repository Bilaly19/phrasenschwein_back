const express = require('express');
const { asyncHandler } = require('../utils/http');
const { validateBody } = require('../validators/validate');
const { acceptInviteSchema } = require('../validators/schemas');

function createInvitesRoutes({ invitesController, authMiddleware }) {
  const router = express.Router();

  router.post('/invites/accept', authMiddleware, validateBody(acceptInviteSchema), asyncHandler(invitesController.acceptInvite));

  return router;
}

module.exports = {
  createInvitesRoutes
};

