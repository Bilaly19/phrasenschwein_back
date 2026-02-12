const { ok, created } = require('../utils/response');
const { asyncHandler } = require('../utils/asyncHandler');
const { extractToken } = require('../middlewares/authMiddleware');

function buildAuthController(authService, logger) {
  return {
    register: asyncHandler(async (req, res) => {
      await authService.register(req.body.username, req.body.password);
      logger.info({ username: req.body.username, reqId: req.id }, 'user_registered');
      return created(res, null, 'Benutzer registriert');
    }),

    login: asyncHandler(async (req, res) => {
      const result = await authService.login(req.body.username, req.body.password);
      logger.info({ username: result.username, reqId: req.id }, 'user_logged_in');
      return ok(res, result, 'Login erfolgreich');
    }),

    logout: asyncHandler(async (req, res) => {
      const token = extractToken(req.headers.authorization);
      await authService.logout(token);
      return ok(res, null, 'Abgemeldet');
    }),

    session: asyncHandler(async (req, res) => {
      return ok(
        res,
        {
          username: req.auth.username,
          expiresAt: req.auth.expiresAt
        },
        'Session aktiv'
      );
    })
  };
}

module.exports = { buildAuthController };
