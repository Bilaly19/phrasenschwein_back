const { AppError } = require('../utils/http');

function extractBearerToken(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') return null;
  if (authHeader.startsWith('Bearer ')) return authHeader.slice(7).trim();
  return authHeader.trim() || null;
}

function createAuthMiddleware({ authService }) {
  return async (req, _res, next) => {
    try {
      const token = extractBearerToken(req.headers.authorization);
      const session = await authService.getSessionByToken(token, { touch: true });

      req.auth = {
        token,
        username: session.username,
        expiresAt: session.expiresAt,
        roles: Array.isArray(session.roles) ? session.roles : ['user']
      };

      next();
    } catch (error) {
      next(error instanceof AppError ? error : new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt'));
    }
  };
}

module.exports = {
  extractBearerToken,
  createAuthMiddleware
};
