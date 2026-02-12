const { asyncHandler } = require('../utils/asyncHandler');

function extractToken(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  if (authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }

  return authHeader.trim();
}

function requireAuth(authService, options = { refresh: false }) {
  return asyncHandler(async (req, _res, next) => {
    const token = extractToken(req.headers.authorization);
    const session = await authService.resolveSession(token, options);
    req.auth = {
      token,
      username: session.username,
      expiresAt: session.expiresAt || null
    };
    next();
  });
}

module.exports = { extractToken, requireAuth };
