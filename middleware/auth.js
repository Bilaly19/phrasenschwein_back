const { readUsers, writeUsers } = require('../storage');
const config = require('../config');

function extractToken(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  if (authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }

  return authHeader.trim();
}

function isExpired(expiresAt) {
  if (!expiresAt) {
    return false;
  }

  const expiresAtMs = new Date(expiresAt).getTime();
  if (Number.isNaN(expiresAtMs)) {
    return true;
  }

  return expiresAtMs <= Date.now();
}

async function cleanupExpiredSessions(usersData, usersPath, keepToken) {
  let changed = false;

  for (const [token, session] of Object.entries(usersData.sessions || {})) {
    if (token === keepToken) {
      continue;
    }

    if (session && typeof session === 'object' && isExpired(session.expiresAt)) {
      delete usersData.sessions[token];
      changed = true;
    }
  }

  if (changed) {
    await writeUsers(usersPath, usersData);
  }
}

function buildSession(username) {
  const expiresAt = new Date(Date.now() + config.sessionTtlMinutes * 60 * 1000).toISOString();
  return {
    username,
    expiresAt
  };
}

function resolveSession(sessions, token) {
  const sessionValue = sessions?.[token];

  if (!sessionValue) {
    return null;
  }

  if (typeof sessionValue === 'string') {
    return { username: sessionValue, legacy: true };
  }

  if (typeof sessionValue === 'object' && sessionValue.username) {
    if (isExpired(sessionValue.expiresAt)) {
      return { expired: true };
    }

    return { username: sessionValue.username, legacy: false };
  }

  return null;
}

function authMiddleware(usersPath) {
  return async (req, res, next) => {
    const token = extractToken(req.headers.authorization);
    if (!token) {
      return res.status(401).json({ message: 'Nicht eingeloggt' });
    }

    const usersData = await readUsers(usersPath);
    const resolved = resolveSession(usersData.sessions, token);

    if (!resolved) {
      await cleanupExpiredSessions(usersData, usersPath, token);
      return res.status(401).json({ message: 'Nicht eingeloggt' });
    }

    if (resolved.expired) {
      delete usersData.sessions[token];
      await writeUsers(usersPath, usersData);
      return res.status(401).json({ message: 'Session abgelaufen' });
    }

    await cleanupExpiredSessions(usersData, usersPath, token);

    req.user = resolved.username;
    req.token = token;
    next();
  };
}

module.exports = {
  authMiddleware,
  extractToken,
  resolveSession,
  buildSession,
  cleanupExpiredSessions
};
