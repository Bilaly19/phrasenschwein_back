const { AppError } = require('../utils/appError');

function createRateLimiter({ windowMs, maxRequests, message }) {
  const buckets = new Map();

  return (req, _res, next) => {
    const key = `${req.ip || req.socket.remoteAddress || 'unknown'}:${req.path}`;
    const now = Date.now();
    const bucket = buckets.get(key);

    if (!bucket || bucket.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    if (bucket.count >= maxRequests) {
      return next(new AppError(429, 'RATE_LIMITED', message));
    }

    bucket.count += 1;
    return next();
  };
}

module.exports = { createRateLimiter };
