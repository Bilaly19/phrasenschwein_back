const { AppError } = require('../utils/http');

function createRateLimiter({ windowMs, maxRequests }) {
  const buckets = new Map();

  return (req, _res, next) => {
    const key = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const bucket = buckets.get(key);

    if (!bucket || bucket.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }

    if (bucket.count >= maxRequests) {
      next(new AppError(429, 'RATE_LIMITED', 'Zu viele Versuche, bitte später erneut.'));
      return;
    }

    bucket.count += 1;
    next();
  };
}

module.exports = {
  createRateLimiter
};
