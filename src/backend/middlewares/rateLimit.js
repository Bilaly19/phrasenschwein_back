const { AppError } = require('../utils/http');

function createRateLimiter({
  windowMs,
  maxRequests,
  keyGenerator = null,
  maxBuckets = 10000,
  cleanupIntervalMs = 60 * 1000
}) {
  const buckets = new Map();
  let lastCleanupAt = 0;

  function pruneBuckets(now) {
    if (now - lastCleanupAt < cleanupIntervalMs && buckets.size <= maxBuckets) {
      return;
    }

    lastCleanupAt = now;

    for (const [key, bucket] of buckets.entries()) {
      if (bucket.resetAt <= now) {
        buckets.delete(key);
      }
    }

    if (buckets.size <= maxBuckets) {
      return;
    }

    const sorted = [...buckets.entries()].sort((a, b) => a[1].resetAt - b[1].resetAt);
    const toDelete = sorted.slice(0, buckets.size - maxBuckets);
    for (const [key] of toDelete) {
      buckets.delete(key);
    }
  }

  return (req, _res, next) => {
    const key = keyGenerator
      ? keyGenerator(req)
      : (req.ip || req.socket.remoteAddress || 'unknown');

    if (!key) {
      next();
      return;
    }

    const now = Date.now();
    pruneBuckets(now);

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
