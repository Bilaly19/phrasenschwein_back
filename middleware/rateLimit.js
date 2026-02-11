function createRateLimiter({ windowMs, maxRequests, message }) {
  const buckets = new Map();

  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const bucket = buckets.get(ip);

    if (!bucket || bucket.resetAt <= now) {
      buckets.set(ip, { count: 1, resetAt: now + windowMs });
      return next();
    }

    if (bucket.count >= maxRequests) {
      return res.status(429).json({ message });
    }

    bucket.count += 1;
    return next();
  };
}

module.exports = {
  createRateLimiter
};
