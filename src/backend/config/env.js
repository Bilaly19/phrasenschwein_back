const path = require('node:path');

const DEFAULT_CORS_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:5174',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:5174'
];

function parsePositiveNumber(rawValue, fallback) {
  const value = Number(rawValue);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function parseCorsOrigins(rawValue) {
  if (!rawValue || !rawValue.trim()) {
    return DEFAULT_CORS_ORIGINS;
  }

  return rawValue
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function loadEnv() {
  const rootDir = process.cwd();

  return {
    nodeEnv: process.env.NODE_ENV || 'development',
    isProduction: process.env.NODE_ENV === 'production',
    port: parsePositiveNumber(process.env.PORT, 3000),
    corsOrigins: parseCorsOrigins(process.env.CORS_ORIGINS),
    sessionTtlMinutes: parsePositiveNumber(process.env.SESSION_TTL_MINUTES, 60 * 24),
    sessionRolling: process.env.SESSION_ROLLING !== 'false',
    bcryptRounds: parsePositiveNumber(process.env.BCRYPT_ROUNDS, 10),
    paypalDonationUrl: process.env.PAYPAL_DONATION_URL?.trim() || null,
    dataPath: path.resolve(rootDir, process.env.DATA_PATH || './data.json'),
    usersPath: path.resolve(rootDir, process.env.USERS_PATH || './users.json'),
    authRateLimitWindowMs: parsePositiveNumber(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
    authRateLimitMax: parsePositiveNumber(process.env.AUTH_RATE_LIMIT_MAX, 20)
  };
}

module.exports = {
  loadEnv
};
