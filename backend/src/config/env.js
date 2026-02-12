const path = require('path');

const DEFAULT_CORS_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:5174',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:5174'
];

function parseNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseCorsOrigins(value) {
  if (!value || !value.trim()) {
    return DEFAULT_CORS_ORIGINS;
  }

  return value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseNumber(process.env.PORT, 3000),
  dataPath: path.resolve(process.cwd(), process.env.DATA_PATH || './data.json'),
  usersPath: path.resolve(process.cwd(), process.env.USERS_PATH || './users.json'),
  paypalDonationUrl: process.env.PAYPAL_DONATION_URL?.trim() || null,

  corsOrigins: parseCorsOrigins(process.env.CORS_ORIGINS),

  sessionTtlMinutes: parseNumber(process.env.SESSION_TTL_MINUTES, 1440),
  rollingSession: process.env.ROLLING_SESSION === 'true',

  loginRateLimitWindowMs: parseNumber(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
  loginRateLimitMaxRequests: parseNumber(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS, 20),

  passwordMinLength: parseNumber(process.env.PASSWORD_MIN_LENGTH, 8),
  passwordMaxLength: parseNumber(process.env.PASSWORD_MAX_LENGTH, 200),

  bcryptSaltRounds: parseNumber(process.env.BCRYPT_SALT_ROUNDS, 10),
  logLevel: process.env.LOG_LEVEL || 'info'
};

module.exports = { env };
