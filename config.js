const path = require('path');

const DEFAULT_CORS_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:5174',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:5174'
];

function parseCorsOrigins(value) {
  if (!value || !value.trim()) {
    return DEFAULT_CORS_ORIGINS;
  }

  return value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function parseNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

const config = {
  port: parseNumber(process.env.PORT, 3000),
  corsOrigins: parseCorsOrigins(process.env.CORS_ORIGINS),
  sessionTtlMinutes: parseNumber(process.env.SESSION_TTL_MINUTES, 1440),
  paypalDonationUrl: process.env.PAYPAL_DONATION_URL?.trim() || null,
  dataPath: path.resolve(process.cwd(), process.env.DATA_PATH || './data.json'),
  usersPath: path.resolve(process.cwd(), process.env.USERS_PATH || './users.json')
};

module.exports = config;
