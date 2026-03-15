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

function parseBoundedInteger(rawValue, fallback, min, max) {
  const value = Number(rawValue);
  if (!Number.isInteger(value)) return fallback;
  if (value < min || value > max) return fallback;
  return value;
}

function parsePort(rawValue, fallback) {
  const value = Number(rawValue);
  return Number.isInteger(value) && value > 0 && value <= 65535 ? value : fallback;
}

function parseBoolean(rawValue, fallback) {
  if (rawValue === undefined || rawValue === null) {
    return fallback;
  }

  const normalized = String(rawValue).trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  return fallback;
}

function parseEnabledByOne(rawValue) {
  if (rawValue === undefined || rawValue === null) {
    return false;
  }

  return String(rawValue).trim() === '1';
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

function parseResolvedPath(rootDir, rawValue, fallbackRelativePath) {
  const value = typeof rawValue === 'string' ? rawValue.trim() : '';
  return path.resolve(rootDir, value || fallbackRelativePath);
}

function loadEnv() {
  const rootDir = process.cwd();
  const nodeEnv = (process.env.NODE_ENV || 'development').trim();
  const isProduction = nodeEnv === 'production';
  const configuredCorsOrigins = process.env.CORS_ALLOWED_ORIGINS ?? process.env.CORS_ORIGINS;
  const openaiBaseUrlRaw = process.env.OPENAI_BASE_URL?.trim();
  const openaiBaseUrl = openaiBaseUrlRaw && openaiBaseUrlRaw.length > 0
    ? openaiBaseUrlRaw.replace(/\/+$/, '')
    : 'https://api.openai.com/v1';

  return {
    nodeEnv,
    isProduction,
    port: parsePort(process.env.PORT, 3000),
    corsOrigins: isProduction && (!configuredCorsOrigins || !configuredCorsOrigins.trim())
      ? []
      : parseCorsOrigins(configuredCorsOrigins),
    sessionTtlMinutes: parsePositiveNumber(process.env.SESSION_TTL_MINUTES, 60 * 24),
    sessionRolling: parseBoolean(process.env.SESSION_ROLLING, true),
    bcryptRounds: parsePositiveNumber(process.env.BCRYPT_ROUNDS, 10),
    paypalDonationUrl: process.env.PAYPAL_DONATION_URL?.trim() || null,
    dataPath: parseResolvedPath(rootDir, process.env.DATA_PATH, './data.json'),
    usersPath: parseResolvedPath(rootDir, process.env.USERS_PATH, './users.json'),
    pigsPath: parseResolvedPath(rootDir, process.env.PIGS_PATH, './pigs.json'),
    dbPath: parseResolvedPath(rootDir, process.env.DB_PATH, './phrasenschwein.db'),
    authRateLimitWindowMs: parsePositiveNumber(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
    authRateLimitMax: parsePositiveNumber(process.env.AUTH_RATE_LIMIT_MAX, 20),
    authAccountRateLimitMax: parsePositiveNumber(
      process.env.AUTH_ACCOUNT_RATE_LIMIT_MAX,
      parsePositiveNumber(process.env.AUTH_RATE_LIMIT_MAX, 20)
    ),
    authLogoutRateLimitMax: parsePositiveNumber(
      process.env.AUTH_LOGOUT_RATE_LIMIT_MAX,
      Math.max(parsePositiveNumber(process.env.AUTH_RATE_LIMIT_MAX, 20), 60)
    ),
    openaiApiKey: process.env.OPENAI_API_KEY?.trim() || '',
    openaiModel: process.env.OPENAI_MODEL?.trim() || 'gpt-4o-mini',
    openaiBaseUrl,
    openaiTimeoutMs: parsePositiveNumber(process.env.OPENAI_TIMEOUT_MS, 20000),
    assistantMaxHistory: parseBoundedInteger(process.env.ASSISTANT_MAX_HISTORY, 8, 1, 20),
    assistantMaxPigs: parseBoundedInteger(process.env.ASSISTANT_MAX_PIGS, 12, 1, 50),
    devSeedUserEnabled: parseEnabledByOne(process.env.DEV_SEED_USER),
    devSeedIsAdmin: parseEnabledByOne(process.env.DEV_SEED_IS_ADMIN),
    devSeedUsername: process.env.DEV_SEED_USERNAME?.trim() || '',
    devSeedPassword: process.env.DEV_SEED_PASSWORD || ''
  };
}

module.exports = {
  loadEnv
};
