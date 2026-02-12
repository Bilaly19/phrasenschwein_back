const express = require('express');
const cors = require('cors');

const defaultConfig = require('./config');
const storage = require('./storage');
const { requestLogger, logInfo } = require('./logger');
const { validateBody, validateParams, validators } = require('./validation');
const { authMiddleware, extractToken, resolveSession, buildSession } = require('./middleware/auth');
const { asyncHandler, errorHandler } = require('./middleware/error');
const { createRateLimiter } = require('./middleware/rateLimit');
const namesService = require('./services/namesService');
const authService = require('./services/authService');

function createApp({ config = defaultConfig, deps = {} } = {}) {
  const {
    readData = storage.readData,
    writeData = storage.writeData,
    readUsers = storage.readUsers,
    writeUsers = storage.writeUsers,
    requestLoggerMiddleware = requestLogger,
    logInfoFn = logInfo
  } = deps;

  const app = express();

  const corsOptions = {
    origin(origin, callback) {
      if (!origin || config.corsOrigins.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error('CORS: Origin nicht erlaubt'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'DELETE']
  };

  const loginRegisterRateLimit = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    maxRequests: 20,
    message: 'Zu viele Versuche, bitte später erneut.'
  });

  app.use(cors(corsOptions));
  app.use(express.json());
  app.use(requestLoggerMiddleware);

  app.get('/api/names', asyncHandler(async (req, res) => {
    const names = await namesService.getNames(readData, config.dataPath);
    res.json(names);
  }));

  app.get('/api/config', asyncHandler(async (req, res) => {
    const payload = await namesService.getConfig(readData, config.dataPath);
    res.json(payload);
  }));

  app.get('/api/donation-link', asyncHandler(async (req, res) => {
    if (!config.paypalDonationUrl) {
      return res.status(404).json({ message: 'PayPal-Spendenlink ist nicht konfiguriert' });
    }

    return res.json({ url: config.paypalDonationUrl });
  }));

  app.post('/api/config', authMiddleware(config.usersPath), validateBody(validators.validateConfig), asyncHandler(async (req, res) => {
    await namesService.updateConfig(readData, writeData, config.dataPath, req.body.valuePerClick);
    res.json({ message: 'Wert gespeichert' });
  }));

  app.post('/api/add', authMiddleware(config.usersPath), validateBody(validators.validateNamePayload), asyncHandler(async (req, res) => {
    const created = await namesService.addName(readData, writeData, config.dataPath, req.body.name);

    if (created) {
      return res.status(201).json({ message: 'Hinzugefügt' });
    }

    return res.status(400).json({ message: 'Name existiert bereits' });
  }));

  app.post('/api/increment/:name', authMiddleware(config.usersPath), validateParams(validators.validateNameParams), asyncHandler(async (req, res) => {
    const found = await namesService.incrementName(readData, writeData, config.dataPath, req.params.name);

    if (found) {
      return res.json({ message: 'Zähler erhöht' });
    }

    return res.status(404).json({ message: 'Name nicht gefunden' });
  }));

  app.post('/api/reset', authMiddleware(config.usersPath), validateBody(validators.validateEmptyBody), asyncHandler(async (req, res) => {
    await namesService.resetNames(readData, writeData, config.dataPath);
    res.json({ message: 'Zurückgesetzt' });
  }));

  app.delete('/api/delete/:name', authMiddleware(config.usersPath), validateParams(validators.validateNameParams), asyncHandler(async (req, res) => {
    const found = await namesService.deleteName(readData, writeData, config.dataPath, req.params.name);

    if (found) {
      return res.json({ message: 'Name gelöscht' });
    }

    return res.status(404).json({ message: 'Name nicht gefunden' });
  }));

  app.post('/api/register', loginRegisterRateLimit, validateBody(validators.validateRegisterLogin), asyncHandler(async (req, res) => {
    const { username, password } = req.body;
    const created = await authService.registerUser(readUsers, writeUsers, config.usersPath, username, password);

    if (!created) {
      return res.status(400).json({ message: 'Benutzer existiert bereits' });
    }

    logInfoFn('Benutzer registriert', { username });
    res.status(201).json({ message: 'Benutzer registriert' });
  }));

  app.post('/api/login', loginRegisterRateLimit, validateBody(validators.validateLogin), asyncHandler(async (req, res) => {
    const { username, password } = req.body;
    const result = await authService.loginUser(readUsers, writeUsers, config.usersPath, username, password, buildSession);

    if (!result) {
      return res.status(401).json({ message: 'Login fehlgeschlagen' });
    }

    logInfoFn('Benutzer eingeloggt', { username: result.username });
    return res.json(result);
  }));

  app.post('/api/logout', validateBody(validators.validateEmptyBody), asyncHandler(async (req, res) => {
    const token = extractToken(req.headers.authorization);
    await authService.logoutUser(readUsers, writeUsers, config.usersPath, token, resolveSession);
    res.json({ message: 'Abgemeldet' });
  }));

  app.use(errorHandler);

  return app;
}

module.exports = {
  createApp
};
