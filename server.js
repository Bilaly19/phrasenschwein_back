const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const config = require('./config');
const { readData, writeData, readUsers, writeUsers } = require('./storage');
const { requestLogger, logInfo } = require('./logger');
const { validateBody, validateParams, validators } = require('./validation');
const { authMiddleware, extractToken, resolveSession, buildSession } = require('./middleware/auth');
const { asyncHandler, errorHandler } = require('./middleware/error');
const { createRateLimiter } = require('./middleware/rateLimit');

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
app.use(requestLogger);

app.get('/api/names', asyncHandler(async (req, res) => {
  const { valuePerClick, ...rest } = await readData(config.dataPath);
  res.json(rest);
}));

app.get('/api/config', asyncHandler(async (req, res) => {
  const data = await readData(config.dataPath);
  res.json({ valuePerClick: data.valuePerClick });
}));

app.post('/api/config', authMiddleware(config.usersPath), validateBody(validators.validateConfig), asyncHandler(async (req, res) => {
  const data = await readData(config.dataPath);
  data.valuePerClick = req.body.valuePerClick;
  await writeData(config.dataPath, data);
  res.json({ message: 'Wert gespeichert' });
}));

app.post('/api/add', authMiddleware(config.usersPath), validateBody(validators.validateNamePayload), asyncHandler(async (req, res) => {
  const data = await readData(config.dataPath);
  const { name } = req.body;

  if (!data[name]) {
    data[name] = { count: 0, lastClickedAt: null };
    await writeData(config.dataPath, data);
    return res.status(201).json({ message: 'Hinzugefügt' });
  }

  return res.status(400).json({ message: 'Name existiert bereits' });
}));

app.post('/api/increment/:name', authMiddleware(config.usersPath), validateParams(validators.validateNameParams), asyncHandler(async (req, res) => {
  const data = await readData(config.dataPath);
  const { name } = req.params;

  if (data[name]) {
    data[name].count += 1;
    data[name].lastClickedAt = new Date().toISOString();
    await writeData(config.dataPath, data);
    return res.json({ message: 'Zähler erhöht' });
  }

  return res.status(404).json({ message: 'Name nicht gefunden' });
}));

app.post('/api/reset', authMiddleware(config.usersPath), validateBody(validators.validateEmptyBody), asyncHandler(async (req, res) => {
  const data = await readData(config.dataPath);

  for (const name in data) {
    if (name !== 'valuePerClick') {
      data[name].count = 0;
      data[name].lastClickedAt = null;
    }
  }

  await writeData(config.dataPath, data);
  res.json({ message: 'Zurückgesetzt' });
}));

app.delete('/api/delete/:name', authMiddleware(config.usersPath), validateParams(validators.validateNameParams), asyncHandler(async (req, res) => {
  const data = await readData(config.dataPath);
  const { name } = req.params;

  if (data[name]) {
    delete data[name];
    await writeData(config.dataPath, data);
    return res.json({ message: 'Name gelöscht' });
  }

  return res.status(404).json({ message: 'Name nicht gefunden' });
}));

app.post('/api/register', loginRegisterRateLimit, validateBody(validators.validateRegisterLogin), asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  const usersData = await readUsers(config.usersPath);

  if (usersData.users?.[username]) {
    return res.status(400).json({ message: 'Benutzer existiert bereits' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  usersData.users[username] = {
    passwordHash,
    createdAt: new Date().toISOString()
  };

  await writeUsers(config.usersPath, usersData);
  logInfo('Benutzer registriert', { username });
  res.status(201).json({ message: 'Benutzer registriert' });
}));

app.post('/api/login', loginRegisterRateLimit, validateBody(validators.validateRegisterLogin), asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  const usersData = await readUsers(config.usersPath);
  const user = usersData.users?.[username];

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ message: 'Login fehlgeschlagen' });
  }

  const token = uuidv4();
  usersData.sessions[token] = buildSession(username);
  await writeUsers(config.usersPath, usersData);
  logInfo('Benutzer eingeloggt', { username });
  return res.json({ token, username });
}));

app.post('/api/logout', validateBody(validators.validateEmptyBody), asyncHandler(async (req, res) => {
  const token = extractToken(req.headers.authorization);
  const usersData = await readUsers(config.usersPath);

  if (token) {
    const session = resolveSession(usersData.sessions, token);
    if (session) {
      delete usersData.sessions[token];
      await writeUsers(config.usersPath, usersData);
    }
  }

  res.json({ message: 'Abgemeldet' });
}));

app.use(errorHandler);

app.listen(config.port, () => {
  logInfo('Server gestartet', {
    port: config.port,
    dataPath: config.dataPath,
    usersPath: config.usersPath,
    sessionTtlMinutes: config.sessionTtlMinutes,
    corsOrigins: config.corsOrigins
  });
});
