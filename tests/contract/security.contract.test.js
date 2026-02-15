const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const request = require('supertest');
const { createApp } = require('../../src/backend/app/createApp');

async function createContractContext(options = {}) {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'phrasenschwein-security-contract-'));
  const dataPath = path.join(tempDir, 'data.json');
  const usersPath = path.join(tempDir, 'users.json');

  await fs.writeFile(dataPath, JSON.stringify({ valuePerClick: 0.5 }, null, 2), 'utf8');
  await fs.writeFile(usersPath, JSON.stringify({ users: {}, sessions: {} }, null, 2), 'utf8');

  const { app } = createApp({
    config: {
      nodeEnv: options.nodeEnv || 'test',
      isProduction: Boolean(options.isProduction),
      dataPath,
      usersPath,
      corsOrigins: options.corsOrigins || ['http://localhost:5173'],
      authRateLimitWindowMs: options.authRateLimitWindowMs || 60_000,
      authRateLimitMax: options.authRateLimitMax || 1000,
      authAccountRateLimitMax: options.authAccountRateLimitMax || options.authRateLimitMax || 1000,
      authLogoutRateLimitMax: options.authLogoutRateLimitMax || options.authRateLimitMax || 1000
    }
  });

  return {
    req: request(app),
    async cleanup() {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  };
}

async function withEnv(tempEnv, fn) {
  const previous = {};
  for (const key of Object.keys(tempEnv)) {
    previous[key] = process.env[key];
    const value = tempEnv[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  try {
    return await fn();
  } finally {
    for (const key of Object.keys(tempEnv)) {
      if (previous[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previous[key];
      }
    }
  }
}

test('per-account limiter throttles repeated failed login attempts for the same username', async (t) => {
  const ctx = await createContractContext({
    nodeEnv: 'production',
    isProduction: true,
    authRateLimitMax: 20,
    authAccountRateLimitMax: 2
  });
  t.after(async () => ctx.cleanup());

  const attempt1 = await ctx.req.post('/api/login').send({ username: 'same-user', password: '12345678' });
  const attempt2 = await ctx.req.post('/api/login').send({ username: 'same-user', password: '12345678' });
  const attempt3 = await ctx.req.post('/api/login').send({ username: 'same-user', password: '12345678' });

  assert.equal(attempt1.status, 401);
  assert.equal(attempt1.body.error.code, 'LOGIN_FAILED');
  assert.equal(attempt2.status, 401);
  assert.equal(attempt2.body.error.code, 'LOGIN_FAILED');

  assert.equal(attempt3.status, 429);
  assert.equal(attempt3.body.ok, false);
  assert.equal(attempt3.body.error.code, 'RATE_LIMITED');
});

test('non-production disables per-account limiter so repeated failed login attempts are not locked instantly', async (t) => {
  const ctx = await createContractContext({
    nodeEnv: 'development',
    isProduction: false,
    authRateLimitMax: 20,
    authAccountRateLimitMax: 2
  });
  t.after(async () => ctx.cleanup());

  const attempt1 = await ctx.req.post('/api/login').send({ username: 'same-user', password: '12345678' });
  const attempt2 = await ctx.req.post('/api/login').send({ username: 'same-user', password: '12345678' });
  const attempt3 = await ctx.req.post('/api/login').send({ username: 'same-user', password: '12345678' });

  assert.equal(attempt1.status, 401);
  assert.equal(attempt1.body.error.code, 'LOGIN_FAILED');
  assert.equal(attempt2.status, 401);
  assert.equal(attempt2.body.error.code, 'LOGIN_FAILED');
  assert.equal(attempt3.status, 401);
  assert.equal(attempt3.body.error.code, 'LOGIN_FAILED');
});

test('different usernames on same IP are not blocked by per-account limiter; IP limiter applies', async (t) => {
  const ctx = await createContractContext({
    authRateLimitMax: 5,
    authAccountRateLimitMax: 2
  });
  t.after(async () => ctx.cleanup());

  const usernames = ['user01', 'user02', 'user03', 'user04', 'user05'];
  for (const username of usernames) {
    const res = await ctx.req.post('/api/login').send({ username, password: '12345678' });
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'LOGIN_FAILED');
  }

  const blocked = await ctx.req.post('/api/login').send({ username: 'user06', password: '12345678' });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.body.error.code, 'RATE_LIMITED');
});

test('login and logout are rate-limited separately so repeated logout does not consume login budget', async (t) => {
  const ctx = await createContractContext({
    authRateLimitMax: 3,
    authAccountRateLimitMax: 100,
    authLogoutRateLimitMax: 10
  });
  t.after(async () => ctx.cleanup());

  const registerRes = await ctx.req.post('/api/register').send({
    username: 'limit-user',
    firstName: 'Limit',
    lastName: 'User',
    password: '12345678'
  });
  assert.equal(registerRes.status, 201);
  assert.equal(registerRes.body.ok, true);

  const login1 = await ctx.req.post('/api/login').send({ username: 'limit-user', password: '12345678' });
  assert.equal(login1.status, 200);

  const logout1 = await ctx.req.post('/api/logout').set('authorization', `Bearer ${login1.body.data.token}`).send({});
  assert.equal(logout1.status, 200);

  const logoutAgain = await ctx.req.post('/api/logout').set('authorization', `Bearer ${login1.body.data.token}`).send({});
  assert.equal(logoutAgain.status, 401);
  assert.equal(logoutAgain.body.error.code, 'UNAUTHORIZED');

  const login2 = await ctx.req.post('/api/login').send({ username: 'limit-user', password: '12345678' });
  assert.equal(login2.status, 200);

  const login3Blocked = await ctx.req.post('/api/login').send({ username: 'limit-user', password: '12345678' });
  assert.equal(login3Blocked.status, 429);
  assert.equal(login3Blocked.body.error.code, 'RATE_LIMITED');
});

test('production CORS allowlist allows configured Origin and sets CORS headers via CORS_ALLOWED_ORIGINS', async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'phrasenschwein-security-cors-allow-'));
  const dataPath = path.join(tempDir, 'data.json');
  const usersPath = path.join(tempDir, 'users.json');
  await fs.writeFile(dataPath, JSON.stringify({ valuePerClick: 0.5 }, null, 2), 'utf8');
  await fs.writeFile(usersPath, JSON.stringify({ users: {}, sessions: {} }, null, 2), 'utf8');

  await withEnv({
    NODE_ENV: 'production',
    CORS_ALLOWED_ORIGINS: 'https://allowed.example',
    CORS_ORIGINS: undefined,
    DATA_PATH: dataPath,
    USERS_PATH: usersPath
  }, async () => {
    const { app } = createApp();
    const res = await request(app)
      .get('/api/config')
      .set('Origin', 'https://allowed.example');

    assert.equal(res.status, 200);
    assert.equal(res.headers['access-control-allow-origin'], 'https://allowed.example');
    assert.equal(res.headers['access-control-allow-credentials'], 'true');
    assert.match(res.headers.vary || '', /Origin/);
    assert.equal(res.body.ok, true);
  });

  await fs.rm(tempDir, { recursive: true, force: true });
});

test('production CORS denies unknown Origin with structured 403 and no stack leakage', async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'phrasenschwein-security-cors-deny-'));
  const dataPath = path.join(tempDir, 'data.json');
  const usersPath = path.join(tempDir, 'users.json');
  await fs.writeFile(dataPath, JSON.stringify({ valuePerClick: 0.5 }, null, 2), 'utf8');
  await fs.writeFile(usersPath, JSON.stringify({ users: {}, sessions: {} }, null, 2), 'utf8');

  await withEnv({
    NODE_ENV: 'production',
    CORS_ALLOWED_ORIGINS: 'https://allowed.example',
    CORS_ORIGINS: undefined,
    DATA_PATH: dataPath,
    USERS_PATH: usersPath
  }, async () => {
    const { app } = createApp();
    const res = await request(app)
      .get('/api/config')
      .set('Origin', 'https://denied.example');

    assert.equal(res.status, 403);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.error.code, 'CORS_ORIGIN_DENIED');
    assert.equal(res.body.error.stack, undefined);
    assert.equal(res.text.includes('"stack"'), false);
  });

  await fs.rm(tempDir, { recursive: true, force: true });
});
