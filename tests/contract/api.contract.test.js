const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const request = require('supertest');
const { createApp } = require('../../src/backend/app/createApp');

async function createContractContext(options = {}) {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'phrasenschwein-contract-'));
  const dataPath = path.join(tempDir, 'data.json');
  const usersPath = path.join(tempDir, 'users.json');

  const seedData = options.seedData || { valuePerClick: 0.5 };
  const seedUsers = options.seedUsers || { users: {}, sessions: {} };

  await fs.writeFile(dataPath, JSON.stringify(seedData, null, 2), 'utf8');
  await fs.writeFile(usersPath, JSON.stringify(seedUsers, null, 2), 'utf8');

  const { app } = createApp({
    config: {
      nodeEnv: 'test',
      isProduction: false,
      dataPath,
      usersPath,
      paypalDonationUrl: options.paypalDonationUrl || null,
      corsOrigins: ['http://localhost:5173'],
      authRateLimitMax: 1000
    }
  });

  return {
    req: request(app),
    dataPath,
    usersPath,
    async cleanup() {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  };
}

async function registerAndLogin(req, username = 'alice', password = '12345678') {
  const registerRes = await req.post('/api/register').send({ username, password });
  assert.equal(registerRes.status, 201);

  const loginRes = await req.post('/api/login').send({ username, password });
  assert.equal(loginRes.status, 200);
  assert.equal(typeof loginRes.body.token, 'string');
  return loginRes.body;
}

test('GET /api/names and GET /api/config return expected public shapes', async (t) => {
  const ctx = await createContractContext({
    seedData: {
      valuePerClick: 0.2,
      Bilal: { count: 3, lastClickedAt: '2025-05-09T21:33:01.731Z' }
    }
  });
  t.after(async () => ctx.cleanup());

  const namesRes = await ctx.req.get('/api/names');
  assert.equal(namesRes.status, 200);
  assert.deepEqual(namesRes.body, {
    Bilal: { count: 3, lastClickedAt: '2025-05-09T21:33:01.731Z' }
  });

  const configRes = await ctx.req.get('/api/config');
  assert.equal(configRes.status, 200);
  assert.deepEqual(configRes.body, { valuePerClick: 0.2 });
});

test('GET /api/donation-link returns 404 when not configured, 200 when configured', async (t) => {
  const withoutLink = await createContractContext();
  t.after(async () => withoutLink.cleanup());
  const notFoundRes = await withoutLink.req.get('/api/donation-link');
  assert.equal(notFoundRes.status, 404);
  assert.equal(notFoundRes.body.ok, false);
  assert.equal(notFoundRes.body.error.code, 'DONATION_LINK_NOT_CONFIGURED');
  assert.equal(notFoundRes.body.error.message, 'PayPal-Spendenlink ist nicht konfiguriert');
  assert.equal(Array.isArray(notFoundRes.body.error.details), true);

  const withLink = await createContractContext({ paypalDonationUrl: 'https://paypal.example/donate' });
  t.after(async () => withLink.cleanup());
  const okRes = await withLink.req.get('/api/donation-link');
  assert.equal(okRes.status, 200);
  assert.deepEqual(okRes.body, { url: 'https://paypal.example/donate' });
});

test('POST /api/register and POST /api/login happy path', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  const registerRes = await ctx.req.post('/api/register').send({ username: 'alice', password: '12345678' });
  assert.equal(registerRes.status, 201);
  assert.deepEqual(registerRes.body, { message: 'Benutzer registriert' });

  const loginRes = await ctx.req.post('/api/login').send({ username: 'alice', password: '12345678' });
  assert.equal(loginRes.status, 200);
  assert.equal(loginRes.body.username, 'alice');
  assert.equal(typeof loginRes.body.token, 'string');
  assert.equal(typeof loginRes.body.expiresAt, 'string');
});

test('auth endpoints return expected validation and login failure errors', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  const invalidRegister = await ctx.req.post('/api/register').send({ username: 'a', password: 'short' });
  assert.equal(invalidRegister.status, 400);
  assert.equal(invalidRegister.body.error.code, 'VALIDATION_ERROR');
  assert.equal(Array.isArray(invalidRegister.body.error.details), true);

  await ctx.req.post('/api/register').send({ username: 'alice', password: '12345678' });

  const duplicateRegister = await ctx.req.post('/api/register').send({ username: 'alice', password: '12345678' });
  assert.equal(duplicateRegister.status, 400);
  assert.equal(duplicateRegister.body.error.code, 'USER_EXISTS');

  const failedLogin = await ctx.req.post('/api/login').send({ username: 'alice', password: 'wrong-password' });
  assert.equal(failedLogin.status, 401);
  assert.equal(failedLogin.body.error.code, 'LOGIN_FAILED');
});

test('auth-required routes reject missing token and expose session when logged in', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  const unauthorizedSession = await ctx.req.get('/api/session');
  assert.equal(unauthorizedSession.status, 401);
  assert.equal(unauthorizedSession.body.error.code, 'UNAUTHORIZED');

  const login = await registerAndLogin(ctx.req, 'bob', '12345678');
  const sessionRes = await ctx.req
    .get('/api/session')
    .set('authorization', `Bearer ${login.token}`);

  assert.equal(sessionRes.status, 200);
  assert.equal(sessionRes.body.username, 'bob');
  assert.equal(typeof sessionRes.body.expiresAt, 'string');
});

test('POST /api/logout revokes token and returns stable response', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  const login = await registerAndLogin(ctx.req, 'charlie', '12345678');

  const logoutRes = await ctx.req
    .post('/api/logout')
    .set('authorization', `Bearer ${login.token}`)
    .send({});
  assert.equal(logoutRes.status, 200);
  assert.deepEqual(logoutRes.body, { message: 'Abgemeldet' });

  const sessionAfterLogout = await ctx.req
    .get('/api/session')
    .set('authorization', `Bearer ${login.token}`);
  assert.equal(sessionAfterLogout.status, 401);
  assert.equal(sessionAfterLogout.body.error.code, 'UNAUTHORIZED');
});

test('names mutation endpoints require auth and support add/increment/reset/delete flow', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  const unauthorizedAdd = await ctx.req.post('/api/add').send({ name: 'Anna' });
  assert.equal(unauthorizedAdd.status, 401);
  assert.equal(unauthorizedAdd.body.error.code, 'UNAUTHORIZED');

  const login = await registerAndLogin(ctx.req, 'dora', '12345678');
  const auth = { authorization: `Bearer ${login.token}` };

  const updateConfig = await ctx.req.post('/api/config').set(auth).send({ valuePerClick: 0.4 });
  assert.equal(updateConfig.status, 200);
  assert.deepEqual(updateConfig.body, { message: 'Wert gespeichert' });

  const addRes = await ctx.req.post('/api/add').set(auth).send({ name: 'Anna' });
  assert.equal(addRes.status, 201);
  assert.equal(typeof addRes.body.message, 'string');

  const incrementRes = await ctx.req.post('/api/increment/Anna').set(auth).send({});
  assert.equal(incrementRes.status, 200);
  assert.equal(typeof incrementRes.body.message, 'string');

  const namesAfterIncrement = await ctx.req.get('/api/names');
  assert.equal(namesAfterIncrement.status, 200);
  assert.equal(namesAfterIncrement.body.Anna.count, 1);

  const resetRes = await ctx.req.post('/api/reset').set(auth).send({});
  assert.equal(resetRes.status, 200);
  assert.equal(typeof resetRes.body.message, 'string');

  const deleteRes = await ctx.req.delete('/api/delete/Anna').set(auth);
  assert.equal(deleteRes.status, 200);
  assert.equal(typeof deleteRes.body.message, 'string');
});

test('names endpoints return expected validation and not-found error cases', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());
  const login = await registerAndLogin(ctx.req, 'erik', '12345678');
  const auth = { authorization: `Bearer ${login.token}` };

  const invalidConfig = await ctx.req.post('/api/config').set(auth).send({ valuePerClick: -1 });
  assert.equal(invalidConfig.status, 400);
  assert.equal(invalidConfig.body.error.code, 'VALIDATION_ERROR');

  const invalidName = await ctx.req.post('/api/add').set(auth).send({ name: '' });
  assert.equal(invalidName.status, 400);
  assert.equal(invalidName.body.error.code, 'VALIDATION_ERROR');

  const missingIncrement = await ctx.req.post('/api/increment/Unknown').set(auth).send({});
  assert.equal(missingIncrement.status, 404);
  assert.equal(missingIncrement.body.error.code, 'NAME_NOT_FOUND');

  const missingDelete = await ctx.req.delete('/api/delete/Unknown').set(auth);
  assert.equal(missingDelete.status, 404);
  assert.equal(missingDelete.body.error.code, 'NAME_NOT_FOUND');
});

test('unknown routes return not found contract', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  const res = await ctx.req.get('/api/does-not-exist');
  assert.equal(res.status, 404);
  assert.equal(res.body.error.code, 'NOT_FOUND');
});
