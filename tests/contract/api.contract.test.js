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
      authRateLimitMax: 1000,
      authAccountRateLimitMax: 1000,
      authLogoutRateLimitMax: 1000
    }
  });

  return {
    req: request(app),
    async cleanup() {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  };
}

async function registerUser(req, username, password = '12345678') {
  const res = await req.post('/api/register').send({
    username,
    firstName: 'First',
    lastName: 'Last',
    password
  });

  assert.equal(res.status, 201);
  assert.equal(res.body.ok, true);
  return res;
}

async function loginUser(req, username, password = '12345678') {
  const res = await req.post('/api/login').send({ username, password });
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
  return res.body.data;
}

test('register accepts username/firstName/lastName/password and auto-creates matching entry', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  const registerRes = await registerUser(ctx.req, 'alice');
  assert.equal(registerRes.body.data.user.username, 'alice');
  assert.equal(registerRes.body.data.user.firstName, 'First');
  assert.equal(registerRes.body.data.user.lastName, 'Last');
  assert.equal(registerRes.body.data.user.role, 'USER');

  const namesRes = await ctx.req.get('/api/names');
  assert.equal(namesRes.status, 200);
  assert.equal(namesRes.body.ok, true);
  assert.deepEqual(namesRes.body.data.alice, {
    name: 'alice',
    clicks: 0,
    lastClickAt: null,
    ownerUsername: 'alice'
  });
});

test('register returns USERNAME_TAKEN for duplicate username', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  await registerUser(ctx.req, 'alice');
  const duplicate = await ctx.req.post('/api/register').send({
    username: 'alice',
    firstName: 'Other',
    lastName: 'User',
    password: '12345678'
  });

  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.body.ok, false);
  assert.equal(duplicate.body.error.code, 'USERNAME_TAKEN');
});

test('register returns NAME_ALREADY_EXISTS when matching name entry already exists', async (t) => {
  const ctx = await createContractContext({
    seedData: {
      valuePerClick: 0.5,
      alice: {
        name: 'alice',
        clicks: 2,
        lastClickAt: '2025-01-01T00:00:00.000Z',
        ownerUsername: 'alice'
      }
    }
  });
  t.after(async () => ctx.cleanup());

  const res = await ctx.req.post('/api/register').send({
    username: 'alice',
    firstName: 'First',
    lastName: 'Last',
    password: '12345678'
  });

  assert.equal(res.status, 409);
  assert.equal(res.body.ok, false);
  assert.equal(res.body.error.code, 'NAME_ALREADY_EXISTS');
});

test('GET /api/session returns username and role for authenticated user', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  await registerUser(ctx.req, 'bob');
  const login = await loginUser(ctx.req, 'bob');

  const sessionRes = await ctx.req
    .get('/api/session')
    .set('authorization', `Bearer ${login.token}`);

  assert.equal(sessionRes.status, 200);
  assert.equal(sessionRes.body.ok, true);
  assert.equal(sessionRes.body.data.username, 'bob');
  assert.equal(sessionRes.body.data.role, 'USER');
  assert.equal(typeof sessionRes.body.data.expiresAt, 'string');
});

test('GET /api/names returns shared board for all users', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  await registerUser(ctx.req, 'alice');
  await registerUser(ctx.req, 'bob');

  const allNames = await ctx.req.get('/api/names');
  assert.equal(allNames.status, 200);
  assert.equal(allNames.body.ok, true);
  assert.ok(allNames.body.data.alice);
  assert.ok(allNames.body.data.bob);
});

test('login recreates missing own name entry automatically', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  await registerUser(ctx.req, 'alice');
  const firstLogin = await loginUser(ctx.req, 'alice');
  const auth = { authorization: `Bearer ${firstLogin.token}` };

  const deleteSelf = await ctx.req.delete('/api/delete/alice').set(auth);
  assert.equal(deleteSelf.status, 200);
  assert.equal(deleteSelf.body.ok, true);

  const namesAfterDelete = await ctx.req.get('/api/names');
  assert.equal(namesAfterDelete.body.data.alice, undefined);

  await loginUser(ctx.req, 'alice');

  const namesAfterRelogin = await ctx.req.get('/api/names');
  assert.deepEqual(namesAfterRelogin.body.data.alice, {
    name: 'alice',
    clicks: 0,
    lastClickAt: null,
    ownerUsername: 'alice'
  });
});

test('user cannot increment or delete someone else entry (403)', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  await registerUser(ctx.req, 'alice');
  await registerUser(ctx.req, 'bob');
  const aliceLogin = await loginUser(ctx.req, 'alice');
  const auth = { authorization: `Bearer ${aliceLogin.token}` };

  const incrementOther = await ctx.req.post('/api/increment/bob').set(auth).send({});
  assert.equal(incrementOther.status, 403);
  assert.equal(incrementOther.body.ok, false);
  assert.equal(incrementOther.body.error.code, 'FORBIDDEN');

  const deleteOther = await ctx.req.delete('/api/delete/bob').set(auth);
  assert.equal(deleteOther.status, 403);
  assert.equal(deleteOther.body.ok, false);
  assert.equal(deleteOther.body.error.code, 'FORBIDDEN');
});

test('user can increment and delete own entry', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  await registerUser(ctx.req, 'alice');
  const aliceLogin = await loginUser(ctx.req, 'alice');
  const auth = { authorization: `Bearer ${aliceLogin.token}` };

  const incrementSelf = await ctx.req.post('/api/increment/alice').set(auth).send({});
  assert.equal(incrementSelf.status, 200);
  assert.equal(incrementSelf.body.ok, true);

  const namesAfterIncrement = await ctx.req.get('/api/names');
  assert.equal(namesAfterIncrement.body.data.alice.clicks, 1);
  assert.match(namesAfterIncrement.body.data.alice.lastClickAt, /^\d{4}-\d{2}-\d{2}T/);

  const deleteSelf = await ctx.req.delete('/api/delete/alice').set(auth);
  assert.equal(deleteSelf.status, 200);
  assert.equal(deleteSelf.body.ok, true);

  const namesAfterDelete = await ctx.req.get('/api/names');
  assert.equal(namesAfterDelete.body.data.alice, undefined);
});

test('POST /api/reset resets only authenticated user entry', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  await registerUser(ctx.req, 'alice');
  await registerUser(ctx.req, 'bob');

  const aliceLogin = await loginUser(ctx.req, 'alice');
  const bobLogin = await loginUser(ctx.req, 'bob');

  await ctx.req.post('/api/increment/alice').set({ authorization: `Bearer ${aliceLogin.token}` }).send({});
  await ctx.req.post('/api/increment/alice').set({ authorization: `Bearer ${aliceLogin.token}` }).send({});
  await ctx.req.post('/api/increment/bob').set({ authorization: `Bearer ${bobLogin.token}` }).send({});

  const resetAlice = await ctx.req.post('/api/reset').set({ authorization: `Bearer ${aliceLogin.token}` }).send({});
  assert.equal(resetAlice.status, 200);
  assert.equal(resetAlice.body.ok, true);

  const namesAfterReset = await ctx.req.get('/api/names');
  assert.equal(namesAfterReset.body.data.alice.clicks, 0);
  assert.equal(namesAfterReset.body.data.alice.lastClickAt, null);
  assert.equal(namesAfterReset.body.data.bob.clicks, 1);
});

test('POST /api/add is disabled with 410 and standard error envelope', async (t) => {
  const ctx = await createContractContext();
  t.after(async () => ctx.cleanup());

  const addRes = await ctx.req.post('/api/add').send({ name: 'someone' });
  assert.equal(addRes.status, 410);
  assert.equal(addRes.body.ok, false);
  assert.equal(addRes.body.error.code, 'MANUAL_NAME_ADD_DISABLED');
  assert.equal(typeof addRes.body.error.message, 'string');
});
