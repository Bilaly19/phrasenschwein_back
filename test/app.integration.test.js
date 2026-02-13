const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const request = require('supertest');

const { createApp } = require('../src/backend/app/createApp');

async function createContext() {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'phrasenschwein-it-'));
  const dataPath = path.join(tempDir, 'data.json');
  const usersPath = path.join(tempDir, 'users.json');

  await fs.writeFile(dataPath, JSON.stringify({ valuePerClick: 0.5 }, null, 2));
  await fs.writeFile(usersPath, JSON.stringify({ users: {}, sessions: {} }, null, 2));

  const { app } = createApp({
    config: {
      nodeEnv: 'test',
      isProduction: false,
      dataPath,
      usersPath,
      authRateLimitMax: 1000
    }
  });

  return {
    req: request(app),
    async cleanup() {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  };
}

test('auth + names flow works end-to-end', async (t) => {
  const ctx = await createContext();
  t.after(async () => ctx.cleanup());

  const registerResponse = await ctx.req.post('/api/register').send({ username: 'tester01', password: 'sicheres-passwort' });
  assert.equal(registerResponse.status, 201);

  const loginResponse = await ctx.req.post('/api/login').send({ username: 'tester01', password: 'sicheres-passwort' });
  assert.equal(loginResponse.status, 200);
  assert.equal(typeof loginResponse.body.token, 'string');

  const addResponse = await ctx.req
    .post('/api/add')
    .set('authorization', `Bearer ${loginResponse.body.token}`)
    .send({ name: 'Anna' });
  assert.equal(addResponse.status, 201);

  const incrementResponse = await ctx.req
    .post('/api/increment/Anna')
    .set('authorization', `Bearer ${loginResponse.body.token}`)
    .send({});
  assert.equal(incrementResponse.status, 200);

  const namesResponse = await ctx.req.get('/api/names');
  assert.equal(namesResponse.status, 200);
  assert.equal(namesResponse.body.Anna.count, 1);
  assert.match(namesResponse.body.Anna.lastClickedAt, /^\d{4}-\d{2}-\d{2}T/);
});
