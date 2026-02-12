const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const { createApp } = require('../app');

async function startTestServer() {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'phrasenschwein-test-'));
  const dataPath = path.join(tempDir, 'data.json');
  const usersPath = path.join(tempDir, 'users.json');

  await fs.writeFile(dataPath, JSON.stringify({ valuePerClick: 0.5 }, null, 2));
  await fs.writeFile(usersPath, JSON.stringify({ users: {}, sessions: {} }, null, 2));

  const app = createApp({
    config: {
      port: 0,
      corsOrigins: ['http://localhost:5173'],
      sessionTtlMinutes: 60,
      paypalDonationUrl: null,
      dataPath,
      usersPath
    },
    deps: {
      requestLoggerMiddleware: (_req, _res, next) => next(),
      logInfoFn: () => {}
    }
  });

  const server = await new Promise((resolve) => {
    const instance = app.listen(0, () => resolve(instance));
  });

  const port = server.address().port;

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    async close() {
      await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  };
}

test('auth + names flow: registrieren, einloggen, Namen anlegen und erhöhen', async () => {
  const ctx = await startTestServer();

  try {
    const registerResponse = await fetch(`${ctx.baseUrl}/api/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'tester01', password: 'sicheres-passwort' })
    });
    assert.equal(registerResponse.status, 201);

    const loginResponse = await fetch(`${ctx.baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'tester01', password: 'sicheres-passwort' })
    });
    assert.equal(loginResponse.status, 200);

    const loginPayload = await loginResponse.json();
    assert.equal(typeof loginPayload.token, 'string');

    const addResponse = await fetch(`${ctx.baseUrl}/api/add`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${loginPayload.token}`
      },
      body: JSON.stringify({ name: 'Anna' })
    });
    assert.equal(addResponse.status, 201);

    const incrementResponse = await fetch(`${ctx.baseUrl}/api/increment/Anna`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${loginPayload.token}`
      },
      body: JSON.stringify({})
    });
    assert.equal(incrementResponse.status, 200);

    const namesResponse = await fetch(`${ctx.baseUrl}/api/names`);
    const namesPayload = await namesResponse.json();

    assert.equal(namesResponse.status, 200);
    assert.equal(namesPayload.Anna.count, 1);
    assert.match(namesPayload.Anna.lastClickedAt, /^\d{4}-\d{2}-\d{2}T/);
  } finally {
    await ctx.close();
  }
});
