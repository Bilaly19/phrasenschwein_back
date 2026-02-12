const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');

async function setupServer() {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'phrasenschwein-test-'));
  process.env.DATA_PATH = path.join(tmpDir, 'data.json');
  process.env.USERS_PATH = path.join(tmpDir, 'users.json');
  process.env.ROLLING_SESSION = 'true';

  delete require.cache[require.resolve('../src/app')];
  delete require.cache[require.resolve('../src/config/env')];

  const { createApp } = require('../src/app');
  const { app } = createApp();

  const server = await new Promise((resolve) => {
    const instance = app.listen(0, () => resolve(instance));
  });

  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  async function call(method, route, body, headers = {}) {
    const response = await fetch(`${baseUrl}${route}`, {
      method,
      headers: { 'Content-Type': 'application/json', ...headers },
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
    const json = await response.json();
    return { status: response.status, body: json };
  }

  return { call, close: () => new Promise((resolve) => server.close(resolve)) };
}

test('register/login/session flow works', async () => {
  const api = await setupServer();

  const registerRes = await api.call('POST', '/api/register', { username: 'tester1', password: 'Password1' });
  assert.equal(registerRes.status, 201);

  const loginRes = await api.call('POST', '/api/login', { username: 'tester1', password: 'Password1' });
  assert.equal(loginRes.status, 200);

  const token = loginRes.body.data.token;
  assert.ok(token);

  const sessionRes = await api.call('GET', '/api/session', undefined, { Authorization: `Bearer ${token}` });
  assert.equal(sessionRes.status, 200);
  assert.equal(sessionRes.body.data.username, 'tester1');

  await api.close();
});

test('counter increment updates state', async () => {
  const api = await setupServer();

  await api.call('POST', '/api/register', { username: 'tester2', password: 'Password1' });
  const loginRes = await api.call('POST', '/api/login', { username: 'tester2', password: 'Password1' });
  const token = loginRes.body.data.token;

  const addRes = await api.call('POST', '/api/add', { name: 'Alice' }, { Authorization: `Bearer ${token}` });
  assert.equal(addRes.status, 201);

  const incrementRes = await api.call('POST', '/api/increment/Alice', {}, { Authorization: `Bearer ${token}` });
  assert.equal(incrementRes.status, 200);
  assert.equal(incrementRes.body.data.count, 1);

  const namesRes = await api.call('GET', '/api/names');
  assert.equal(namesRes.status, 200);
  assert.equal(namesRes.body.data.Alice.count, 1);

  await api.close();
});
