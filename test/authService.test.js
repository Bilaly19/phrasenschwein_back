const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bcrypt = require('bcrypt');

const { AuthService } = require('../src/backend/services/authService');

function createUsersRepositoryMock() {
  const users = {};
  const sessions = {};

  return {
    users,
    sessions,
    async createUser(username, userData) {
      if (users[username]) return false;
      users[username] = userData;
      return true;
    },
    async findUser(username) {
      return users[username] || null;
    },
    async countUsersCreatedBy(createdBy) {
      return Object.values(users).filter((user) => user?.createdBy === createdBy).length;
    },
    async updateUser(username, updater) {
      if (!users[username]) return false;
      users[username] = updater(users[username]);
      return true;
    },
    async listUsers() {
      return Object.entries(users).map(([username, user]) => ({
        username,
        createdAt: user.createdAt,
        createdBy: user.createdBy || null,
        roles: user.roles
      }));
    },
    async createSession(tokenHash, sessionData) {
      sessions[tokenHash] = sessionData;
    },
    async cleanupExpiredSessions(_nowIso, _keepTokenHash, _keepFallbackToken) {},
    async findSession(tokenHash, fallbackToken = null) {
      return sessions[tokenHash] || sessions[fallbackToken] || null;
    },
    async deleteSession(tokenHash, fallbackToken = null) {
      const key = sessions[tokenHash] ? tokenHash : fallbackToken;
      if (!key || !sessions[key]) return false;
      delete sessions[key];
      return true;
    },
    async updateSession(tokenHash, updater, fallbackToken = null) {
      const key = sessions[tokenHash] ? tokenHash : fallbackToken;
      if (!key || !sessions[key]) return false;
      sessions[key] = updater(sessions[key]);
      return true;
    }
  };
}

test('login stores only token hash in sessions', async () => {
  const repo = createUsersRepositoryMock();
  repo.users.tester = {
    passwordHash: await bcrypt.hash('12345678', 4),
    createdAt: new Date().toISOString(),
    roles: ['user']
  };

  const authService = new AuthService({ usersRepository: repo, sessionTtlMinutes: 60, sessionRolling: true, bcryptRounds: 4 });
  const loginResult = await authService.login('tester', '12345678');

  const tokenHash = crypto.createHash('sha256').update(loginResult.token).digest('hex');

  assert.ok(repo.sessions[tokenHash]);
  assert.equal(repo.sessions[loginResult.token], undefined);
});

test('getSessionByToken removes expired sessions', async () => {
  const repo = createUsersRepositoryMock();
  const authService = new AuthService({ usersRepository: repo, sessionTtlMinutes: 60, sessionRolling: true, bcryptRounds: 4 });
  const token = 'token1';
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  repo.sessions[tokenHash] = {
    username: 'tester',
    expiresAt: new Date(Date.now() - 1000).toISOString()
  };

  await assert.rejects(() => authService.getSessionByToken(token), /Session abgelaufen/);
  assert.equal(repo.sessions[tokenHash], undefined);
});

test('logout revokes active session token', async () => {
  const repo = createUsersRepositoryMock();
  const authService = new AuthService({ usersRepository: repo, sessionTtlMinutes: 60, sessionRolling: true, bcryptRounds: 4 });
  const token = 'token2';
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  repo.sessions[tokenHash] = {
    username: 'tester',
    expiresAt: new Date(Date.now() + 1000).toISOString()
  };

  await authService.logout(token);
  assert.equal(repo.sessions[tokenHash], undefined);
});

test('register stores default role user', async () => {
  const repo = createUsersRepositoryMock();
  const authService = new AuthService({ usersRepository: repo, sessionTtlMinutes: 60, sessionRolling: true, bcryptRounds: 4 });

  await authService.register('new-user', '12345678');
  assert.deepEqual(repo.users['new-user'].roles, ['user']);
});

test('register admin keeps admin and user roles', async () => {
  const repo = createUsersRepositoryMock();
  const authService = new AuthService({ usersRepository: repo, sessionTtlMinutes: 60, sessionRolling: true, bcryptRounds: 4 });

  await authService.register('admin-user', '12345678', { roles: ['admin'] });
  assert.deepEqual(repo.users['admin-user'].roles, ['admin', 'user']);
});

test('createUserByActor allows admin to assign roles', async () => {
  const repo = createUsersRepositoryMock();
  const authService = new AuthService({ usersRepository: repo, sessionTtlMinutes: 60, sessionRolling: true, bcryptRounds: 4 });

  await authService.createUserByActor({ username: 'root', roles: ['admin', 'user'] }, 'editor1', '12345678', { roles: ['editor'] });
  assert.deepEqual(repo.users.editor1.roles, ['editor', 'user']);
  assert.equal(repo.users.editor1.createdBy, 'root');
});

test('createUserByActor limits normal user to one created account', async () => {
  const repo = createUsersRepositoryMock();
  const authService = new AuthService({ usersRepository: repo, sessionTtlMinutes: 60, sessionRolling: true, bcryptRounds: 4 });

  await authService.createUserByActor({ username: 'user1', roles: ['user'] }, 'child1', '12345678', { roles: ['admin'] });
  assert.deepEqual(repo.users.child1.roles, ['user']);

  await assert.rejects(
    () => authService.createUserByActor({ username: 'user1', roles: ['user'] }, 'child2', '12345678'),
    /Du kannst nur einen weiteren User anlegen/
  );
});
