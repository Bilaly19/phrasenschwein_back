const test = require('node:test');
const assert = require('node:assert/strict');

const { AuthService } = require('../src/backend/services/authService');

function createUsersRepositoryMock() {
  const users = {
    tester: { passwordHash: null }
  };
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
    async createSession(token, sessionData) {
      sessions[token] = sessionData;
    },
    async cleanupExpiredSessions() {},
    async findSession(token) {
      return sessions[token] || null;
    },
    async deleteSession(token) {
      delete sessions[token];
      return true;
    },
    async updateSession(token, updater) {
      if (!sessions[token]) return false;
      sessions[token] = updater(sessions[token]);
      return true;
    }
  };
}

test('getSessionByToken entfernt abgelaufene Sessions', async () => {
  const repo = createUsersRepositoryMock();
  const authService = new AuthService({ usersRepository: repo, sessionTtlMinutes: 60, sessionRolling: true, bcryptRounds: 4 });

  repo.sessions.token1 = {
    username: 'tester',
    expiresAt: new Date(Date.now() - 1000).toISOString()
  };

  await assert.rejects(() => authService.getSessionByToken('token1'), /Session abgelaufen/);
  assert.equal(repo.sessions.token1, undefined);
});
