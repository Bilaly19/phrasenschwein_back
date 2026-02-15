const { readJsonOrDefault, writeJsonAtomic, withFileLock } = require('./jsonFileStore');

const defaultUsers = {
  users: {},
  sessions: {}
};

function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
}

function normalizeUserRecord(key, user) {
  const username = normalizeUsername(user?.username) || key;
  return {
    username,
    firstName: typeof user?.firstName === 'string' ? user.firstName : '',
    lastName: typeof user?.lastName === 'string' ? user.lastName : '',
    passwordHash: user?.passwordHash,
    role: typeof user?.role === 'string' && user.role.trim() ? user.role.trim().toUpperCase() : 'USER',
    createdAt: user?.createdAt || null,
    createdBy: user?.createdBy || null
  };
}

class JsonUsersRepository {
  constructor({ usersPath }) {
    this.usersPath = usersPath;
  }

  async readRaw() {
    const data = await readJsonOrDefault(this.usersPath, defaultUsers);
    data.users = data.users && typeof data.users === 'object' ? data.users : {};
    data.sessions = data.sessions && typeof data.sessions === 'object' ? data.sessions : {};
    return data;
  }

  async writeRaw(data) {
    await writeJsonAtomic(this.usersPath, { ...defaultUsers, ...data });
  }

  async findUser(username) {
    const normalizedUsername = normalizeUsername(username);
    const data = await this.readRaw();
    const user = data.users[normalizedUsername];
    if (!user) return null;
    return normalizeUserRecord(normalizedUsername, user);
  }

  async createUser(username, userData) {
    const normalizedUsername = normalizeUsername(username);

    return withFileLock(this.usersPath, async () => {
      const data = await this.readRaw();
      if (data.users[normalizedUsername]) return false;

      data.users[normalizedUsername] = normalizeUserRecord(normalizedUsername, {
        ...userData,
        username: normalizedUsername
      });
      await this.writeRaw(data);
      return true;
    });
  }

  async deleteUser(username) {
    const normalizedUsername = normalizeUsername(username);

    return withFileLock(this.usersPath, async () => {
      const data = await this.readRaw();
      if (!data.users[normalizedUsername]) return false;

      delete data.users[normalizedUsername];
      await this.writeRaw(data);
      return true;
    });
  }

  async countUsersCreatedBy(createdBy) {
    const normalizedCreatedBy = normalizeUsername(createdBy);
    const data = await this.readRaw();
    if (!normalizedCreatedBy) return 0;

    return Object.values(data.users)
      .map((user) => normalizeUserRecord(normalizeUsername(user?.username || ''), user))
      .filter((user) => normalizeUsername(user.createdBy) === normalizedCreatedBy)
      .length;
  }

  async updateUser(username, updater) {
    const normalizedUsername = normalizeUsername(username);

    return withFileLock(this.usersPath, async () => {
      const data = await this.readRaw();
      if (!data.users[normalizedUsername]) return false;

      const current = normalizeUserRecord(normalizedUsername, data.users[normalizedUsername]);
      data.users[normalizedUsername] = normalizeUserRecord(normalizedUsername, updater(current));
      await this.writeRaw(data);
      return true;
    });
  }

  async listUsers() {
    const data = await this.readRaw();
    return Object.entries(data.users).map(([username, user]) => normalizeUserRecord(username, user));
  }

  async createSession(tokenHash, sessionData) {
    await withFileLock(this.usersPath, async () => {
      const data = await this.readRaw();
      data.sessions[tokenHash] = sessionData;
      await this.writeRaw(data);
    });
  }

  async findSession(tokenHash, fallbackToken = null) {
    const data = await this.readRaw();
    return data.sessions[tokenHash] || data.sessions[fallbackToken] || null;
  }

  async deleteSession(tokenHash, fallbackToken = null) {
    return withFileLock(this.usersPath, async () => {
      const data = await this.readRaw();
      const key = data.sessions[tokenHash] ? tokenHash : fallbackToken;
      if (!key || !data.sessions[key]) return false;

      delete data.sessions[key];
      await this.writeRaw(data);
      return true;
    });
  }

  async cleanupExpiredSessions(nowIso, keepTokenHash = null, keepFallbackToken = null) {
    const nowMs = new Date(nowIso).getTime();
    await withFileLock(this.usersPath, async () => {
      const data = await this.readRaw();
      let changed = false;

      for (const [token, session] of Object.entries(data.sessions)) {
        if (token === keepTokenHash || token === keepFallbackToken) continue;

        if (!session || typeof session !== 'object' || !session.expiresAt) {
          delete data.sessions[token];
          changed = true;
          continue;
        }

        const expiresMs = new Date(session.expiresAt).getTime();
        if (!Number.isFinite(expiresMs) || expiresMs <= nowMs) {
          delete data.sessions[token];
          changed = true;
        }
      }

      if (changed) {
        await this.writeRaw(data);
      }
    });
  }

  async updateSession(tokenHash, updater, fallbackToken = null) {
    return withFileLock(this.usersPath, async () => {
      const data = await this.readRaw();
      const key = data.sessions[tokenHash] ? tokenHash : fallbackToken;
      if (!key || !data.sessions[key]) return false;

      data.sessions[key] = updater(data.sessions[key]);
      await this.writeRaw(data);
      return true;
    });
  }
}

module.exports = {
  JsonUsersRepository
};