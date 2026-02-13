const { readJsonOrDefault, writeJsonAtomic, withFileLock } = require('./jsonFileStore');

const defaultUsers = {
  users: {},
  sessions: {}
};

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
    const data = await this.readRaw();
    return data.users[username] || null;
  }

  async createUser(username, userData) {
    return withFileLock(this.usersPath, async () => {
      const data = await this.readRaw();
      if (data.users[username]) return false;

      data.users[username] = userData;
      await this.writeRaw(data);
      return true;
    });
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
