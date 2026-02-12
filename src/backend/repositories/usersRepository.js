const { readJsonOrDefault, writeJsonAtomic } = require('./jsonFileStore');

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
    const data = await this.readRaw();
    if (data.users[username]) return false;

    data.users[username] = userData;
    await this.writeRaw(data);
    return true;
  }

  async createSession(token, sessionData) {
    const data = await this.readRaw();
    data.sessions[token] = sessionData;
    await this.writeRaw(data);
  }

  async findSession(token) {
    const data = await this.readRaw();
    return data.sessions[token] || null;
  }

  async deleteSession(token) {
    const data = await this.readRaw();
    if (!data.sessions[token]) return false;

    delete data.sessions[token];
    await this.writeRaw(data);
    return true;
  }

  async cleanupExpiredSessions(nowIso, keepToken = null) {
    const nowMs = new Date(nowIso).getTime();
    const data = await this.readRaw();
    let changed = false;

    for (const [token, session] of Object.entries(data.sessions)) {
      if (token === keepToken) continue;
      if (!session?.expiresAt) continue;

      const expiresMs = new Date(session.expiresAt).getTime();
      if (Number.isFinite(expiresMs) && expiresMs <= nowMs) {
        delete data.sessions[token];
        changed = true;
      }
    }

    if (changed) {
      await this.writeRaw(data);
    }
  }

  async updateSession(token, updater) {
    const data = await this.readRaw();
    const current = data.sessions[token];
    if (!current) return false;

    data.sessions[token] = updater(current);
    await this.writeRaw(data);
    return true;
  }
}

module.exports = {
  JsonUsersRepository
};
