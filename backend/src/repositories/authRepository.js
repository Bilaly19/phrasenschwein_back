const { atomicWriteJson, readJsonWithFallback } = require('./jsonFileStore');

class AuthRepository {
  async getState() {}
  async saveState(_state) {}
}

class InMemoryFileAuthRepository extends AuthRepository {
  constructor(filePath) {
    super();
    this.filePath = filePath;
  }

  async getState() {
    const raw = await readJsonWithFallback(this.filePath, { users: {}, sessions: {} });
    return {
      users: raw.users && typeof raw.users === 'object' ? raw.users : {},
      sessions: raw.sessions && typeof raw.sessions === 'object' ? raw.sessions : {}
    };
  }

  async saveState(state) {
    await atomicWriteJson(this.filePath, {
      users: state.users || {},
      sessions: state.sessions || {}
    });
    return state;
  }
}

module.exports = { AuthRepository, InMemoryFileAuthRepository };
