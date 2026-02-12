const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const { AppError } = require('../utils/appError');

function isSessionExpired(expiresAt) {
  return !expiresAt || Number.isNaN(new Date(expiresAt).getTime()) || new Date(expiresAt).getTime() <= Date.now();
}

class AuthService {
  constructor(authRepository, options) {
    this.authRepository = authRepository;
    this.options = options;
  }

  buildSession(username) {
    return {
      username,
      expiresAt: new Date(Date.now() + this.options.sessionTtlMinutes * 60 * 1000).toISOString()
    };
  }

  async register(username, password) {
    const state = await this.authRepository.getState();
    if (state.users[username]) {
      throw new AppError(400, 'USER_EXISTS', 'Benutzer existiert bereits');
    }

    const passwordHash = await bcrypt.hash(password, this.options.bcryptSaltRounds);
    state.users[username] = { passwordHash, createdAt: new Date().toISOString() };
    await this.authRepository.saveState(state);
  }

  async login(username, password) {
    const state = await this.authRepository.getState();
    const user = state.users[username];
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      throw new AppError(401, 'INVALID_LOGIN', 'Login fehlgeschlagen');
    }

    const token = uuidv4();
    state.sessions[token] = this.buildSession(username);
    await this.authRepository.saveState(state);
    return { token, username, expiresAt: state.sessions[token].expiresAt };
  }

  async logout(token) {
    if (!token) {
      return;
    }

    const state = await this.authRepository.getState();
    if (state.sessions[token]) {
      delete state.sessions[token];
      await this.authRepository.saveState(state);
    }
  }

  async resolveSession(token, { refresh = false } = {}) {
    if (!token) {
      throw new AppError(401, 'UNAUTHENTICATED', 'Nicht eingeloggt');
    }

    const state = await this.authRepository.getState();
    const session = state.sessions[token];

    if (!session) {
      throw new AppError(401, 'UNAUTHENTICATED', 'Nicht eingeloggt');
    }

    if (typeof session === 'string') {
      return { username: session, expiresAt: null };
    }

    if (isSessionExpired(session.expiresAt)) {
      delete state.sessions[token];
      await this.authRepository.saveState(state);
      throw new AppError(401, 'SESSION_EXPIRED', 'Session abgelaufen');
    }

    if (refresh && this.options.rollingSession) {
      state.sessions[token] = this.buildSession(session.username);
      await this.authRepository.saveState(state);
      return state.sessions[token];
    }

    return session;
  }

  async cleanupExpiredSessions() {
    const state = await this.authRepository.getState();
    let changed = false;

    for (const [token, session] of Object.entries(state.sessions)) {
      if (typeof session === 'object' && isSessionExpired(session.expiresAt)) {
        delete state.sessions[token];
        changed = true;
      }
    }

    if (changed) {
      await this.authRepository.saveState(state);
    }
  }
}

module.exports = { AuthService };
