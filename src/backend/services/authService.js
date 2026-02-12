const bcrypt = require('bcrypt');
const crypto = require('node:crypto');
const { AppError } = require('../utils/http');

class AuthService {
  constructor({ usersRepository, sessionTtlMinutes, sessionRolling, bcryptRounds }) {
    this.usersRepository = usersRepository;
    this.sessionTtlMinutes = sessionTtlMinutes;
    this.sessionRolling = sessionRolling;
    this.bcryptRounds = bcryptRounds;
  }

  buildSession(username) {
    return {
      username,
      expiresAt: new Date(Date.now() + this.sessionTtlMinutes * 60 * 1000).toISOString(),
      createdAt: new Date().toISOString()
    };
  }

  isSessionExpired(session) {
    const expiresAt = new Date(session.expiresAt).getTime();
    return !Number.isFinite(expiresAt) || expiresAt <= Date.now();
  }

  async register(username, password) {
    const passwordHash = await bcrypt.hash(password, this.bcryptRounds);
    const created = await this.usersRepository.createUser(username, {
      passwordHash,
      createdAt: new Date().toISOString(),
      roles: ['user']
    });

    if (!created) {
      throw new AppError(400, 'USER_EXISTS', 'Benutzer existiert bereits');
    }
  }

  async login(username, password) {
    const user = await this.usersRepository.findUser(username);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      throw new AppError(401, 'LOGIN_FAILED', 'Login fehlgeschlagen');
    }

    const token = crypto.randomUUID();
    const session = this.buildSession(username);
    await this.usersRepository.createSession(token, session);

    return {
      token,
      username,
      expiresAt: session.expiresAt
    };
  }

  async logout(token) {
    if (!token) return;
    await this.usersRepository.deleteSession(token);
  }

  async getSessionByToken(token, { touch = false } = {}) {
    if (!token) {
      throw new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt');
    }

    await this.usersRepository.cleanupExpiredSessions(new Date().toISOString(), token);
    const session = await this.usersRepository.findSession(token);

    if (!session) {
      throw new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt');
    }

    if (this.isSessionExpired(session)) {
      await this.usersRepository.deleteSession(token);
      throw new AppError(401, 'SESSION_EXPIRED', 'Session abgelaufen');
    }

    if (touch && this.sessionRolling) {
      const nextExpiresAt = new Date(Date.now() + this.sessionTtlMinutes * 60 * 1000).toISOString();
      await this.usersRepository.updateSession(token, (current) => ({ ...current, expiresAt: nextExpiresAt }));
      session.expiresAt = nextExpiresAt;
    }

    return session;
  }
}

module.exports = {
  AuthService
};
