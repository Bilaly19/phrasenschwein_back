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

  hashSessionToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
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
    const tokenHash = this.hashSessionToken(token);
    const session = this.buildSession(username);
    await this.usersRepository.createSession(tokenHash, session);

    return {
      token,
      username,
      expiresAt: session.expiresAt
    };
  }

  async logout(token) {
    if (!token) return;
    const tokenHash = this.hashSessionToken(token);
    await this.usersRepository.deleteSession(tokenHash, token);
  }

  async getSessionByToken(token, { touch = false } = {}) {
    if (!token) {
      throw new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt');
    }

    const tokenHash = this.hashSessionToken(token);
    await this.usersRepository.cleanupExpiredSessions(new Date().toISOString(), tokenHash, token);
    const session = await this.usersRepository.findSession(tokenHash, token);

    if (!session) {
      throw new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt');
    }

    if (this.isSessionExpired(session)) {
      await this.usersRepository.deleteSession(tokenHash, token);
      throw new AppError(401, 'SESSION_EXPIRED', 'Session abgelaufen');
    }

    if (touch && this.sessionRolling) {
      const nextExpiresAt = new Date(Date.now() + this.sessionTtlMinutes * 60 * 1000).toISOString();
      await this.usersRepository.updateSession(tokenHash, (current) => ({ ...current, expiresAt: nextExpiresAt }), token);
      session.expiresAt = nextExpiresAt;
    }

    return session;
  }
}

module.exports = {
  AuthService
};
