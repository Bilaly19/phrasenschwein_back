const bcrypt = require('bcrypt');
const crypto = require('node:crypto');
const { AppError } = require('../utils/http');

function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
}

function normalizeHumanName(name) {
  return typeof name === 'string' ? name.trim() : '';
}

function normalizeRole(role) {
  const upper = typeof role === 'string' ? role.trim().toUpperCase() : '';
  return upper || 'USER';
}

class AuthService {
  constructor({ usersRepository, namesRepository, sessionTtlMinutes, sessionRolling, bcryptRounds }) {
    this.usersRepository = usersRepository;
    this.namesRepository = namesRepository;
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

  async ensureNameEntry(username) {
    const existing = await this.namesRepository.getName(username);
    if (existing) return;

    await this.namesRepository.addName(username, username);
  }

  hasAdminRole(actor) {
    if (typeof actor?.role === 'string' && actor.role.toUpperCase() === 'ADMIN') {
      return true;
    }

    if (Array.isArray(actor?.roles)) {
      return actor.roles.some((role) => String(role).trim().toLowerCase() === 'admin');
    }

    return false;
  }

  async register({ username, firstName, lastName, password }, { role = 'USER', createdBy = null } = {}) {
    const normalizedUsername = normalizeUsername(username);
    const normalizedFirstName = normalizeHumanName(firstName);
    const normalizedLastName = normalizeHumanName(lastName);

    const existingUser = await this.usersRepository.findUser(normalizedUsername);
    if (existingUser) {
      throw new AppError(409, 'USERNAME_TAKEN', 'Username bereits vergeben');
    }

    const existingNameEntry = await this.namesRepository.getName(normalizedUsername);
    if (existingNameEntry) {
      throw new AppError(409, 'NAME_ALREADY_EXISTS', 'Name existiert bereits');
    }

    const passwordHash = await bcrypt.hash(password, this.bcryptRounds);
    const created = await this.usersRepository.createUser(normalizedUsername, {
      username: normalizedUsername,
      firstName: normalizedFirstName,
      lastName: normalizedLastName,
      passwordHash,
      role: normalizeRole(role),
      createdAt: new Date().toISOString(),
      createdBy: normalizeUsername(createdBy) || null
    });

    if (!created) {
      throw new AppError(409, 'USERNAME_TAKEN', 'Username bereits vergeben');
    }

    const nameCreated = await this.namesRepository.addName(normalizedUsername, normalizedUsername);
    if (!nameCreated) {
      await this.usersRepository.deleteUser(normalizedUsername);
      throw new AppError(409, 'NAME_ALREADY_EXISTS', 'Name existiert bereits');
    }

    return {
      username: normalizedUsername,
      firstName: normalizedFirstName,
      lastName: normalizedLastName,
      role: normalizeRole(role)
    };
  }

  async createUserByActor(actor, username, password, { firstName = '', lastName = '', roles = ['USER'] } = {}) {
    const isActorAdmin = this.hasAdminRole(actor);

    if (!isActorAdmin) {
      const createdCount = await this.usersRepository.countUsersCreatedBy(actor?.username);
      if (createdCount >= 1) {
        throw new AppError(403, 'USER_CREATE_LIMIT_REACHED', 'Du kannst nur einen weiteren User anlegen');
      }
    }

    const effectiveRole = isActorAdmin && Array.isArray(roles) && roles.length > 0
      ? normalizeRole(roles[0])
      : 'USER';

    return this.register(
      {
        username,
        firstName: firstName || username,
        lastName: lastName || '',
        password
      },
      {
        role: effectiveRole,
        createdBy: actor?.username || null
      }
    );
  }

  async setUserRolesByAdmin(targetUsername, roles) {
    const updated = await this.usersRepository.updateUser(targetUsername, (existing) => ({
      ...existing,
      role: normalizeRole(Array.isArray(roles) ? roles[0] : 'USER')
    }));

    if (!updated) {
      throw new AppError(404, 'USER_NOT_FOUND', 'Benutzer nicht gefunden');
    }
  }

  async listUsers() {
    const users = await this.usersRepository.listUsers();
    return users
      .map((user) => ({
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        createdAt: user.createdAt,
        createdBy: user.createdBy,
        role: normalizeRole(user.role)
      }))
      .sort((a, b) => a.username.localeCompare(b.username));
  }

  async login(username, password) {
    const normalizedUsername = normalizeUsername(username);
    const user = await this.usersRepository.findUser(normalizedUsername);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      throw new AppError(401, 'LOGIN_FAILED', 'Login fehlgeschlagen');
    }

    await this.ensureNameEntry(normalizedUsername);

    const token = crypto.randomUUID();
    const tokenHash = this.hashSessionToken(token);
    const session = this.buildSession(normalizedUsername);
    await this.usersRepository.createSession(tokenHash, session);

    return {
      token,
      username: normalizedUsername,
      role: normalizeRole(user.role),
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

    const user = await this.usersRepository.findUser(session.username);
    await this.ensureNameEntry(session.username);

    return {
      ...session,
      role: normalizeRole(user?.role)
    };
  }
}

module.exports = {
  AuthService
};
