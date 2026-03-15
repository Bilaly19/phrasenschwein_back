function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
}

function normalizeUserRecord(row) {
  return {
    username: row.username,
    firstName: row.first_name || '',
    lastName: row.last_name || '',
    passwordHash: row.password_hash,
    role: row.role || 'USER',
    createdAt: row.created_at || null,
    createdBy: row.created_by || null
  };
}

class SqliteUsersRepository {
  constructor({ db }) {
    this.db = db;
  }

  async findUser(username) {
    const normalized = normalizeUsername(username);
    const row = this.db.prepare('SELECT * FROM users WHERE username = ?').get(normalized);
    return row ? normalizeUserRecord(row) : null;
  }

  async createUser(username, userData) {
    const normalized = normalizeUsername(username);
    const result = this.db.prepare(`
      INSERT OR IGNORE INTO users (username, first_name, last_name, password_hash, role, created_at, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      normalized,
      userData.firstName || '',
      userData.lastName || '',
      userData.passwordHash || null,
      userData.role || 'USER',
      userData.createdAt || null,
      userData.createdBy || null
    );
    return result.changes > 0;
  }

  async deleteUser(username) {
    const normalized = normalizeUsername(username);
    const result = this.db.prepare('DELETE FROM users WHERE username = ?').run(normalized);
    return result.changes > 0;
  }

  async countUsersCreatedBy(createdBy) {
    const normalized = normalizeUsername(createdBy);
    if (!normalized) return 0;
    const row = this.db.prepare('SELECT COUNT(*) as count FROM users WHERE created_by = ?').get(normalized);
    return row?.count || 0;
  }

  async updateUser(username, updater) {
    const normalized = normalizeUsername(username);
    const existing = await this.findUser(normalized);
    if (!existing) return false;

    const updated = updater(existing);
    this.db.prepare(`
      UPDATE users SET first_name = ?, last_name = ?, password_hash = ?, role = ?, created_at = ?, created_by = ?
      WHERE username = ?
    `).run(
      updated.firstName || '',
      updated.lastName || '',
      updated.passwordHash || null,
      updated.role || 'USER',
      updated.createdAt || null,
      updated.createdBy || null,
      normalized
    );
    return true;
  }

  async listUsers() {
    const rows = this.db.prepare('SELECT * FROM users ORDER BY username').all();
    return rows.map(normalizeUserRecord);
  }

  async createSession(tokenHash, sessionData) {
    this.db.prepare(`
      INSERT OR REPLACE INTO sessions (token_hash, username, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `).run(
      tokenHash,
      sessionData.username,
      sessionData.expiresAt,
      sessionData.createdAt || new Date().toISOString()
    );
  }

  async findSession(tokenHash, fallbackToken = null) {
    let row = this.db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(tokenHash);
    if (!row && fallbackToken) {
      row = this.db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(fallbackToken);
    }
    if (!row) return null;
    return {
      username: row.username,
      expiresAt: row.expires_at,
      createdAt: row.created_at
    };
  }

  async deleteSession(tokenHash, fallbackToken = null) {
    let result = this.db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
    if (result.changes === 0 && fallbackToken) {
      result = this.db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(fallbackToken);
    }
    return result.changes > 0;
  }

  async cleanupExpiredSessions(nowIso, keepTokenHash = null, keepFallbackToken = null) {
    this.db.prepare(`
      DELETE FROM sessions
      WHERE expires_at <= ?
        AND (? = '' OR token_hash != ?)
        AND (? = '' OR token_hash != ?)
    `).run(
      nowIso,
      keepTokenHash || '', keepTokenHash || '',
      keepFallbackToken || '', keepFallbackToken || ''
    );
  }

  async updateSession(tokenHash, updater, fallbackToken = null) {
    const session = await this.findSession(tokenHash, fallbackToken);
    if (!session) return false;

    const updated = updater(session);
    const keyRow = this.db.prepare('SELECT token_hash FROM sessions WHERE token_hash = ?').get(tokenHash);
    const key = keyRow ? tokenHash : fallbackToken;
    if (!key) return false;

    this.db.prepare('UPDATE sessions SET expires_at = ?, username = ? WHERE token_hash = ?').run(
      updated.expiresAt,
      updated.username,
      key
    );
    return true;
  }
}

module.exports = { SqliteUsersRepository };
