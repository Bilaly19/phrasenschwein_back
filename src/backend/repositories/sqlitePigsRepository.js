const crypto = require('node:crypto');

const DEFAULT_VALUE_PER_CLICK = 0.5;

function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
}

function normalizePigTitle(title) {
  const trimmed = typeof title === 'string' ? title.trim() : '';
  return trimmed || 'Phrasenschwein';
}

function hashInviteToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

class SqlitePigsRepository {
  constructor({ db }) {
    this.db = db;
  }

  async listPigsForUser(username) {
    const normalized = normalizeUsername(username);
    const rows = this.db.prepare(`
      SELECT p.id, p.title, p.value_per_click, p.created_at, p.created_by, pm.role
      FROM pigs p
      JOIN pig_members pm ON p.id = pm.pig_id
      WHERE pm.username = ?
      ORDER BY p.created_at ASC
    `).all(normalized);

    return rows.map((row) => ({
      id: row.id,
      title: row.title,
      valuePerClick: row.value_per_click,
      createdAt: row.created_at || null,
      createdBy: row.created_by || null,
      role: row.role || 'member'
    }));
  }

  async getPig(pigId) {
    const pig = this.db.prepare('SELECT * FROM pigs WHERE id = ?').get(pigId);
    if (!pig) return null;

    const members = this.db.prepare('SELECT * FROM pig_members WHERE pig_id = ?').all(pigId);
    const names = this.db.prepare('SELECT * FROM pig_names WHERE pig_id = ?').all(pigId);
    const invites = this.db.prepare('SELECT * FROM pig_invites WHERE pig_id = ?').all(pigId);

    const membersObj = {};
    for (const m of members) {
      membersObj[m.username] = { username: m.username, role: m.role, joinedAt: m.joined_at };
    }

    const namesObj = {};
    for (const n of names) {
      namesObj[n.username] = {
        name: n.name,
        clicks: n.clicks,
        lastClickAt: n.last_click_at,
        ownerUsername: n.owner_username
      };
    }

    const invitesArr = invites.map((i) => ({
      id: i.id,
      tokenHash: i.token_hash,
      createdAt: i.created_at,
      createdBy: i.created_by,
      expiresAt: i.expires_at,
      maxUses: i.max_uses,
      uses: i.uses,
      revokedAt: i.revoked_at
    }));

    return {
      id: pig.id,
      title: pig.title,
      valuePerClick: pig.value_per_click,
      paypalLink: pig.paypal_link || '',
      createdAt: pig.created_at || null,
      createdBy: pig.created_by || null,
      members: membersObj,
      names: namesObj,
      invites: invitesArr
    };
  }

  async getPigNames(pigId) {
    const pig = await this.getPig(pigId);
    if (!pig) return null;
    return pig.names;
  }

  async getPigConfig(pigId) {
    const row = this.db.prepare('SELECT value_per_click, paypal_link FROM pigs WHERE id = ?').get(pigId);
    if (!row) return null;
    return { valuePerClick: row.value_per_click, paypalLink: row.paypal_link || '' };
  }

  async setPigConfig(pigId, { valuePerClick, paypalLink }) {
    const result = this.db.prepare(`
      UPDATE pigs SET value_per_click = ?, paypal_link = ? WHERE id = ?
    `).run(
      Number.isFinite(valuePerClick) ? valuePerClick : DEFAULT_VALUE_PER_CLICK,
      typeof paypalLink === 'string' ? paypalLink.trim() : '',
      pigId
    );
    return result.changes > 0;
  }

  async createPig({ title, createdBy }) {
    const normalizedCreatedBy = normalizeUsername(createdBy);
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const normalizedTitle = normalizePigTitle(title);

    this.db.transaction(() => {
      this.db.prepare(`
        INSERT INTO pigs (id, title, created_at, created_by, value_per_click, paypal_link)
        VALUES (?, ?, ?, ?, ?, '')
      `).run(id, normalizedTitle, now, normalizedCreatedBy, DEFAULT_VALUE_PER_CLICK);

      this.db.prepare(`
        INSERT INTO pig_members (pig_id, username, role, joined_at)
        VALUES (?, ?, 'admin', ?)
      `).run(id, normalizedCreatedBy, now);

      this.db.prepare(`
        INSERT INTO pig_names (pig_id, username, name, clicks, last_click_at, owner_username)
        VALUES (?, ?, ?, 0, NULL, ?)
      `).run(id, normalizedCreatedBy, normalizedCreatedBy, normalizedCreatedBy);
    })();

    return {
      id,
      title: normalizedTitle,
      createdAt: now,
      createdBy: normalizedCreatedBy,
      valuePerClick: DEFAULT_VALUE_PER_CLICK,
      paypalLink: '',
      members: { [normalizedCreatedBy]: { username: normalizedCreatedBy, role: 'admin', joinedAt: now } },
      names: { [normalizedCreatedBy]: { name: normalizedCreatedBy, clicks: 0, lastClickAt: null, ownerUsername: normalizedCreatedBy } },
      invites: []
    };
  }

  async addInvite(pigId, inviteRecord) {
    const pig = this.db.prepare('SELECT id FROM pigs WHERE id = ?').get(pigId);
    if (!pig) return null;

    this.db.prepare(`
      INSERT INTO pig_invites (id, pig_id, token_hash, created_at, created_by, expires_at, max_uses, uses, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      inviteRecord.id,
      pigId,
      inviteRecord.tokenHash,
      inviteRecord.createdAt || new Date().toISOString(),
      inviteRecord.createdBy || null,
      inviteRecord.expiresAt,
      inviteRecord.maxUses || 1,
      inviteRecord.uses || 0,
      inviteRecord.revokedAt || null
    );

    return inviteRecord;
  }

  async acceptInvite(token, username) {
    const normalizedUsername = normalizeUsername(username);
    const tokenHash = hashInviteToken(token);
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();

    return this.db.transaction(() => {
      const invite = this.db.prepare('SELECT * FROM pig_invites WHERE token_hash = ?').get(tokenHash);

      if (!invite) return { ok: false, reason: 'INVITE_NOT_FOUND' };
      if (invite.revoked_at) return { ok: false, reason: 'INVITE_REVOKED' };

      const expiresAtMs = new Date(invite.expires_at).getTime();
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
        return { ok: false, reason: 'INVITE_EXPIRED' };
      }

      if (invite.uses >= invite.max_uses) {
        return { ok: false, reason: 'INVITE_MAX_USES_REACHED' };
      }

      const pigId = invite.pig_id;
      const existing = this.db.prepare(
        'SELECT username FROM pig_members WHERE pig_id = ? AND username = ?'
      ).get(pigId, normalizedUsername);
      const alreadyMember = Boolean(existing);

      if (!alreadyMember) {
        this.db.prepare(`
          INSERT OR IGNORE INTO pig_members (pig_id, username, role, joined_at)
          VALUES (?, ?, 'member', ?)
        `).run(pigId, normalizedUsername, nowIso);

        this.db.prepare(`
          INSERT OR IGNORE INTO pig_names (pig_id, username, name, clicks, last_click_at, owner_username)
          VALUES (?, ?, ?, 0, NULL, ?)
        `).run(pigId, normalizedUsername, normalizedUsername, normalizedUsername);

        this.db.prepare('UPDATE pig_invites SET uses = uses + 1 WHERE token_hash = ?').run(tokenHash);
      }

      return { ok: true, pigId, alreadyMember };
    })();
  }

  async incrementName(pigId, username) {
    const normalizedUsername = normalizeUsername(username);
    const result = this.db.prepare(`
      UPDATE pig_names SET clicks = clicks + 1, last_click_at = ?
      WHERE pig_id = ? AND username = ?
    `).run(new Date().toISOString(), pigId, normalizedUsername);
    return result.changes > 0;
  }

  async resetName(pigId, username) {
    const normalizedUsername = normalizeUsername(username);
    const result = this.db.prepare(`
      UPDATE pig_names SET clicks = 0, last_click_at = NULL
      WHERE pig_id = ? AND username = ?
    `).run(pigId, normalizedUsername);
    return result.changes > 0;
  }
}

module.exports = { SqlitePigsRepository, hashInviteToken };
