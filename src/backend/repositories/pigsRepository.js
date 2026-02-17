const crypto = require('node:crypto');
const { readJsonOrDefault, writeJsonAtomic, withFileLock } = require('./jsonFileStore');

const DEFAULT_VALUE_PER_CLICK = 0.5;

const defaultPigs = {
  pigs: {}
};

function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
}

function normalizePigTitle(title) {
  const trimmed = typeof title === 'string' ? title.trim() : '';
  return trimmed || 'Phrasenschwein';
}

function normalizePig(pig) {
  if (!pig || typeof pig !== 'object') return null;

  const id = typeof pig.id === 'string' ? pig.id : '';
  if (!id) return null;

  const valuePerClick = Number.isFinite(pig.valuePerClick) ? pig.valuePerClick : DEFAULT_VALUE_PER_CLICK;
  const members = pig.members && typeof pig.members === 'object' ? pig.members : {};
  const names = pig.names && typeof pig.names === 'object' ? pig.names : {};
  const invites = Array.isArray(pig.invites) ? pig.invites : [];

  return {
    ...pig,
    id,
    title: normalizePigTitle(pig.title),
    valuePerClick,
    members,
    names,
    invites
  };
}

function normalizeNameEntry(key, entry) {
  const normalizedKey = normalizeUsername(key);

  if (!entry || typeof entry !== 'object') {
    return buildNameEntry(normalizedKey);
  }

  const legacyClicks = Number.isFinite(entry.count) ? entry.count : 0;
  const clicks = Number.isFinite(entry.clicks) ? entry.clicks : legacyClicks;
  const lastClickAt = typeof entry.lastClickAt === 'string'
    ? entry.lastClickAt
    : (typeof entry.lastClickedAt === 'string' ? entry.lastClickedAt : null);

  const ownerUsername = typeof entry.ownerUsername === 'string' && entry.ownerUsername.trim()
    ? entry.ownerUsername.trim().toLowerCase()
    : normalizedKey;

  const name = typeof entry.name === 'string' && entry.name.trim()
    ? entry.name.trim().toLowerCase()
    : normalizedKey;

  return {
    name,
    clicks,
    lastClickAt,
    ownerUsername
  };
}

function buildNameEntry(username) {
  const normalized = normalizeUsername(username);
  return {
    name: normalized,
    clicks: 0,
    lastClickAt: null,
    ownerUsername: normalized
  };
}

function buildMember(username, role) {
  const normalized = normalizeUsername(username);
  return {
    username: normalized,
    role: role === 'admin' ? 'admin' : 'member',
    joinedAt: new Date().toISOString()
  };
}

function hashInviteToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

class JsonPigsRepository {
  constructor({ pigsPath }) {
    this.pigsPath = pigsPath;
  }

  async readRaw() {
    const data = await readJsonOrDefault(this.pigsPath, defaultPigs);
    data.pigs = data.pigs && typeof data.pigs === 'object' ? data.pigs : {};
    return data;
  }

  async writeRaw(data) {
    await writeJsonAtomic(this.pigsPath, { ...defaultPigs, ...data });
  }

  async listPigsForUser(username) {
    const normalizedUsername = normalizeUsername(username);
    const data = await this.readRaw();

    return Object.values(data.pigs)
      .map(normalizePig)
      .filter(Boolean)
      .filter((pig) => Boolean(pig.members?.[normalizedUsername]))
      .map((pig) => ({
        id: pig.id,
        title: pig.title,
        valuePerClick: pig.valuePerClick,
        createdAt: pig.createdAt || null,
        createdBy: pig.createdBy || null,
        role: pig.members?.[normalizedUsername]?.role || 'member'
      }))
      .sort((a, b) => String(a.createdAt || '').localeCompare(String(b.createdAt || '')));
  }

  async getPig(pigId) {
    const data = await this.readRaw();
    const pig = normalizePig(data.pigs[pigId]);
    return pig || null;
  }

  async getPigNames(pigId) {
    const pig = await this.getPig(pigId);
    if (!pig) return null;

    const normalized = {};
    for (const [name, entry] of Object.entries(pig.names || {})) {
      if (typeof entry !== 'object' || entry === null) continue;
      const normalizedKey = normalizeUsername(name);
      normalized[normalizedKey] = normalizeNameEntry(normalizedKey, entry);
    }
    return normalized;
  }

  async getPigConfig(pigId) {
    const pig = await this.getPig(pigId);
    if (!pig) return null;
    return { valuePerClick: pig.valuePerClick };
  }

  async setPigValuePerClick(pigId, valuePerClick) {
    return withFileLock(this.pigsPath, async () => {
      const data = await this.readRaw();
      const pig = normalizePig(data.pigs[pigId]);
      if (!pig) return false;

      pig.valuePerClick = valuePerClick;
      data.pigs[pigId] = pig;
      await this.writeRaw(data);
      return true;
    });
  }

  async createPig({ title, createdBy }) {
    const normalizedCreatedBy = normalizeUsername(createdBy);

    return withFileLock(this.pigsPath, async () => {
      const data = await this.readRaw();
      const id = crypto.randomUUID();
      const now = new Date().toISOString();

      const pig = normalizePig({
        id,
        title: normalizePigTitle(title),
        createdAt: now,
        createdBy: normalizedCreatedBy,
        valuePerClick: DEFAULT_VALUE_PER_CLICK,
        members: {
          [normalizedCreatedBy]: buildMember(normalizedCreatedBy, 'admin')
        },
        names: {
          [normalizedCreatedBy]: buildNameEntry(normalizedCreatedBy)
        },
        invites: []
      });

      data.pigs[id] = pig;
      await this.writeRaw(data);

      return pig;
    });
  }

  async addInvite(pigId, inviteRecord) {
    return withFileLock(this.pigsPath, async () => {
      const data = await this.readRaw();
      const pig = normalizePig(data.pigs[pigId]);
      if (!pig) return null;

      const nextInvite = { ...inviteRecord };
      pig.invites = Array.isArray(pig.invites) ? pig.invites : [];
      pig.invites.push(nextInvite);

      data.pigs[pigId] = pig;
      await this.writeRaw(data);
      return nextInvite;
    });
  }

  async acceptInvite(token, username) {
    const normalizedUsername = normalizeUsername(username);
    const tokenHash = hashInviteToken(token);

    return withFileLock(this.pigsPath, async () => {
      const data = await this.readRaw();
      const nowMs = Date.now();

      for (const [pigId, pigValue] of Object.entries(data.pigs)) {
        const pig = normalizePig(pigValue);
        if (!pig) continue;
        if (!Array.isArray(pig.invites) || pig.invites.length === 0) continue;

        const inviteIndex = pig.invites.findIndex((invite) => invite && invite.tokenHash === tokenHash);
        if (inviteIndex === -1) continue;

        const invite = pig.invites[inviteIndex];

        if (invite.revokedAt) {
          return { ok: false, reason: 'INVITE_REVOKED' };
        }

        const expiresAtMs = new Date(invite.expiresAt).getTime();
        if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
          return { ok: false, reason: 'INVITE_EXPIRED' };
        }

        const maxUses = Number.isInteger(invite.maxUses) ? invite.maxUses : 1;
        const uses = Number.isInteger(invite.uses) ? invite.uses : 0;
        if (uses >= maxUses) {
          return { ok: false, reason: 'INVITE_MAX_USES_REACHED' };
        }

        pig.members = pig.members && typeof pig.members === 'object' ? pig.members : {};
        pig.names = pig.names && typeof pig.names === 'object' ? pig.names : {};

        const alreadyMember = Boolean(pig.members[normalizedUsername]);

        if (!alreadyMember) {
          pig.members[normalizedUsername] = buildMember(normalizedUsername, 'member');
          if (!pig.names[normalizedUsername]) {
            pig.names[normalizedUsername] = buildNameEntry(normalizedUsername);
          }
          invite.uses = uses + 1;
        }

        pig.invites[inviteIndex] = invite;
        data.pigs[pigId] = pig;
        await this.writeRaw(data);

        return {
          ok: true,
          pigId,
          alreadyMember
        };
      }

      return { ok: false, reason: 'INVITE_NOT_FOUND' };
    });
  }

  async incrementName(pigId, username) {
    const normalizedUsername = normalizeUsername(username);

    return withFileLock(this.pigsPath, async () => {
      const data = await this.readRaw();
      const pig = normalizePig(data.pigs[pigId]);
      if (!pig) return false;

      pig.names = pig.names && typeof pig.names === 'object' ? pig.names : {};
      if (!pig.names[normalizedUsername]) return false;

      const entry = normalizeNameEntry(normalizedUsername, pig.names[normalizedUsername]);
      entry.clicks += 1;
      entry.lastClickAt = new Date().toISOString();
      pig.names[normalizedUsername] = entry;

      data.pigs[pigId] = pig;
      await this.writeRaw(data);
      return true;
    });
  }

  async resetName(pigId, username) {
    const normalizedUsername = normalizeUsername(username);

    return withFileLock(this.pigsPath, async () => {
      const data = await this.readRaw();
      const pig = normalizePig(data.pigs[pigId]);
      if (!pig) return false;

      pig.names = pig.names && typeof pig.names === 'object' ? pig.names : {};
      if (!pig.names[normalizedUsername]) return false;

      const entry = normalizeNameEntry(normalizedUsername, pig.names[normalizedUsername]);
      entry.clicks = 0;
      entry.lastClickAt = null;
      pig.names[normalizedUsername] = entry;

      data.pigs[pigId] = pig;
      await this.writeRaw(data);
      return true;
    });
  }
}

module.exports = {
  JsonPigsRepository,
  hashInviteToken
};
