const crypto = require('node:crypto');
const { AppError } = require('../utils/http');
const { hashInviteToken } = require('../repositories/pigsRepository');

function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
}

function toSafeInteger(value, fallback) {
  const num = Number(value);
  return Number.isInteger(num) ? num : fallback;
}

function generateInviteToken() {
  // Short, URL-safe token suitable for copy/paste and links.
  return crypto.randomBytes(18).toString('base64url');
}

class PigsService {
  constructor({ pigsRepository }) {
    this.pigsRepository = pigsRepository;
  }

  async listPigs(username) {
    const normalizedUsername = normalizeUsername(username);
    return this.pigsRepository.listPigsForUser(normalizedUsername);
  }

  async createPigByActor(actor, { title }) {
    const normalizedUsername = normalizeUsername(actor?.username);
    if (!normalizedUsername) {
      throw new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt');
    }

    const pig = await this.pigsRepository.createPig({ title, createdBy: normalizedUsername });
    return {
      id: pig.id,
      title: pig.title,
      valuePerClick: pig.valuePerClick,
      createdAt: pig.createdAt,
      createdBy: pig.createdBy,
      role: 'admin'
    };
  }

  async assertPigAdmin(pigId, username) {
    const pig = await this.pigsRepository.getPig(pigId);
    if (!pig) {
      throw new AppError(404, 'PIG_NOT_FOUND', 'Phrasenschwein nicht gefunden');
    }

    const normalizedUsername = normalizeUsername(username);
    const role = pig.members?.[normalizedUsername]?.role || null;
    if (role !== 'admin') {
      throw new AppError(403, 'FORBIDDEN', 'Nicht erlaubt');
    }

    return pig;
  }

  async createInviteByActor(actor, pigId, { maxUses, ttlHours } = {}) {
    const normalizedUsername = normalizeUsername(actor?.username);
    if (!normalizedUsername) {
      throw new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt');
    }

    await this.assertPigAdmin(pigId, normalizedUsername);

    const effectiveMaxUses = toSafeInteger(maxUses, 1);
    const effectiveTtlHours = toSafeInteger(ttlHours, 24 * 7);
    const now = Date.now();
    const expiresAt = new Date(now + effectiveTtlHours * 60 * 60 * 1000).toISOString();

    const token = generateInviteToken();
    const inviteRecord = {
      id: crypto.randomUUID(),
      tokenHash: hashInviteToken(token),
      createdAt: new Date(now).toISOString(),
      createdBy: normalizedUsername,
      expiresAt,
      maxUses: effectiveMaxUses,
      uses: 0,
      revokedAt: null
    };

    const storedInvite = await this.pigsRepository.addInvite(pigId, inviteRecord);
    if (!storedInvite) {
      throw new AppError(404, 'PIG_NOT_FOUND', 'Phrasenschwein nicht gefunden');
    }

    return {
      token,
      invite: {
        id: storedInvite.id,
        createdAt: storedInvite.createdAt,
        createdBy: storedInvite.createdBy,
        expiresAt: storedInvite.expiresAt,
        maxUses: storedInvite.maxUses,
        uses: storedInvite.uses
      }
    };
  }

  async acceptInviteByActor(actor, token) {
    const normalizedUsername = normalizeUsername(actor?.username);
    if (!normalizedUsername) {
      throw new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt');
    }

    const normalizedToken = typeof token === 'string' ? token.trim() : '';
    if (!normalizedToken) {
      throw new AppError(400, 'INVITE_INVALID', 'Invite-Code ist ungueltig');
    }

    const result = await this.pigsRepository.acceptInvite(normalizedToken, normalizedUsername);
    if (result.ok) {
      return { pigId: result.pigId, alreadyMember: result.alreadyMember };
    }

    switch (result.reason) {
      case 'INVITE_NOT_FOUND':
        throw new AppError(404, 'INVITE_NOT_FOUND', 'Invite-Code ist ungueltig');
      case 'INVITE_REVOKED':
        throw new AppError(410, 'INVITE_REVOKED', 'Invite wurde widerrufen');
      case 'INVITE_EXPIRED':
        throw new AppError(410, 'INVITE_EXPIRED', 'Invite ist abgelaufen');
      case 'INVITE_MAX_USES_REACHED':
        throw new AppError(410, 'INVITE_MAX_USES_REACHED', 'Invite wurde bereits verwendet');
      default:
        throw new AppError(400, 'INVITE_INVALID', 'Invite-Code ist ungueltig');
    }
  }
}

module.exports = {
  PigsService
};
