const fs = require('node:fs');

function safeReadJson(filePath, fallback) {
  try {
    if (!filePath || !fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch {
    return fallback;
  }
}

function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
}

function migrateJsonToSqlite(db, { dataPath, usersPath, pigsPath, logger }) {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const pigCount = db.prepare('SELECT COUNT(*) as count FROM pigs').get();

  if ((userCount?.count || 0) > 0 || (pigCount?.count || 0) > 0) {
    logger?.info('SQLite migration: data already present, skipping');
    return;
  }

  const usersData = safeReadJson(usersPath, { users: {}, sessions: {} });
  const pigsData = safeReadJson(pigsPath, { pigs: {} });
  const namesData = safeReadJson(dataPath, { valuePerClick: 0.5 });

  const DEFAULT_VALUE_PER_CLICK = 0.5;
  const nowIso = new Date().toISOString();

  db.transaction(() => {
    // Migrate users
    const insertUser = db.prepare(`
      INSERT OR IGNORE INTO users (username, first_name, last_name, password_hash, role, created_at, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const [key, user] of Object.entries(usersData.users || {})) {
      const username = normalizeUsername(user?.username) || normalizeUsername(key);
      if (!username) continue;
      insertUser.run(
        username,
        user?.firstName || '',
        user?.lastName || '',
        user?.passwordHash || null,
        user?.role || 'USER',
        user?.createdAt || null,
        user?.createdBy || null
      );
    }

    // Migrate sessions (skip already-expired ones)
    const insertSession = db.prepare(`
      INSERT OR IGNORE INTO sessions (token_hash, username, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `);

    for (const [tokenHash, session] of Object.entries(usersData.sessions || {})) {
      if (!session || !session.expiresAt || session.expiresAt <= nowIso) continue;
      if (!session.username) continue;
      insertSession.run(tokenHash, session.username, session.expiresAt, session.createdAt || nowIso);
    }

    // Migrate pigs
    const insertPig = db.prepare(`
      INSERT OR IGNORE INTO pigs (id, title, created_at, created_by, value_per_click, paypal_link)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const insertMember = db.prepare(`
      INSERT OR IGNORE INTO pig_members (pig_id, username, role, joined_at)
      VALUES (?, ?, ?, ?)
    `);
    const insertPigName = db.prepare(`
      INSERT OR IGNORE INTO pig_names (pig_id, username, name, clicks, last_click_at, owner_username)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const insertInvite = db.prepare(`
      INSERT OR IGNORE INTO pig_invites (id, pig_id, token_hash, created_at, created_by, expires_at, max_uses, uses, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const pig of Object.values(pigsData.pigs || {})) {
      if (!pig || !pig.id) continue;

      insertPig.run(
        pig.id,
        pig.title || 'Phrasenschwein',
        pig.createdAt || null,
        pig.createdBy || null,
        Number.isFinite(pig.valuePerClick) ? pig.valuePerClick : DEFAULT_VALUE_PER_CLICK,
        pig.paypalLink || ''
      );

      for (const [username, member] of Object.entries(pig.members || {})) {
        if (!member || !username) continue;
        insertMember.run(pig.id, normalizeUsername(username), member.role || 'member', member.joinedAt || null);
      }

      for (const [username, entry] of Object.entries(pig.names || {})) {
        if (!entry || typeof entry !== 'object' || !username) continue;
        const clicks = Number.isFinite(entry.clicks) ? entry.clicks : (Number.isFinite(entry.count) ? entry.count : 0);
        const lastClickAt = entry.lastClickAt || entry.lastClickedAt || null;
        const ownerUsername = normalizeUsername(entry.ownerUsername) || normalizeUsername(username);
        const normalizedUsername = normalizeUsername(username);
        insertPigName.run(pig.id, normalizedUsername, normalizedUsername, clicks, lastClickAt, ownerUsername);
      }

      for (const invite of (pig.invites || [])) {
        if (!invite || !invite.id || !invite.tokenHash) continue;
        insertInvite.run(
          invite.id, pig.id, invite.tokenHash,
          invite.createdAt || null, invite.createdBy || null,
          invite.expiresAt || new Date(Date.now() + 86400000).toISOString(),
          invite.maxUses || 1, invite.uses || 0, invite.revokedAt || null
        );
      }
    }

    // Migrate global names (data.json)
    const insertGlobalName = db.prepare(`
      INSERT OR IGNORE INTO global_names (name, clicks, last_click_at, owner_username)
      VALUES (?, ?, ?, ?)
    `);

    for (const [key, entry] of Object.entries(namesData)) {
      if (key === 'valuePerClick' || typeof entry !== 'object' || !entry) continue;
      const clicks = Number.isFinite(entry.clicks) ? entry.clicks : (Number.isFinite(entry.count) ? entry.count : 0);
      insertGlobalName.run(key, clicks, entry.lastClickAt || null, entry.ownerUsername || key);
    }

    // Migrate valuePerClick config
    const valuePerClick = Number.isFinite(namesData.valuePerClick) ? namesData.valuePerClick : DEFAULT_VALUE_PER_CLICK;
    db.prepare("INSERT OR REPLACE INTO global_config (key, value) VALUES ('valuePerClick', ?)").run(String(valuePerClick));
  })();

  logger?.info('SQLite migration from JSON files completed successfully');
}

module.exports = { migrateJsonToSqlite };
