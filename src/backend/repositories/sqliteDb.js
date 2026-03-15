const Database = require('better-sqlite3');
const path = require('node:path');
const fs = require('node:fs');

function createDb(dbPath) {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      first_name TEXT NOT NULL DEFAULT '',
      last_name TEXT NOT NULL DEFAULT '',
      password_hash TEXT,
      role TEXT NOT NULL DEFAULT 'USER',
      created_at TEXT,
      created_by TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

    CREATE TABLE IF NOT EXISTS pigs (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL DEFAULT 'Phrasenschwein',
      created_at TEXT,
      created_by TEXT,
      value_per_click REAL NOT NULL DEFAULT 0.5,
      paypal_link TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS pig_members (
      pig_id TEXT NOT NULL,
      username TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      joined_at TEXT,
      PRIMARY KEY (pig_id, username),
      FOREIGN KEY (pig_id) REFERENCES pigs(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS pig_names (
      pig_id TEXT NOT NULL,
      username TEXT NOT NULL,
      name TEXT NOT NULL,
      clicks INTEGER NOT NULL DEFAULT 0,
      last_click_at TEXT,
      owner_username TEXT,
      PRIMARY KEY (pig_id, username),
      FOREIGN KEY (pig_id) REFERENCES pigs(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS pig_invites (
      id TEXT PRIMARY KEY,
      pig_id TEXT NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      created_at TEXT,
      created_by TEXT,
      expires_at TEXT NOT NULL,
      max_uses INTEGER NOT NULL DEFAULT 1,
      uses INTEGER NOT NULL DEFAULT 0,
      revoked_at TEXT,
      FOREIGN KEY (pig_id) REFERENCES pigs(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS global_names (
      name TEXT PRIMARY KEY,
      clicks INTEGER NOT NULL DEFAULT 0,
      last_click_at TEXT,
      owner_username TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS global_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    INSERT OR IGNORE INTO global_config (key, value) VALUES ('valuePerClick', '0.5');
  `);

  return db;
}

module.exports = { createDb };
