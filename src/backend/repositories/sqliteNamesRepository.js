const DEFAULT_VALUE_PER_CLICK = 0.5;

class SqliteNamesRepository {
  constructor({ db }) {
    this.db = db;
  }

  async getNames() {
    const rows = this.db.prepare('SELECT * FROM global_names').all();
    const result = {};
    for (const row of rows) {
      result[row.name] = {
        name: row.name,
        clicks: row.clicks,
        lastClickAt: row.last_click_at,
        ownerUsername: row.owner_username
      };
    }
    return result;
  }

  async getName(name) {
    const row = this.db.prepare('SELECT * FROM global_names WHERE name = ?').get(name);
    if (!row) return null;
    return {
      name: row.name,
      clicks: row.clicks,
      lastClickAt: row.last_click_at,
      ownerUsername: row.owner_username
    };
  }

  async getConfig() {
    const row = this.db.prepare("SELECT value FROM global_config WHERE key = 'valuePerClick'").get();
    const valuePerClick = row ? parseFloat(row.value) : DEFAULT_VALUE_PER_CLICK;
    return { valuePerClick: Number.isFinite(valuePerClick) ? valuePerClick : DEFAULT_VALUE_PER_CLICK };
  }

  async setValuePerClick(valuePerClick) {
    this.db.prepare(
      "INSERT OR REPLACE INTO global_config (key, value) VALUES ('valuePerClick', ?)"
    ).run(String(valuePerClick));
  }

  async addName(name, ownerUsername = name) {
    const result = this.db.prepare(`
      INSERT OR IGNORE INTO global_names (name, clicks, last_click_at, owner_username)
      VALUES (?, 0, NULL, ?)
    `).run(name, ownerUsername);
    return result.changes > 0;
  }

  async incrementName(name) {
    const result = this.db.prepare(`
      UPDATE global_names SET clicks = clicks + 1, last_click_at = ? WHERE name = ?
    `).run(new Date().toISOString(), name);
    return result.changes > 0;
  }

  async resetName(name) {
    const result = this.db.prepare(`
      UPDATE global_names SET clicks = 0, last_click_at = NULL WHERE name = ?
    `).run(name);
    return result.changes > 0;
  }

  async resetNames() {
    this.db.prepare('UPDATE global_names SET clicks = 0, last_click_at = NULL').run();
  }
}

module.exports = { SqliteNamesRepository };
