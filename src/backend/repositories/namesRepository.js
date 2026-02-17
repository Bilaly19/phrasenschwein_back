const { readJsonOrDefault, writeJsonAtomic, withFileLock } = require('./jsonFileStore');

const defaultData = {
  valuePerClick: 0.5
};

function normalizeEntry(name, entry) {
  if (!entry || typeof entry !== 'object') {
    return {
      name,
      clicks: 0,
      lastClickAt: null,
      ownerUsername: name
    };
  }

  const legacyClicks = Number.isFinite(entry.count) ? entry.count : 0;
  const clicks = Number.isFinite(entry.clicks) ? entry.clicks : legacyClicks;
  const lastClickAt = typeof entry.lastClickAt === 'string'
    ? entry.lastClickAt
    : (typeof entry.lastClickedAt === 'string' ? entry.lastClickedAt : null);

  const ownerUsername = typeof entry.ownerUsername === 'string' && entry.ownerUsername.trim()
    ? entry.ownerUsername.trim().toLowerCase()
    : name;

  return {
    name,
    clicks,
    lastClickAt,
    ownerUsername
  };
}

class JsonNamesRepository {
  constructor({ dataPath }) {
    this.dataPath = dataPath;
  }

  async readRaw() {
    const data = await readJsonOrDefault(this.dataPath, defaultData);
    if (!Number.isFinite(data.valuePerClick)) {
      data.valuePerClick = defaultData.valuePerClick;
    }
    return data;
  }

  async writeRaw(data) {
    await writeJsonAtomic(this.dataPath, { ...defaultData, ...data });
  }

  async getNames() {
    const { valuePerClick, ...names } = await this.readRaw();
    const normalized = {};

    for (const [name, entry] of Object.entries(names)) {
      if (typeof entry !== 'object' || entry === null) {
        continue;
      }
      normalized[name] = normalizeEntry(name, entry);
    }

    return normalized;
  }

  async getName(name) {
    const data = await this.readRaw();
    if (!data[name]) return null;
    return normalizeEntry(name, data[name]);
  }

  async getConfig() {
    const data = await this.readRaw();
    return { valuePerClick: data.valuePerClick };
  }

  async setValuePerClick(valuePerClick) {
    await withFileLock(this.dataPath, async () => {
      const data = await this.readRaw();
      data.valuePerClick = valuePerClick;
      await this.writeRaw(data);
    });
  }

  async addName(name, ownerUsername = name) {
    return withFileLock(this.dataPath, async () => {
      const data = await this.readRaw();
      if (data[name]) return false;

      data[name] = {
        name,
        clicks: 0,
        lastClickAt: null,
        ownerUsername
      };
      await this.writeRaw(data);
      return true;
    });
  }

  async incrementName(name) {
    return withFileLock(this.dataPath, async () => {
      const data = await this.readRaw();
      if (!data[name]) return false;

      const entry = normalizeEntry(name, data[name]);
      entry.clicks += 1;
      entry.lastClickAt = new Date().toISOString();
      data[name] = entry;

      await this.writeRaw(data);
      return true;
    });
  }

  async resetName(name) {
    return withFileLock(this.dataPath, async () => {
      const data = await this.readRaw();
      if (!data[name]) return false;

      const entry = normalizeEntry(name, data[name]);
      entry.clicks = 0;
      entry.lastClickAt = null;
      data[name] = entry;

      await this.writeRaw(data);
      return true;
    });
  }

  async resetNames() {
    await withFileLock(this.dataPath, async () => {
      const data = await this.readRaw();

      for (const [name, value] of Object.entries(data)) {
        if (name === 'valuePerClick' || typeof value !== 'object' || value === null) continue;
        const entry = normalizeEntry(name, value);
        entry.clicks = 0;
        entry.lastClickAt = null;
        data[name] = entry;
      }

      await this.writeRaw(data);
    });
  }
}

module.exports = {
  JsonNamesRepository
};
