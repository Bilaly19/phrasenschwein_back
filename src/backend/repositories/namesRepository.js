const { readJsonOrDefault, writeJsonAtomic } = require('./jsonFileStore');

const defaultData = {
  valuePerClick: 0.5
};

class JsonNamesRepository {
  constructor({ dataPath }) {
    this.dataPath = dataPath;
  }

  async readRaw() {
    return readJsonOrDefault(this.dataPath, defaultData);
  }

  async writeRaw(data) {
    await writeJsonAtomic(this.dataPath, { ...defaultData, ...data });
  }

  async getNames() {
    const { valuePerClick, ...names } = await this.readRaw();
    return names;
  }

  async getConfig() {
    const data = await this.readRaw();
    return { valuePerClick: data.valuePerClick };
  }

  async setValuePerClick(valuePerClick) {
    const data = await this.readRaw();
    data.valuePerClick = valuePerClick;
    await this.writeRaw(data);
  }

  async addName(name) {
    const data = await this.readRaw();
    if (data[name]) return false;

    data[name] = { count: 0, lastClickedAt: null };
    await this.writeRaw(data);
    return true;
  }

  async incrementName(name) {
    const data = await this.readRaw();
    if (!data[name]) return false;

    data[name].count += 1;
    data[name].lastClickedAt = new Date().toISOString();
    await this.writeRaw(data);
    return true;
  }

  async resetNames() {
    const data = await this.readRaw();

    for (const [name, value] of Object.entries(data)) {
      if (name === 'valuePerClick' || typeof value !== 'object') continue;
      data[name] = { ...value, count: 0, lastClickedAt: null };
    }

    await this.writeRaw(data);
  }

  async deleteName(name) {
    const data = await this.readRaw();
    if (!data[name]) return false;

    delete data[name];
    await this.writeRaw(data);
    return true;
  }
}

module.exports = {
  JsonNamesRepository
};
