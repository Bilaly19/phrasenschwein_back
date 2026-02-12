const { atomicWriteJson, readJsonWithFallback } = require('./jsonFileStore');

class CounterRepository {
  async getAll() {}
  async saveAll(_model) {}
}

class InMemoryFileCounterRepository extends CounterRepository {
  constructor(filePath) {
    super();
    this.filePath = filePath;
  }

  async getAll() {
    const raw = await readJsonWithFallback(this.filePath, { valuePerClick: 0.5 });
    const valuePerClick = typeof raw.valuePerClick === 'number' ? raw.valuePerClick : 0.5;
    const counters = {};

    for (const [key, value] of Object.entries(raw)) {
      if (key === 'valuePerClick') {
        continue;
      }
      if (value && typeof value === 'object') {
        counters[key] = {
          count: Number.isInteger(value.count) ? value.count : 0,
          lastClickedAt: value.lastClickedAt || null
        };
      }
    }

    return { valuePerClick, counters };
  }

  async saveAll(model) {
    const payload = { valuePerClick: model.valuePerClick, ...model.counters };
    await atomicWriteJson(this.filePath, payload);
    return model;
  }
}

module.exports = { CounterRepository, InMemoryFileCounterRepository };
