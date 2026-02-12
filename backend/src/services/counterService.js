const { AppError } = require('../utils/appError');

class CounterService {
  constructor(counterRepository) {
    this.counterRepository = counterRepository;
  }

  async getNames() {
    const model = await this.counterRepository.getAll();
    return model.counters;
  }

  async getConfig() {
    const model = await this.counterRepository.getAll();
    return { valuePerClick: model.valuePerClick };
  }

  async setConfig(valuePerClick) {
    const model = await this.counterRepository.getAll();
    model.valuePerClick = valuePerClick;
    await this.counterRepository.saveAll(model);
  }

  async addName(name) {
    const model = await this.counterRepository.getAll();
    if (model.counters[name]) {
      throw new AppError(400, 'NAME_EXISTS', 'Name existiert bereits');
    }

    model.counters[name] = { count: 0, lastClickedAt: null };
    await this.counterRepository.saveAll(model);
  }

  async increment(name) {
    const model = await this.counterRepository.getAll();
    const entry = model.counters[name];
    if (!entry) {
      throw new AppError(404, 'NAME_NOT_FOUND', 'Name nicht gefunden');
    }

    entry.count += 1;
    entry.lastClickedAt = new Date().toISOString();
    await this.counterRepository.saveAll(model);
    return entry;
  }

  async reset() {
    const model = await this.counterRepository.getAll();
    for (const item of Object.values(model.counters)) {
      item.count = 0;
      item.lastClickedAt = null;
    }
    await this.counterRepository.saveAll(model);
  }

  async delete(name) {
    const model = await this.counterRepository.getAll();
    if (!model.counters[name]) {
      throw new AppError(404, 'NAME_NOT_FOUND', 'Name nicht gefunden');
    }

    delete model.counters[name];
    await this.counterRepository.saveAll(model);
  }
}

module.exports = { CounterService };
