const { AppError } = require('../utils/http');

class NamesService {
  constructor({ namesRepository }) {
    this.namesRepository = namesRepository;
  }

  getNames() {
    return this.namesRepository.getNames();
  }

  getConfig() {
    return this.namesRepository.getConfig();
  }

  async updateConfig(valuePerClick) {
    await this.namesRepository.setValuePerClick(valuePerClick);
  }

  async addName(name) {
    const created = await this.namesRepository.addName(name);
    if (!created) {
      throw new AppError(400, 'NAME_EXISTS', 'Name existiert bereits');
    }
  }

  async incrementName(name) {
    const found = await this.namesRepository.incrementName(name);
    if (!found) {
      throw new AppError(404, 'NAME_NOT_FOUND', 'Name nicht gefunden');
    }
  }

  async resetNames() {
    await this.namesRepository.resetNames();
  }

  async deleteName(name) {
    const found = await this.namesRepository.deleteName(name);
    if (!found) {
      throw new AppError(404, 'NAME_NOT_FOUND', 'Name nicht gefunden');
    }
  }
}

module.exports = {
  NamesService
};
