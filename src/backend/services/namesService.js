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

  async addName(_name) {
    throw new AppError(410, 'MANUAL_NAME_ADD_DISABLED', 'Manuelles Hinzufuegen ist deaktiviert');
  }

  assertOwnership(requestedName, authUsername) {
    if (requestedName !== authUsername) {
      throw new AppError(403, 'FORBIDDEN', 'Nicht erlaubt');
    }
  }

  async incrementName(name, authUsername) {
    this.assertOwnership(name, authUsername);

    const found = await this.namesRepository.incrementName(name);
    if (!found) {
      throw new AppError(404, 'NAME_NOT_FOUND', 'Name nicht gefunden');
    }
  }

  async resetOwnName(authUsername) {
    const found = await this.namesRepository.resetName(authUsername);
    if (!found) {
      throw new AppError(404, 'NAME_NOT_FOUND', 'Name nicht gefunden');
    }
  }

  async deleteName(name, authUsername) {
    this.assertOwnership(name, authUsername);

    const found = await this.namesRepository.deleteName(name);
    if (!found) {
      throw new AppError(404, 'NAME_NOT_FOUND', 'Name nicht gefunden');
    }
  }
}

module.exports = {
  NamesService
};