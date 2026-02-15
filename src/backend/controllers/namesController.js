const { AppError } = require('../utils/http');

class NamesController {
  constructor({ namesService, config }) {
    this.namesService = namesService;
    this.config = config;
  }

  getNames = async (_req, res) => {
    const names = await this.namesService.getNames();
    res.json(names);
  };

  getConfig = async (_req, res) => {
    const config = await this.namesService.getConfig();
    res.json(config);
  };

  getDonationLink = async (_req, res) => {
    if (!this.config.paypalDonationUrl) {
      throw new AppError(404, 'DONATION_LINK_NOT_CONFIGURED', 'PayPal-Spendenlink ist nicht konfiguriert');
    }

    res.json({ url: this.config.paypalDonationUrl });
  };

  assertAdmin(req) {
    if (!req.auth?.roles?.includes('admin')) {
      throw new AppError(403, 'FORBIDDEN', 'Nicht erlaubt');
    }
  }

  updateConfig = async (req, res) => {
    this.assertAdmin(req);
    await this.namesService.updateConfig(req.body.valuePerClick);
    res.json({ message: 'Wert gespeichert' });
  };

  addName = async (req, res) => {
    await this.namesService.addName(req.body.name);
    res.status(201).json({ message: 'Hinzugefügt' });
  };

  incrementName = async (req, res) => {
    await this.namesService.incrementName(req.params.name);
    res.json({ message: 'Zähler erhöht' });
  };

  resetNames = async (req, res) => {
    this.assertAdmin(req);
    await this.namesService.resetNames();
    res.json({ message: 'Zurückgesetzt' });
  };

  deleteName = async (req, res) => {
    this.assertAdmin(req);
    await this.namesService.deleteName(req.params.name);
    res.json({ message: 'Name gelöscht' });
  };
}

module.exports = {
  NamesController
};
