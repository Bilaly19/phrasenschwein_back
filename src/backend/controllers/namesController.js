const { AppError } = require('../utils/http');

class NamesController {
  constructor({ namesService, config }) {
    this.namesService = namesService;
    this.config = config;
  }

  getNames = async (_req, res) => {
    const names = await this.namesService.getNames();
    res.json({ ok: true, data: names });
  };

  getConfig = async (_req, res) => {
    const config = await this.namesService.getConfig();
    res.json({ ok: true, data: config });
  };

  getDonationLink = async (_req, res) => {
    if (!this.config.paypalDonationUrl) {
      throw new AppError(404, 'DONATION_LINK_NOT_CONFIGURED', 'PayPal-Spendenlink ist nicht konfiguriert');
    }

    res.json({ ok: true, data: { url: this.config.paypalDonationUrl } });
  };

  assertAdmin(req) {
    if (req.auth?.role !== 'ADMIN') {
      throw new AppError(403, 'FORBIDDEN', 'Nicht erlaubt');
    }
  }

  updateConfig = async (req, res) => {
    this.assertAdmin(req);
    await this.namesService.updateConfig(req.body.valuePerClick);
    res.json({ ok: true, data: { message: 'Wert gespeichert' } });
  };

  addName = async (req, res) => {
    await this.namesService.addName(req.body.name);
    res.status(201).json({ ok: true, data: { message: 'Hinzugefuegt' } });
  };

  incrementName = async (req, res) => {
    await this.namesService.incrementName(req.params.name, req.auth.username);
    res.json({ ok: true, data: { message: 'Zaehler erhoeht' } });
  };

  resetNames = async (req, res) => {
    await this.namesService.resetOwnName(req.auth.username);
    res.json({ ok: true, data: { message: 'Zurueckgesetzt' } });
  };
}

module.exports = {
  NamesController
};
