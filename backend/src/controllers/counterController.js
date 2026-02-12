const { ok, created } = require('../utils/response');
const { asyncHandler } = require('../utils/asyncHandler');

function buildCounterController(counterService, env) {
  return {
    getNames: asyncHandler(async (_req, res) => {
      const data = await counterService.getNames();
      return ok(res, data);
    }),

    getConfig: asyncHandler(async (_req, res) => {
      return ok(res, await counterService.getConfig());
    }),

    getDonationLink: asyncHandler(async (_req, res) => {
      if (!env.paypalDonationUrl) {
        return res.status(404).json({ success: false, error: { code: 'DONATION_URL_MISSING', message: 'PayPal-Spendenlink ist nicht konfiguriert' } });
      }

      return ok(res, { url: env.paypalDonationUrl });
    }),

    setConfig: asyncHandler(async (req, res) => {
      await counterService.setConfig(req.body.valuePerClick);
      return ok(res, null, 'Wert gespeichert');
    }),

    addName: asyncHandler(async (req, res) => {
      await counterService.addName(req.body.name);
      return created(res, null, 'Hinzugefügt');
    }),

    increment: asyncHandler(async (req, res) => {
      const entry = await counterService.increment(req.params.name);
      return ok(res, entry, 'Zähler erhöht');
    }),

    reset: asyncHandler(async (_req, res) => {
      await counterService.reset();
      return ok(res, null, 'Zurückgesetzt');
    }),

    deleteName: asyncHandler(async (req, res) => {
      await counterService.delete(req.params.name);
      return ok(res, null, 'Name gelöscht');
    })
  };
}

module.exports = { buildCounterController };
