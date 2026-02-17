class PigsController {
  constructor({ pigsService, logger }) {
    this.pigsService = pigsService;
    this.logger = logger;
  }

  listPigs = async (req, res) => {
    const pigs = await this.pigsService.listPigs(req.auth.username);
    res.json({ ok: true, data: { pigs } });
  };

  createPig = async (req, res) => {
    const pig = await this.pigsService.createPigByActor(req.auth, { title: req.body?.title });
    this.logger.info({ actor: req.auth.username, pigId: pig.id }, 'Phrasenschwein erstellt');
    res.status(201).json({ ok: true, data: { pig } });
  };

  createInvite = async (req, res) => {
    const { pigId } = req.params;
    const { maxUses, ttlHours } = req.body || {};
    const payload = await this.pigsService.createInviteByActor(req.auth, pigId, { maxUses, ttlHours });
    this.logger.info({ actor: req.auth.username, pigId, inviteId: payload.invite.id }, 'Invite erstellt');
    res.status(201).json({ ok: true, data: payload });
  };
}

module.exports = {
  PigsController
};

