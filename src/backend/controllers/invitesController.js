class InvitesController {
  constructor({ pigsService, logger }) {
    this.pigsService = pigsService;
    this.logger = logger;
  }

  acceptInvite = async (req, res) => {
    const { token } = req.body || {};
    const result = await this.pigsService.acceptInviteByActor(req.auth, token);
    this.logger.info({ actor: req.auth.username, pigId: result.pigId }, 'Invite angenommen');
    res.json({ ok: true, data: result });
  };
}

module.exports = {
  InvitesController
};

