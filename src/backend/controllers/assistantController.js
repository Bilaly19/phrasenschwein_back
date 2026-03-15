class AssistantController {
  constructor({ assistantService }) {
    this.assistantService = assistantService;
  }

  chat = async (req, res) => {
    const result = await this.assistantService.chatByActor(req.auth, req.body || {});
    res.json({ ok: true, data: result });
  };
}

module.exports = {
  AssistantController
};
