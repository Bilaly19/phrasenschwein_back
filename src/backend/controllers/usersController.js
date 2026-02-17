const { AppError } = require('../utils/http');

class UsersController {
  constructor({ authService, logger }) {
    this.authService = authService;
    this.logger = logger;
  }

  assertAdmin(req) {
    if (req.auth?.role !== 'ADMIN') {
      throw new AppError(403, 'FORBIDDEN', 'Nicht erlaubt');
    }
  }

  listUsers = async (_req, res) => {
    const users = await this.authService.listUsers();
    res.json({ ok: true, data: { users } });
  };

  createUser = async (req, res) => {
    const { username, password, firstName, lastName, roles } = req.body;
    await this.authService.createUserByActor(req.auth, username, password, { firstName, lastName, roles });

    this.logger.info({ actor: req.auth.username, username }, 'Benutzer erstellt');
    res.status(201).json({ ok: true, data: { message: 'Benutzer erstellt' } });
  };

  setRoles = async (req, res) => {
    this.assertAdmin(req);
    const { username } = req.params;
    const { roles } = req.body;

    await this.authService.setUserRolesByAdmin(username, roles);
    this.logger.info({ actor: req.auth.username, username, roles }, 'Rollen aktualisiert');
    res.json({ ok: true, data: { message: 'Rollen aktualisiert' } });
  };
}

module.exports = {
  UsersController
};