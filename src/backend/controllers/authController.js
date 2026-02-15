const { AppError } = require('../utils/http');
const { extractBearerToken } = require('../middlewares/authSession');

class AuthController {
  constructor({ authService, logger }) {
    this.authService = authService;
    this.logger = logger;
  }

  register = async (req, res) => {
    const { username, firstName, lastName, password } = req.body;
    const user = await this.authService.register({ username, firstName, lastName, password });

    this.logger.info({ username: user.username }, 'Benutzer registriert');
    res.status(201).json({
      ok: true,
      data: {
        user
      }
    });
  };

  login = async (req, res) => {
    const { username, password } = req.body;
    const loginResult = await this.authService.login(username, password);

    this.logger.info({ username: loginResult.username }, 'Benutzer eingeloggt');
    res.json({ ok: true, data: loginResult });
  };

  logout = async (req, res) => {
    const token = req.auth?.token || extractBearerToken(req.headers.authorization);
    if (!token) {
      throw new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt');
    }

    await this.authService.logout(token);
    res.json({ ok: true, data: { message: 'Abgemeldet' } });
  };

  whoAmI = async (req, res) => {
    res.json({
      ok: true,
      data: {
        username: req.auth.username,
        role: req.auth.role,
        expiresAt: req.auth.expiresAt
      }
    });
  };
}

module.exports = {
  AuthController
};