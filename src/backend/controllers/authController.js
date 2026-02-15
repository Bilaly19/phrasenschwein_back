const { AppError } = require('../utils/http');
const { extractBearerToken } = require('../middlewares/authSession');

class AuthController {
  constructor({ authService, logger }) {
    this.authService = authService;
    this.logger = logger;
  }

  register = async (req, res) => {
    const { username, password } = req.body;
    await this.authService.register(username, password);

    this.logger.info({ username }, 'Benutzer registriert');
    res.status(201).json({ message: 'Benutzer registriert' });
  };

  login = async (req, res) => {
    const { username, password } = req.body;
    const loginResult = await this.authService.login(username, password);

    this.logger.info({ username }, 'Benutzer eingeloggt');
    res.json(loginResult);
  };

  logout = async (req, res) => {
    const token = req.auth?.token || extractBearerToken(req.headers.authorization);
    if (!token) {
      throw new AppError(401, 'UNAUTHORIZED', 'Nicht eingeloggt');
    }

    await this.authService.logout(token);
    res.json({ message: 'Abgemeldet' });
  };

  whoAmI = async (req, res) => {
    res.json({
      username: req.auth.username,
      expiresAt: req.auth.expiresAt
    });
  };
}

module.exports = {
  AuthController
};
