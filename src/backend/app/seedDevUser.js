async function seedDevUserIfEnabled({ config, authService, usersRepository, logger }) {
  const isDev = config.nodeEnv === 'development';
  if (!isDev || config.isProduction) {
    return;
  }

  if (!config.devSeedUserEnabled) {
    return;
  }

  const username = (config.devSeedUsername || '').trim();
  const password = config.devSeedPassword || '';

  if (!username || !password) {
    logger.warn({ usernameConfigured: Boolean(username) }, 'DEV_SEED_USER enabled but credentials are missing');
    return;
  }

  const existing = await usersRepository.findUser(username);
  if (existing) {
    return;
  }

  const role = config.devSeedIsAdmin ? 'ADMIN' : 'USER';
  await authService.register({
    username,
    firstName: username,
    lastName: 'Dev',
    password
  }, { role });
  logger.info({ username, role }, 'Development seed user created');
}

module.exports = {
  seedDevUserIfEnabled
};
