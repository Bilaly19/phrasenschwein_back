const { createApp } = require('./src/backend/app/createApp');
const { seedDevUserIfEnabled } = require('./src/backend/app/seedDevUser');

const { app, container } = createApp();

async function start() {
  await seedDevUserIfEnabled({
    config: container.config,
    authService: container.authService,
    usersRepository: container.usersRepository,
    logger: container.logger
  });

  app.listen(container.config.port, () => {
    container.logger.info({
      port: container.config.port,
      dataPath: container.config.dataPath,
      usersPath: container.config.usersPath,
      sessionTtlMinutes: container.config.sessionTtlMinutes,
      corsOrigins: container.config.corsOrigins
    }, 'Server gestartet');
  });
}

start().catch((error) => {
  container.logger.error({ error }, 'Server failed to start');
  process.exit(1);
});
