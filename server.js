const { createApp } = require('./src/backend/app/createApp');
const { seedDevUserIfEnabled } = require('./src/backend/app/seedDevUser');
const { migrateJsonToSqlite } = require('./src/backend/migrations/migrateJsonToSqlite');

const { app, container } = createApp();

async function start() {
  // Migrate existing JSON data to SQLite on first run
  migrateJsonToSqlite(container.db, {
    dataPath: container.config.dataPath,
    usersPath: container.config.usersPath,
    pigsPath: container.config.pigsPath,
    logger: container.logger
  });

  // Clean up expired sessions on startup
  await container.usersRepository.cleanupExpiredSessions(new Date().toISOString());

  await seedDevUserIfEnabled({
    config: container.config,
    authService: container.authService,
    usersRepository: container.usersRepository,
    logger: container.logger
  });

  app.listen(container.config.port, () => {
    container.logger.info({
      port: container.config.port,
      dbPath: container.config.dbPath,
      sessionTtlMinutes: container.config.sessionTtlMinutes,
      corsOrigins: container.config.corsOrigins
    }, 'Server gestartet');
  });
}

start().catch((error) => {
  container.logger.error({ error }, 'Server failed to start');
  process.exit(1);
});
