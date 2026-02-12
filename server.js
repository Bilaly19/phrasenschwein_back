const { createApp } = require('./src/backend/app/createApp');

const { app, container } = createApp();

app.listen(container.config.port, () => {
  container.logger.info({
    port: container.config.port,
    dataPath: container.config.dataPath,
    usersPath: container.config.usersPath,
    sessionTtlMinutes: container.config.sessionTtlMinutes,
    corsOrigins: container.config.corsOrigins
  }, 'Server gestartet');
});
