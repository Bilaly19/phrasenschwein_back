const { createApp } = require('./app');
const { logger } = require('./utils/logger');

const { app, env } = createApp();

app.listen(env.port, () => {
  logger.info(
    {
      port: env.port,
      dataPath: env.dataPath,
      usersPath: env.usersPath,
      sessionTtlMinutes: env.sessionTtlMinutes,
      corsOrigins: env.corsOrigins
    },
    'server_started'
  );
});
