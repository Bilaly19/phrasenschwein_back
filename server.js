const config = require('./config');
const { logInfo } = require('./logger');
const { createApp } = require('./app');

const app = createApp({ config });

app.listen(config.port, () => {
  logInfo('Server gestartet', {
    port: config.port,
    dataPath: config.dataPath,
    usersPath: config.usersPath,
    sessionTtlMinutes: config.sessionTtlMinutes,
    corsOrigins: config.corsOrigins
  });
});
