const { createApp: createStructuredApp } = require('./src/backend/app/createApp');

function createApp(options = {}) {
  const { app } = createStructuredApp(options);
  return app;
}

module.exports = {
  createApp
};
