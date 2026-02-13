const helmet = require('helmet');

function securityHeadersMiddleware(config) {
  return helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    hsts: config.isProduction ? undefined : false
  });
}

module.exports = {
  securityHeadersMiddleware
};
