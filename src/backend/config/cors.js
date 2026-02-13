function createCorsOptions(config) {
  const allowedOrigins = new Set(config.corsOrigins || []);

  return {
    origin(origin, callback) {
      if (!origin) {
        callback(null, true);
        return;
      }

      if (!config.isProduction) {
        callback(null, true);
        return;
      }

      if (allowedOrigins.has(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error('CORS: Origin nicht erlaubt'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'DELETE']
  };
}

module.exports = {
  createCorsOptions
};
