function createCorsOptions(config) {
  return {
    origin(origin, callback) {
      if (!origin || config.corsOrigins.includes(origin)) {
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
