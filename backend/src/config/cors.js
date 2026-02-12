const { env } = require('./env');

const corsOptions = {
  origin(origin, callback) {
    if (!origin || env.corsOrigins.includes(origin)) {
      callback(null, true);
      return;
    }

    callback(Object.assign(new Error('CORS: Origin nicht erlaubt'), { statusCode: 403 }));
  },
  credentials: true,
  methods: ['GET', 'POST', 'DELETE']
};

module.exports = { corsOptions };
