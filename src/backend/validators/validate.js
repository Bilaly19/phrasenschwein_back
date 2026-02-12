const { AppError } = require('../utils/http');

function validateBody(schema) {
  return (req, _res, next) => {
    const result = schema(req.body);
    if (result.success) {
      next();
      return;
    }

    next(new AppError(400, 'VALIDATION_ERROR', 'Ungültige Eingabe', result.details));
  };
}

function validateParams(schema) {
  return (req, _res, next) => {
    const result = schema(req.params);
    if (result.success) {
      next();
      return;
    }

    next(new AppError(400, 'VALIDATION_ERROR', 'Ungültige Eingabe', result.details));
  };
}

module.exports = {
  validateBody,
  validateParams
};
