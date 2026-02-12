const { AppError } = require('../utils/appError');

function withValidation(validator, source) {
  return (req, _res, next) => {
    const details = validator(req[source]);
    if (details.length) {
      return next(new AppError(400, 'VALIDATION_ERROR', 'Ungültige Eingabe', details));
    }
    return next();
  };
}

function validateBody(validator) {
  return withValidation(validator, 'body');
}

function validateParams(validator) {
  return withValidation(validator, 'params');
}

module.exports = { validateBody, validateParams };
