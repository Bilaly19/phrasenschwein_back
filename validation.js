const USERNAME_REGEX = /^[a-zA-Z0-9._-]+$/;
const NAME_REGEX = /^[\p{L}\p{N} ._-]+$/u;
const CONTROL_CHAR_REGEX = /[\x00-\x1F\x7F]/;

function makeValidationError(message, details) {
  return {
    message,
    details
  };
}

function validateRegisterLogin(payload) {
  const details = [];

  if (typeof payload?.username !== 'string' || payload.username.length < 3 || payload.username.length > 40) {
    details.push({ path: 'username', message: 'username muss 3-40 Zeichen lang sein' });
  } else if (!USERNAME_REGEX.test(payload.username)) {
    details.push({ path: 'username', message: 'username darf nur a-z, A-Z, 0-9, . _ - enthalten' });
  }

  if (typeof payload?.password !== 'string' || payload.password.length < 8 || payload.password.length > 200) {
    details.push({ path: 'password', message: 'password muss 8-200 Zeichen lang sein' });
  }

  return details.length ? makeValidationError('Ungültige Eingabe', details) : null;
}

function validateConfig(payload) {
  const details = [];
  const value = payload?.valuePerClick;

  if (typeof value !== 'number' || Number.isNaN(value) || value < 0 || value > 1000) {
    details.push({ path: 'valuePerClick', message: 'valuePerClick muss eine Zahl zwischen 0 und 1000 sein' });
  }

  return details.length ? makeValidationError('Ungültige Eingabe', details) : null;
}

function validateNamePayload(payload) {
  const details = [];
  const name = payload?.name;

  if (typeof name !== 'string' || name.length < 1 || name.length > 60) {
    details.push({ path: 'name', message: 'name muss 1-60 Zeichen lang sein' });
  } else {
    if (!NAME_REGEX.test(name)) {
      details.push({ path: 'name', message: 'name enthält ungültige Zeichen' });
    }
    if (CONTROL_CHAR_REGEX.test(name)) {
      details.push({ path: 'name', message: 'name darf keine Steuerzeichen enthalten' });
    }
  }

  return details.length ? makeValidationError('Ungültige Eingabe', details) : null;
}

function validateNameParams(params) {
  return validateNamePayload(params);
}

function validateEmptyBody(payload) {
  if (payload && typeof payload === 'object') {
    return null;
  }

  return makeValidationError('Ungültige Eingabe', [{ path: '', message: 'Body muss ein JSON-Objekt sein' }]);
}

function validateBody(validator) {
  return (req, res, next) => {
    const error = validator(req.body);
    if (error) {
      return res.status(400).json(error);
    }

    next();
  };
}

function validateParams(validator) {
  return (req, res, next) => {
    const error = validator(req.params);
    if (error) {
      return res.status(400).json(error);
    }

    next();
  };
}

module.exports = {
  validateBody,
  validateParams,
  validators: {
    validateRegisterLogin,
    validateConfig,
    validateNamePayload,
    validateNameParams,
    validateEmptyBody
  }
};
