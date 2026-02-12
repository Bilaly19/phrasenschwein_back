const USERNAME_REGEX = /^[a-zA-Z0-9._-]+$/;
const NAME_REGEX = /^[\p{L}\p{N} ._-]+$/u;
const CONTROL_CHAR_REGEX = /[\x00-\x1F\x7F]/;

function validationResult(details) {
  if (!details.length) return { success: true };
  return { success: false, details };
}

function registerSchema(payload) {
  const details = [];
  if (typeof payload?.username !== 'string' || payload.username.length < 3 || payload.username.length > 40) {
    details.push({ path: 'username', message: 'username muss 3-40 Zeichen lang sein' });
  } else if (!USERNAME_REGEX.test(payload.username)) {
    details.push({ path: 'username', message: 'username darf nur a-z, A-Z, 0-9, . _ - enthalten' });
  }

  if (typeof payload?.password !== 'string' || payload.password.length < 8 || payload.password.length > 200) {
    details.push({ path: 'password', message: 'password muss 8-200 Zeichen lang sein' });
  }

  return validationResult(details);
}

function loginSchema(payload) {
  const details = [];
  if (typeof payload?.username !== 'string' || payload.username.length < 3 || payload.username.length > 40) {
    details.push({ path: 'username', message: 'username muss 3-40 Zeichen lang sein' });
  } else if (!USERNAME_REGEX.test(payload.username)) {
    details.push({ path: 'username', message: 'username darf nur a-z, A-Z, 0-9, . _ - enthalten' });
  }

  if (typeof payload?.password !== 'string' || payload.password.length < 1 || payload.password.length > 200) {
    details.push({ path: 'password', message: 'password muss 1-200 Zeichen lang sein' });
  }

  return validationResult(details);
}

function configSchema(payload) {
  const details = [];
  if (typeof payload?.valuePerClick !== 'number' || Number.isNaN(payload.valuePerClick) || payload.valuePerClick < 0 || payload.valuePerClick > 1000) {
    details.push({ path: 'valuePerClick', message: 'valuePerClick muss zwischen 0 und 1000 sein' });
  }
  return validationResult(details);
}

function addNameSchema(payload) {
  const details = [];
  if (typeof payload?.name !== 'string' || payload.name.length < 1 || payload.name.length > 60) {
    details.push({ path: 'name', message: 'name muss 1-60 Zeichen lang sein' });
  } else {
    if (!NAME_REGEX.test(payload.name)) details.push({ path: 'name', message: 'name enthält ungültige Zeichen' });
    if (CONTROL_CHAR_REGEX.test(payload.name)) details.push({ path: 'name', message: 'name darf keine Steuerzeichen enthalten' });
  }
  return validationResult(details);
}

function incrementParamsSchema(payload) {
  return addNameSchema(payload);
}

function emptyBodySchema(payload) {
  if (payload && typeof payload === 'object') return { success: true };
  return validationResult([{ path: '', message: 'Body muss ein JSON-Objekt sein' }]);
}

module.exports = {
  registerSchema,
  loginSchema,
  configSchema,
  addNameSchema,
  incrementParamsSchema,
  emptyBodySchema
};
