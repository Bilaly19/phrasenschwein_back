const { env } = require('../config/env');

const usernameRegex = /^[a-zA-Z0-9._-]+$/;
const nameRegex = /^[\p{L}\p{N} ._-]+$/u;
const controlCharRegex = /[\x00-\x1F\x7F]/;

function error(path, message) {
  return { path, message };
}

function validateRegister(payload) {
  const details = [];

  if (typeof payload?.username !== 'string' || payload.username.length < 3 || payload.username.length > 40) {
    details.push(error('username', 'username muss 3-40 Zeichen lang sein'));
  } else if (!usernameRegex.test(payload.username)) {
    details.push(error('username', 'username darf nur a-z, A-Z, 0-9, . _ - enthalten'));
  }

  if (typeof payload?.password !== 'string' || payload.password.length < env.passwordMinLength || payload.password.length > env.passwordMaxLength) {
    details.push(error('password', `password muss ${env.passwordMinLength}-${env.passwordMaxLength} Zeichen lang sein`));
  } else {
    if (!/[A-Z]/.test(payload.password)) {
      details.push(error('password', 'password muss mindestens 1 Großbuchstaben enthalten'));
    }
    if (!/[a-z]/.test(payload.password)) {
      details.push(error('password', 'password muss mindestens 1 Kleinbuchstaben enthalten'));
    }
    if (!/\d/.test(payload.password)) {
      details.push(error('password', 'password muss mindestens 1 Zahl enthalten'));
    }
  }

  return details;
}

function validateLogin(payload) {
  const details = [];

  if (typeof payload?.username !== 'string' || payload.username.length < 3 || payload.username.length > 40 || !usernameRegex.test(payload.username)) {
    details.push(error('username', 'Ungültiger username'));
  }

  if (typeof payload?.password !== 'string' || payload.password.length < 1 || payload.password.length > env.passwordMaxLength) {
    details.push(error('password', 'Ungültiges password'));
  }

  return details;
}

function validateConfig(payload) {
  const value = payload?.valuePerClick;
  if (typeof value !== 'number' || Number.isNaN(value) || value < 0 || value > 1000) {
    return [error('valuePerClick', 'valuePerClick muss eine Zahl zwischen 0 und 1000 sein')];
  }
  return [];
}

function validateNamePayload(payload) {
  const name = payload?.name;
  const details = [];
  if (typeof name !== 'string' || name.length < 1 || name.length > 60) {
    details.push(error('name', 'name muss 1-60 Zeichen lang sein'));
  } else {
    if (!nameRegex.test(name)) {
      details.push(error('name', 'name enthält ungültige Zeichen'));
    }
    if (controlCharRegex.test(name)) {
      details.push(error('name', 'name darf keine Steuerzeichen enthalten'));
    }
  }
  return details;
}

function validateNameParam(params) {
  return validateNamePayload(params);
}

function validateEmptyObject(payload) {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    return [];
  }
  return [error('', 'Body muss ein JSON-Objekt sein')];
}

module.exports = {
  validateRegister,
  validateLogin,
  validateConfig,
  validateNamePayload,
  validateNameParam,
  validateEmptyObject
};
