const USERNAME_REGEX = /^[a-zA-Z0-9._-]+$/;
const PERSON_NAME_REGEX = /^[\p{L} -]+$/u;
const CONTROL_CHAR_REGEX = /[\x00-\x1F\x7F]/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function validationResult(details) {
  if (!details.length) return { success: true };
  return { success: false, details };
}

function validateUsername(value, fieldName, details) {
  const username = typeof value === 'string' ? value.trim() : '';

  if (username.length < 3 || username.length > 24) {
    details.push({ path: fieldName, message: `${fieldName} muss 3-24 Zeichen lang sein` });
  } else if (!USERNAME_REGEX.test(username)) {
    details.push({ path: fieldName, message: `${fieldName} darf nur a-z, A-Z, 0-9, . _ - enthalten` });
  }
}

function registerSchema(payload) {
  const details = [];
  const firstName = typeof payload?.firstName === 'string' ? payload.firstName.trim() : '';
  const lastName = typeof payload?.lastName === 'string' ? payload.lastName.trim() : '';

  validateUsername(payload?.username, 'username', details);

  if (firstName.length < 1 || firstName.length > 50) {
    details.push({ path: 'firstName', message: 'firstName muss 1-50 Zeichen lang sein' });
  } else if (!PERSON_NAME_REGEX.test(firstName) || CONTROL_CHAR_REGEX.test(firstName)) {
    details.push({ path: 'firstName', message: 'firstName darf nur Buchstaben, Leerzeichen und - enthalten' });
  }

  if (lastName.length < 1 || lastName.length > 50) {
    details.push({ path: 'lastName', message: 'lastName muss 1-50 Zeichen lang sein' });
  } else if (!PERSON_NAME_REGEX.test(lastName) || CONTROL_CHAR_REGEX.test(lastName)) {
    details.push({ path: 'lastName', message: 'lastName darf nur Buchstaben, Leerzeichen und - enthalten' });
  }

  if (typeof payload?.password !== 'string' || payload.password.length < 8 || payload.password.length > 200) {
    details.push({ path: 'password', message: 'password muss 8-200 Zeichen lang sein' });
  }

  return validationResult(details);
}

function loginSchema(payload) {
  const details = [];
  validateUsername(payload?.username, 'username', details);

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

  if (payload?.paypalLink !== undefined) {
    if (typeof payload.paypalLink !== 'string' || payload.paypalLink.length > 2048) {
      details.push({ path: 'paypalLink', message: 'paypalLink muss ein String mit maximal 2048 Zeichen sein' });
    } else {
      const trimmed = payload.paypalLink.trim();
      if (CONTROL_CHAR_REGEX.test(trimmed)) {
        details.push({ path: 'paypalLink', message: 'paypalLink darf keine Steuerzeichen enthalten' });
      } else if (trimmed && !/^https?:\/\//i.test(trimmed)) {
        details.push({ path: 'paypalLink', message: 'paypalLink muss mit http:// oder https:// beginnen' });
      }
    }
  }
  return validationResult(details);
}

function addNameSchema(payload) {
  const details = [];
  if (typeof payload?.name !== 'string' || payload.name.length < 1 || payload.name.length > 24) {
    details.push({ path: 'name', message: 'name muss 1-24 Zeichen lang sein' });
  } else if (!USERNAME_REGEX.test(payload.name)) {
    details.push({ path: 'name', message: 'name enthaelt ungueltige Zeichen' });
  } else if (CONTROL_CHAR_REGEX.test(payload.name)) {
    details.push({ path: 'name', message: 'name darf keine Steuerzeichen enthalten' });
  }
  return validationResult(details);
}

function incrementParamsSchema(payload) {
  return addNameSchema(payload);
}

function usernameParamsSchema(payload) {
  const details = [];
  validateUsername(payload?.username, 'username', details);
  return validationResult(details);
}

function roleUpdateSchema(payload) {
  const details = [];
  if (!Array.isArray(payload?.roles) || payload.roles.length === 0) {
    details.push({ path: 'roles', message: 'roles muss ein nicht-leeres Array sein' });
  } else {
    const hasInvalid = payload.roles.some((role) => typeof role !== 'string' || !role.trim());
    if (hasInvalid) {
      details.push({ path: 'roles', message: 'roles darf nur nicht-leere Strings enthalten' });
    }
  }

  return validationResult(details);
}

function emptyBodySchema(payload) {
  if (payload && typeof payload === 'object') return { success: true };
  return validationResult([{ path: '', message: 'Body muss ein JSON-Objekt sein' }]);
}

function pigIdParamsSchema(payload) {
  const details = [];
  const pigId = typeof payload?.pigId === 'string' ? payload.pigId.trim() : '';
  if (!pigId || !UUID_REGEX.test(pigId)) {
    details.push({ path: 'pigId', message: 'pigId muss eine UUID sein' });
  }
  return validationResult(details);
}

function createPigSchema(payload) {
  const details = [];
  const title = typeof payload?.title === 'string' ? payload.title.trim() : '';

  if (title) {
    if (title.length < 1 || title.length > 60) {
      details.push({ path: 'title', message: 'title muss 1-60 Zeichen lang sein' });
    } else if (CONTROL_CHAR_REGEX.test(title)) {
      details.push({ path: 'title', message: 'title darf keine Steuerzeichen enthalten' });
    }
  }

  return validationResult(details);
}

function createInviteSchema(payload) {
  const details = [];
  const maxUses = payload?.maxUses;
  const ttlHours = payload?.ttlHours;

  if (maxUses !== undefined) {
    if (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > 100) {
      details.push({ path: 'maxUses', message: 'maxUses muss eine ganze Zahl zwischen 1 und 100 sein' });
    }
  }

  if (ttlHours !== undefined) {
    if (!Number.isInteger(ttlHours) || ttlHours < 1 || ttlHours > 24 * 30) {
      details.push({ path: 'ttlHours', message: 'ttlHours muss eine ganze Zahl zwischen 1 und 720 sein' });
    }
  }

  return validationResult(details);
}

function acceptInviteSchema(payload) {
  const details = [];
  const token = typeof payload?.token === 'string' ? payload.token.trim() : '';

  if (token.length < 8 || token.length > 200) {
    details.push({ path: 'token', message: 'token muss 8-200 Zeichen lang sein' });
  } else if (CONTROL_CHAR_REGEX.test(token)) {
    details.push({ path: 'token', message: 'token darf keine Steuerzeichen enthalten' });
  }

  return validationResult(details);
}

module.exports = {
  registerSchema,
  loginSchema,
  configSchema,
  addNameSchema,
  incrementParamsSchema,
  usernameParamsSchema,
  roleUpdateSchema,
  emptyBodySchema,
  pigIdParamsSchema,
  createPigSchema,
  createInviteSchema,
  acceptInviteSchema
};
