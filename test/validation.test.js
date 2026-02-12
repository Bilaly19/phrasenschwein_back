const test = require('node:test');
const assert = require('node:assert/strict');

const { validators } = require('../validation');

test('validateRegisterLogin akzeptiert gültige Nutzerdaten', () => {
  const result = validators.validateRegisterLogin({ username: 'user_123', password: '12345678' });
  assert.equal(result, null);
});

test('validateRegisterLogin lehnt kurze Passwörter ab', () => {
  const result = validators.validateRegisterLogin({ username: 'user_123', password: '123' });
  assert.equal(result.message, 'Ungültige Eingabe');
  assert.ok(result.details.some((detail) => detail.path === 'password'));
});

test('validateNamePayload lehnt Steuerzeichen ab', () => {
  const result = validators.validateNamePayload({ name: 'Max\nMustermann' });
  assert.equal(result.message, 'Ungültige Eingabe');
  assert.ok(result.details.some((detail) => detail.message.includes('Steuerzeichen')));
});

test('validateConfig akzeptiert Zahlen im erlaubten Bereich', () => {
  assert.equal(validators.validateConfig({ valuePerClick: 0 }), null);
  assert.equal(validators.validateConfig({ valuePerClick: 1000 }), null);
});
