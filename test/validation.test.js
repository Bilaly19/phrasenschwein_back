const test = require('node:test');
const assert = require('node:assert/strict');

const {
  registerSchema,
  configSchema,
  addNameSchema
} = require('../src/backend/validators/schemas');

test('registerSchema accepts valid credentials', () => {
  const result = registerSchema({ username: 'user_123', password: '12345678' });
  assert.equal(result.success, true);
});

test('registerSchema rejects short passwords', () => {
  const result = registerSchema({ username: 'user_123', password: '123' });
  assert.equal(result.success, false);
  assert.ok(result.details.some((detail) => detail.path === 'password'));
});

test('addNameSchema rejects control characters', () => {
  const result = addNameSchema({ name: 'Max\nMustermann' });
  assert.equal(result.success, false);
  assert.ok(result.details.some((detail) => detail.message.includes('Steuerzeichen')));
});

test('configSchema accepts numbers in valid range', () => {
  assert.equal(configSchema({ valuePerClick: 0 }).success, true);
  assert.equal(configSchema({ valuePerClick: 1000 }).success, true);
});
