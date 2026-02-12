const { validateBody, validateParams } = require('./src/backend/validators/validate');
const {
  registerSchema,
  loginSchema,
  configSchema,
  addNameSchema,
  incrementParamsSchema,
  emptyBodySchema
} = require('./src/backend/validators/schemas');

function toLegacyValidator(schema) {
  return (payload) => {
    const result = schema(payload);
    if (result.success) {
      return null;
    }

    return {
      message: 'Ungültige Eingabe',
      details: result.details
    };
  };
}

module.exports = {
  validateBody,
  validateParams,
  validators: {
    validateRegisterLogin: toLegacyValidator(registerSchema),
    validateLogin: toLegacyValidator(loginSchema),
    validateConfig: toLegacyValidator(configSchema),
    validateNamePayload: toLegacyValidator(addNameSchema),
    validateNameParams: toLegacyValidator(incrementParamsSchema),
    validateEmptyBody: toLegacyValidator(emptyBodySchema)
  }
};
