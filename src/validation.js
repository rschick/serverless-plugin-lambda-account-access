'use strict';

const functionSchema = () => {
  return {
    properties: {
      allowAccess: {
        anyOf: [{
          type: 'array',
          items: {
            type: 'string'
          }
        }, {
          type: 'string'
        }
      ]
      },
    },
  }
}

const providerSchema = () => {
  return {
      provider: {
        properties: {
          access: { type: 'object' },
        },
      }
    }
}

const hasValidationSupport = (serverless, validationFunction) => {
  return serverless.configSchemaHandler &&
    serverless.configSchemaHandler[validationFunction] &&
    typeof serverless.configSchemaHandler[validationFunction] === 'function';
}

module.exports = (serverless) => {
  if (hasValidationSupport(serverless, 'defineFunctionProperties')) {
    serverless.configSchemaHandler.defineFunctionProperties('aws', functionSchema());
  }
  if (hasValidationSupport(serverless, 'defineProvider')) {
    serverless.configSchemaHandler.defineProvider('aws', providerSchema());
  }
}
