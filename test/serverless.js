'use strict';

module.exports = ({
  functions,
  includeValidation = true,
  provider,
  resources,
  version = '1.12.0'
} = {}) => {
  const serverless = {
    version: version,
    cli: {
      log: () => {}
    },
    service: {
      provider: provider,
      functions: functions,
      resources: resources ? { Resources: resources } : undefined
    },
    getProvider: () => {
      return {
        naming: {
          getLambdaLogicalId(functionName) {
            return `${functionName.charAt(0).toUpperCase()}${functionName.slice(1)}LambdaFunction`
          }
        }
      };
    }
  };

  if (includeValidation) {
    serverless.configSchemaHandler = {
      defineFunctionProperties: () => {},
      defineProvider: () => {},
    };
  }

  return serverless;
};
