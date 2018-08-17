 'use strict';

const semver = require('semver');

module.exports = class AwsAddLambdaAccountPermissions {
  constructor(serverless, options) {
    if (!semver.satisfies(serverless.version, '>= 1.12')) {
      throw new Error('serverless-plugin-lambda-account-access requires serverless 1.12 or higher!');
    }
    this.serverless = serverless;
    this.options = options;
    this.provider = this.serverless.getProvider('aws');
    this.hooks = {
      'package:createDeploymentArtifacts': () => this.beforeDeploy(),
    };
  }

  addPoliciesForFunctions(globalAllowAccess) {
    const service = this.serverless.service;
    if (typeof service.functions !== 'object') {
      return;
    }

    const resources = service.resources = service.resources || {};
    if (!resources.Resources) {
      resources.Resources = {};
    }

    Object.keys(service.functions).forEach(functionName => {
      let localAllowAccess = service.functions[functionName].allowAccess;
      if (localAllowAccess === false || (globalAllowAccess.length === 0 && !localAllowAccess)) {
        return;
      }

      const functionAllowAccess = localAllowAccess
        ? [].concat(localAllowAccess)
        : globalAllowAccess;

      const functionLogicalId = this.provider.naming.getLambdaLogicalId(functionName);

      functionAllowAccess.reduce((previousResourceName, principal) => {
        let principalString;
        if (principal instanceof Object && principal['Fn::ImportValue']) {
          principalString = principal['Fn::ImportValue'];
        }
        else {
          principal = principal.toString();
          principalString = principal;
        }
        const principalName = principalString.replace(/\b\w/g, l => l.toUpperCase()).replace(/[_\W]+/g, "");
        const resourceName = `${functionLogicalId}PermitInvokeFrom${principalName}`;
        const resource = {
          Type: 'AWS::Lambda::Permission',
          Properties: {
            Action: 'lambda:InvokeFunction',
            FunctionName: {
              'Fn::GetAtt': [ functionLogicalId, 'Arn' ],
            },
            Principal: principal
          }
        };

        if (previousResourceName) {
          resource.DependsOn = previousResourceName;
        }

        resources.Resources[resourceName] = resource;
        return resourceName;
      }, null);
    });
  }

  beforeDeploy() {
    const service = this.serverless.service;
    let globalAllowAccess = service.provider && service.provider.allowAccess
      ? [].concat(service.provider.allowAccess)
      : [];

    this.addPoliciesForFunctions(globalAllowAccess);
  }
};
