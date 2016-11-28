 'use strict';

const semver = require('semver');

module.exports = class AwsAddLambdaAccountPermissions {
  constructor(serverless, options) {
    if (!semver.satisfies(serverless.version, '>= 1.2')) {
      throw new Error('serverless-plugin-lambda-account-access requires serverless 1.2 or higher!');
    }
    this.serverless = serverless;
    this.options = options;
    this.provider = this.serverless.getProvider('aws');
    this.hooks = {
      'before:deploy:deploy': () => this.beforeDeploy(),
    };
  }

  addPoliciesForAccount(account) {
    const service = this.serverless.service;
    if (typeof service.functions !== 'object') {
      return;
    }
    const resources = service.resources || {};
    if (!resources.Resources) {
      resources.Resources = {};
    }
    Object.keys(service.functions).forEach(functionName => {
      const functionLogicalId = this.provider.naming
        .getLambdaLogicalId(functionName);
      resources.Resources[`${functionLogicalId}PermitInvokeFromAccount${account}`] = {
        Type: 'AWS::Lambda::Permission',
        Properties: {
          Action: 'lambda:InvokeFunction',
          FunctionName: {
            'Fn::GetAtt': [ functionLogicalId, 'Arn' ],
          },
          Principal: account,
        }
      };
    });
  }

  beforeDeploy() {
    const service = this.serverless.service;
    const permitAccounts = service.provider && service.provider.permitAccounts.toString();
    if (permitAccounts) {
      permitAccounts.split(',').map(this.addPoliciesForAccount.bind(this));
    }
  }
};