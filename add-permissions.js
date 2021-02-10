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
    this.serverless.configSchemaHandler.defineFunctionProperties(this.provider, {
      properties: {
        allowAccess: { type: 'array' },
      },
    });
   this.serverless.configSchemaHandler.defineProvider(this.provider, {
      provider: {
        properties: {
          access: { type: 'object' },
        },
      }
    });
  }

  addPermissions(accessConfig) {
    const { service } = this.serverless;
    const resources = service.resources = service.resources || {};
    if (!resources.Resources) {
      resources.Resources = {};
    }

    Object.keys(accessConfig).reduce((dependsOnList, groupName) => {
      const { functions, policy, role } = accessConfig[groupName];

      if (functions.length !== 0) {
        if (policy) {
          const { principals } = policy;
          if (!principals) {
            throw new Error(`Group "${groupName}" does not have policy principals configured`);
          }

          [].concat(principals).forEach(principal => {
            const {
              principal: normalizedPrincipal,
              principalName
            } = this.normalizePrincipal(principal);

            functions.forEach(functionLogicalId => {
              const resourceName = `${functionLogicalId}PermitInvokeFrom${principalName}`;

              if (!resources.Resources[resourceName]) {
                const resource = {
                  Type: 'AWS::Lambda::Permission',
                  Properties: {
                    Action: 'lambda:InvokeFunction',
                    FunctionName: {
                      'Fn::GetAtt': [ functionLogicalId, 'Arn' ],
                    },
                    Principal: normalizedPrincipal
                  }
                };

                const dependsOn = dependsOnList[functionLogicalId];
                if (dependsOn) {
                  resource.DependsOn = dependsOn;
                }

                resources.Resources[resourceName] = resource;
                dependsOnList[functionLogicalId] = resourceName;
              }
            });
          });
        }

        if (role) {
          [].concat(role).forEach(({ name, principals }) => {
            if (!name) {
              throw new Error(`Group "${groupName}" does not have role name configured`);
            }

            if (!principals) {
              throw new Error(`Role "${name}" in the "${groupName}" group does not have principals configured`);
            }

            const resourceName = `LambdaAccessRole${this.normalizeName(name)}`;
            if (resources.Resources[resourceName]) {
              throw new Error(`Roles must have unique names [${name}]`);
            }

            if (principals.length !== 0) {
              const resource = {
                Type: 'AWS::IAM::Role',
                Properties: {
                  RoleName: name,
                  Policies: [{
                    PolicyName: name,
                    PolicyDocument: {
                      Version: '2012-10-17',
                      Statement: [{
                        Effect: 'Allow',
                        Action: 'lambda:InvokeFunction',
                        Resource: functions.map(functionLogicalId => ({
                          'Fn::GetAtt': [ functionLogicalId, 'Arn' ]
                        }))
                      }]
                    }
                  }],
                  AssumeRolePolicyDocument: {
                    Version: '2012-10-17',
                    Statement: [{
                      Effect: 'Allow',
                      Action: 'sts:AssumeRole',
                      Principal: {
                        AWS: [].concat(principals).map(principal => this.normalizePrincipal(principal).principal)
                      }
                    }]
                  }
                }
              };

              resources.Resources[resourceName] = resource;
            }
          });
        }
      } else {
        this.log(`WARNING: Group "${groupName}" is not used`);
      }

      return dependsOnList;
    }, {});
  }

  beforeDeploy() {
    const { service } = this.serverless;
    const { functions, provider: { access } = {} } = service;
    if (typeof functions !== 'object' || !access) {
      return;
    }

    const { groups } = access;
    if (!groups) {
      throw new Error('Access configuration must have groups defined');
    }

    const accessConfig = this.compileAccessConfig(groups, functions);

    this.addPermissions(accessConfig);
  }

  compileAccessConfig(groups, functions) {
    const accessConfig = Object.keys(groups).reduce((acc, groupName) => {
      const { policy, role } = groups[groupName];
      acc[groupName] = {
        functions: [],
        policy,
        role
      };

      return acc;
    }, {});

    return Object.keys(functions).reduce((acc, functionName) => {
      const { allowAccess } = functions[functionName];

      if (allowAccess) {
        const functionLogicalId = this.provider.naming.getLambdaLogicalId(functionName);
        [].concat(allowAccess).forEach(groupName => {
          const groupConf = acc[groupName];
          if (!groupConf) {
            throw new Error(`Function "${functionName}" references an access group "${groupName}" that does not exist`);
          }

          groupConf.functions.push(functionLogicalId);
        });
      }

      return acc;
    }, accessConfig);
  }

  log(message) {
    this.serverless.cli.log(`[serverless-plugin-lambda-account-access]: ${message}`);
  }

  normalizeName(name) {
    return name.replace(/\b\w/g, l => l.toUpperCase()).replace(/[_\W]+/g, "");
  }

  normalizePrincipal(principal) {
    let principalString;
    const fnName = principal instanceof Object ? Object.keys(principal).find(k => k.indexOf('Fn::') >= 0) : undefined;
    if (fnName) {
      principalString = principal[fnName].toString();
    } else {
      principal = principal.toString();
      principalString = principal;
    }

    return {
      principal,
      principalName: this.normalizeName(principalString)
    };
  }
};
