'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');

const AwsAddLambdaAccountPermissions = require('../add-permissions');

function createTestInstance(options) {
  options = options || {};
  return new AwsAddLambdaAccountPermissions({
    version: options.version || '1.12.0',
    cli: {
      log: () => {}
    },
    service: {
      provider: options.provider,
      functions: options.functions,
      resources: options.resources ? { Resources: options.resources } : undefined
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
  }, {});
}

describe('serverless-plugin-lambda-account-access', function() {

  describe('#constructor', function() {
    it('should throw on older version', function() {
      expect(() => createTestInstance({ version: '1.11.0' }))
        .to.throw('serverless-plugin-lambda-account-access requires serverless 1.12 or higher!');
    });

    it('should create hooks', function() {
      const instance = createTestInstance();
      expect(instance)
        .to.have.property('hooks')
        .that.has.all.keys('package:createDeploymentArtifacts');

      const stub = sinon.stub(instance, 'beforeDeploy');
      instance.hooks['package:createDeploymentArtifacts']();

      sinon.assert.calledOnce(stub);
    });
  });

  describe('#beforeDeploy', function() {
    it('should not add resources when no functions defined', function() {
      const instance = createTestInstance({
        provider: {
          access: {
            groups: {
              api: {
                policy: {
                  principals: 111111111111
                }
              }
            }
          }
        }
      });

      instance.beforeDeploy();

      expect(instance)
        .to.have.nested.property('serverless.service.resources')
        .that.is.undefined;
    });

    it('should not add resources when provider config is not set', function() {
      const instance = createTestInstance({
        functions: {
          function1: {}
        }
      });

      instance.beforeDeploy();

      expect(instance)
        .to.have.nested.property('serverless.service.resources')
        .that.is.undefined;
    });

    it('should not add resources when access config is not set', function() {
      const instance = createTestInstance({
        provider: {},
        functions: {
          function1: {}
        }
      });

      instance.beforeDeploy();

      expect(instance)
        .to.have.nested.property('serverless.service.resources')
        .that.is.undefined;
    });

    it('should throw when access config does not have groups', function() {
      const instance = createTestInstance({
        provider: {
          access: {}
        },
        functions: {
          function1: {}
        }
      });

      expect(() => instance.beforeDeploy())
        .to.throw('Access configuration must have groups defined');
    });

    it('should throw when function references access group that does not exist', function() {
      const instance = createTestInstance({
        provider: {
          access: {
            groups: {}
          }
        },
        functions: {
          function1: {
            allowAccess: 'api'
          }
        }
      });

      expect(() => instance.beforeDeploy())
        .to.throw('Function "function1" references an access group "api" that does not exist');
    });

    it('should create resources object when no resources were configured', function() {
      const instance = createTestInstance({
        provider: {
          access: {
            groups: {}
          }
        },
        functions: {}
      });

      instance.beforeDeploy();

      expect(instance)
        .to.have.nested.property('serverless.service.resources')
        .that.deep.equals({
          Resources: {}
        });
    });

    it('should not override resources object when serverless has configured resources', function() {
      const testResources = { Gold: {} }
      const instance = createTestInstance({
        provider: {
          access: {
            groups: {}
          }
        },
        functions: {},
        resources: testResources
      });

      instance.beforeDeploy();

      expect(instance)
        .to.have.nested.property('serverless.service.resources')
        .that.deep.equals({
          Resources: testResources
        });
    });

    it('should log warning when group is not used', function() {
      const instance = createTestInstance({
        provider: {
          access: {
            groups: {
              api: {
                policy: {
                  principals: 111111111111
                }
              },
              api2: {
                policy: {
                  principals: 222222222222
                }
              }
            }
          }
        },
        functions: {
          function1: {
            allowAccess: 'api'
          }
        }
      });

      const stub = sinon.stub(instance.serverless.cli, 'log');

      instance.beforeDeploy();

      sinon.assert.calledWithExactly(stub, '[serverless-plugin-lambda-account-access]: WARNING: Group "api2" is not used');
    });

    describe('policy', function() {
      it('should throw when policy principals are not configured', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  policy: {}
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            }
          }
        });

        expect(() => instance.beforeDeploy())
          .to.throw('Group "api" does not have policy principals configured');
      });

      it('should support single principal', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  policy: {
                    principals: 111111111111
                  }
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            },
            function2: {
              allowAccess: 'api'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'Function1LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            },
            'Function2LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            }
          });
      });

      it('should support multiple principals', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  policy: {
                    principals: [111111111111, 222222222222]
                  }
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            },
            function2: {
              allowAccess: 'api'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'Function1LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            },
            'Function1LambdaFunctionPermitInvokeFrom222222222222': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': '222222222222'
              },
              'DependsOn': 'Function1LambdaFunctionPermitInvokeFrom111111111111'
            },
            'Function2LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            },
            'Function2LambdaFunctionPermitInvokeFrom222222222222': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ],
                },
                'Principal': '222222222222'
              },
              'DependsOn': 'Function2LambdaFunctionPermitInvokeFrom111111111111'
            }
          });
      });

      it('should support multiple group policies', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  policy: {
                    principals: 111111111111
                  }
                },
                api2: {
                  policy: {
                    principals: 222222222222
                  }
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: ['api', 'api2']
            },
            function2: {
              allowAccess: ['api', 'api2']
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'Function1LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            },
            'Function1LambdaFunctionPermitInvokeFrom222222222222': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': '222222222222'
              },
              'DependsOn': 'Function1LambdaFunctionPermitInvokeFrom111111111111'
            },
            'Function2LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            },
            'Function2LambdaFunctionPermitInvokeFrom222222222222': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ],
                },
                'Principal': '222222222222'
              },
              'DependsOn': 'Function2LambdaFunctionPermitInvokeFrom111111111111'
            }
          });
      });

      it('should not duplicate policy resources when multiple groups have the same principal', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  policy: {
                    principals: 111111111111
                  }
                },
                api2: {
                  policy: {
                    principals: 111111111111
                  }
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: ['api', 'api2']
            },
            function2: {
              allowAccess: ['api', 'api2']
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'Function1LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            },
            'Function2LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            }
          });
      });

      it('should not add policy resources for the function that does not have allowAccess set', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  policy: {
                    principals: 111111111111
                  }
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            },
            function2: {}
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'Function1LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            }
          });
      });

      it('should add function policy resources only for the groups set in allowAccess', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  policy: {
                    principals: 111111111111
                  }
                },
                api2: {
                  policy: {
                    principals: 222222222222
                  }
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            },
            function2: {
              allowAccess: 'api2'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'Function1LambdaFunctionPermitInvokeFrom111111111111': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': '111111111111'
              }
            },
            'Function2LambdaFunctionPermitInvokeFrom222222222222': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ],
                },
                'Principal': '222222222222'
              }
            }
          });
      });

      it('should support principal to be an ARN', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  policy: {
                    principals: 'arn:aws:iam::111111111111:root'
                  }
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'Function1LambdaFunctionPermitInvokeFromArnAwsIam111111111111Root': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': 'arn:aws:iam::111111111111:root'
              }
            }
          });
      });

      it('should support principal to be an ARN Output from CloudFormation', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  policy: {
                    principals: {'Fn::ImportValue':'output-role-arn'}
                  }
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'Function1LambdaFunctionPermitInvokeFromOutputRoleArn': {
              'Type': 'AWS::Lambda::Permission',
              'Properties': {
                'Action': 'lambda:InvokeFunction',
                'FunctionName': {
                  'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
                },
                'Principal': { 'Fn::ImportValue':'output-role-arn' }
              }
            }
          });
      });
    });

    describe('role', function() {
      it('should throw when role does not have name', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    principals: 111111111111
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            }
          }
        });

        expect(() => instance.beforeDeploy())
          .to.throw('Group "api" does not have role name configured');
      });

      it('should throw when role does not have principals', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo'
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            }
          }
        });

        expect(() => instance.beforeDeploy())
          .to.throw('Role "foo" in the "api" group does not have principals configured');
      });

      it('should throw when role names are not unique', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo',
                    principals: 111111111111
                  }]
                },
                api2: {
                  role: [{
                    name: 'foo',
                    principals: 222222222222
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: ['api', 'api2']
            }
          }
        });

        expect(() => instance.beforeDeploy())
          .to.throw('Roles must have unique names [foo]');
      });

      it('should not create role when principals list is empty', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo',
                    principals: []
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({});
      });

      it('should support single principal', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo',
                    principals: 111111111111
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            },
            function2: {
              allowAccess: 'api'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'LambdaAccessRoleFoo': {
              'Type': 'AWS::IAM::Role',
              'Properties': {
                'RoleName': 'foo',
                'Policies': [{
                  'PolicyName': 'foo',
                  'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                      'Effect': 'Allow',
                      'Action': 'lambda:InvokeFunction',
                      'Resource': [
                        { 'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ] },
                        { 'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ] }
                      ]
                    }]
                  }
                }],
                'AssumeRolePolicyDocument': {
                  'Version': '2012-10-17',
                  'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                      AWS: ['111111111111']
                    }
                  }]
                }
              }
            }
          });
      });

      it('should support multiple principals', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo',
                    principals: [111111111111, 222222222222]
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            },
            function2: {
              allowAccess: 'api'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'LambdaAccessRoleFoo': {
              'Type': 'AWS::IAM::Role',
              'Properties': {
                'RoleName': 'foo',
                'Policies': [{
                  'PolicyName': 'foo',
                  'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                      'Effect': 'Allow',
                      'Action': 'lambda:InvokeFunction',
                      'Resource': [
                        { 'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ] },
                        { 'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ] }
                      ]
                    }]
                  }
                }],
                'AssumeRolePolicyDocument': {
                  'Version': '2012-10-17',
                  'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                      AWS: ['111111111111', '222222222222']
                    }
                  }]
                }
              }
            }
          });
      });

      it('should support adding function to multiple roles', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo',
                    principals: 111111111111
                  }]
                },
                api2: {
                  role: [{
                    name: 'foo2',
                    principals: 222222222222
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: ['api', 'api2']
            },
            function2: {
              allowAccess: ['api', 'api2']
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'LambdaAccessRoleFoo': {
              'Type': 'AWS::IAM::Role',
              'Properties': {
                'RoleName': 'foo',
                'Policies': [{
                  'PolicyName': 'foo',
                  'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                      'Effect': 'Allow',
                      'Action': 'lambda:InvokeFunction',
                      'Resource': [
                        { 'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ] },
                        { 'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ] }
                      ]
                    }]
                  }
                }],
                'AssumeRolePolicyDocument': {
                  'Version': '2012-10-17',
                  'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                      AWS: ['111111111111']
                    }
                  }]
                }
              }
            },
            'LambdaAccessRoleFoo2': {
              'Type': 'AWS::IAM::Role',
              'Properties': {
                'RoleName': 'foo2',
                'Policies': [{
                  'PolicyName': 'foo2',
                  'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                      'Effect': 'Allow',
                      'Action': 'lambda:InvokeFunction',
                      'Resource': [
                        { 'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ] },
                        { 'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ] }
                      ]
                    }]
                  }
                }],
                'AssumeRolePolicyDocument': {
                  'Version': '2012-10-17',
                  'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                      AWS: ['222222222222']
                    }
                  }]
                }
              }
            }
          });
      });

      it('should not allow role access to the function that does not have allowAccess set', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo',
                    principals: 111111111111
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            },
            function2: {}
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'LambdaAccessRoleFoo': {
              'Type': 'AWS::IAM::Role',
              'Properties': {
                'RoleName': 'foo',
                'Policies': [{
                  'PolicyName': 'foo',
                  'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                      'Effect': 'Allow',
                      'Action': 'lambda:InvokeFunction',
                      'Resource': [
                        { 'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ] }
                      ]
                    }]
                  }
                }],
                'AssumeRolePolicyDocument': {
                  'Version': '2012-10-17',
                  'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                      AWS: ['111111111111']
                    }
                  }]
                }
              }
            }
          });
      });

      it('should allow role access to the function only for the groups set in allowAccess', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo',
                    principals: 111111111111
                  }]
                },
                api2: {
                  role: [{
                    name: 'foo2',
                    principals: 222222222222
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            },
            function2: {
              allowAccess: 'api2'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'LambdaAccessRoleFoo': {
              'Type': 'AWS::IAM::Role',
              'Properties': {
                'RoleName': 'foo',
                'Policies': [{
                  'PolicyName': 'foo',
                  'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                      'Effect': 'Allow',
                      'Action': 'lambda:InvokeFunction',
                      'Resource': [
                        { 'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ] }
                      ]
                    }]
                  }
                }],
                'AssumeRolePolicyDocument': {
                  'Version': '2012-10-17',
                  'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                      AWS: ['111111111111']
                    }
                  }]
                }
              }
            },
            'LambdaAccessRoleFoo2': {
              'Type': 'AWS::IAM::Role',
              'Properties': {
                'RoleName': 'foo2',
                'Policies': [{
                  'PolicyName': 'foo2',
                  'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                      'Effect': 'Allow',
                      'Action': 'lambda:InvokeFunction',
                      'Resource': [
                        { 'Fn::GetAtt': [ 'Function2LambdaFunction', 'Arn' ] }
                      ]
                    }]
                  }
                }],
                'AssumeRolePolicyDocument': {
                  'Version': '2012-10-17',
                  'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                      AWS: ['222222222222']
                    }
                  }]
                }
              }
            }
          });
      });

      it('should support principal to be an ARN', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo',
                    principals: 'arn:aws:iam::111111111111:root'
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'LambdaAccessRoleFoo': {
              'Type': 'AWS::IAM::Role',
              'Properties': {
                'RoleName': 'foo',
                'Policies': [{
                  'PolicyName': 'foo',
                  'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                      'Effect': 'Allow',
                      'Action': 'lambda:InvokeFunction',
                      'Resource': [
                        { 'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ] }
                      ]
                    }]
                  }
                }],
                'AssumeRolePolicyDocument': {
                  'Version': '2012-10-17',
                  'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                      AWS: ['arn:aws:iam::111111111111:root']
                    }
                  }]
                }
              }
            }
          });
      });

      it('should support principal to be an ARN Output from CloudFormation', function() {
        const instance = createTestInstance({
          provider: {
            access: {
              groups: {
                api: {
                  role: [{
                    name: 'foo',
                    principals: {'Fn::ImportValue':'output-role-arn'}
                  }]
                }
              }
            }
          },
          functions: {
            function1: {
              allowAccess: 'api'
            }
          }
        });

        instance.beforeDeploy();

        expect(instance)
          .to.have.nested.property('serverless.service.resources.Resources')
          .that.deep.equals({
            'LambdaAccessRoleFoo': {
              'Type': 'AWS::IAM::Role',
              'Properties': {
                'RoleName': 'foo',
                'Policies': [{
                  'PolicyName': 'foo',
                  'PolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [{
                      'Effect': 'Allow',
                      'Action': 'lambda:InvokeFunction',
                      'Resource': [
                        { 'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ] }
                      ]
                    }]
                  }
                }],
                'AssumeRolePolicyDocument': {
                  'Version': '2012-10-17',
                  'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Principal': {
                      AWS: [
                        { 'Fn::ImportValue':'output-role-arn' }
                      ]
                    }
                  }]
                }
              }
            }
          });
      });
    });
  });
});
