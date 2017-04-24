'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');

const AwsAddLambdaAccountPermissions = require('../add-permissions');

function createTestInstance(options) {
  options = options || {};
  return new AwsAddLambdaAccountPermissions({
    version: options.version || '1.2.0',
    service: {
      provider: options.provider || {},
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
      expect(() => createTestInstance({ version: '1.1.1' }))
        .to.throw('serverless-plugin-lambda-account-access requires serverless 1.2 or higher!');
    });

    it('should create hooks', function() {
      const instance = createTestInstance();
      expect(instance)
        .to.have.property('hooks')
        .that.has.all.keys('before:deploy:createDeploymentArtifacts');

      const stub = sinon.stub(instance, 'addPoliciesForFunctions');
      instance.hooks['before:deploy:createDeploymentArtifacts']();

      sinon.assert.calledOnce(stub);
    });
  });

  describe('#beforeDeploy', function() {
    describe('should properly call addPoliciesForFunctions', function() {
      it('when global allowAccess option is a single value', function() {
        const allowAccess = '111111111111';
        const instance = createTestInstance({
          provider: { allowAccess }
        });
        const stub = sinon.stub(instance, 'addPoliciesForFunctions');

        instance.beforeDeploy();

        sinon.assert.calledOnce(stub);
        sinon.assert.calledWithExactly(stub, [allowAccess]);
      });

      it('when global allowAccess option is an array', function() {
        const allowAccess = ['111111111111', '222222222222'];
        const instance = createTestInstance({
          provider: { allowAccess }
        });
        const stub = sinon.stub(instance, 'addPoliciesForFunctions');

        instance.beforeDeploy();

        sinon.assert.calledOnce(stub);
        sinon.assert.calledWithExactly(stub, allowAccess);
      });

      it('when global allowAccess option is not defined', function() {
        const instance = createTestInstance();
        const stub = sinon.stub(instance, 'addPoliciesForFunctions');

        instance.beforeDeploy();

        sinon.assert.calledOnce(stub);
        sinon.assert.calledWithExactly(stub, []);
      });
    });
  });

  describe('#addPoliciesForFunctions', function() {
    it('should not add resources when no functions defined', function() {
      const instance = createTestInstance();

      instance.addPoliciesForFunctions([]);

      expect(instance)
        .to.have.deep.property('serverless.service.resources')
        .that.is.undefined;
    });

    it('should create resources object when no resources were configured', function() {
      const instance = createTestInstance({ functions: {} });

      instance.addPoliciesForFunctions([]);

      expect(instance)
        .to.have.deep.property('serverless.service.resources')
        .that.deep.equals({
          Resources: {}
        });
    });

    it('should not override resources object when serverless has configured resources', function() {
      const testResources = { Gold: {} }
      const instance = createTestInstance({
        functions: {},
        resources: testResources
      });

      instance.addPoliciesForFunctions([]);

      expect(instance)
        .to.have.deep.property('serverless.service.resources')
        .that.deep.equals({
          Resources: testResources
        });
    });

    it('should allow access for principals that are defined globally', function() {
      const instance = createTestInstance({
        functions: {
          function1: {},
          function2: {}
        }
      });

      instance.addPoliciesForFunctions([111111111111, 222222222222]);

      expect(instance)
        .to.have.deep.property('serverless.service.resources.Resources')
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

    it('should allow access for principals that are defined locally', function() {
      const instance = createTestInstance({
        functions: {
          function1: {},
          function2: {
            allowAccess: [111111111111, 222222222222]
          }
        }
      });

      instance.addPoliciesForFunctions([]);

      expect(instance)
        .to.have.deep.property('serverless.service.resources.Resources')
        .that.deep.equals({
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
            }
          }
        });
    });

    it('should not allow access to function when allowAccess is set to false locally', function() {
      const instance = createTestInstance({
        functions: {
          function1: {
            allowAccess: false
          },
          function2: {}
        }
      });

      instance.addPoliciesForFunctions([111111111111, 222222222222]);

      expect(instance)
        .to.have.deep.property('serverless.service.resources.Resources')
        .that.deep.equals({
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
            }
          }
        });
    });

    it('local allowAccess should override global allowAccess', function() {
      const instance = createTestInstance({
        functions: {
          function1: {
            allowAccess: [333333333333, 444444444444]
          },
          function2: {}
        }
      });

      instance.addPoliciesForFunctions([111111111111, 222222222222]);

      expect(instance)
        .to.have.deep.property('serverless.service.resources.Resources')
        .that.deep.equals({
          'Function1LambdaFunctionPermitInvokeFrom333333333333': {
            'Type': 'AWS::Lambda::Permission',
            'Properties': {
              'Action': 'lambda:InvokeFunction',
              'FunctionName': {
                'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
              },
              'Principal': '333333333333'
            }
          },
          'Function1LambdaFunctionPermitInvokeFrom444444444444': {
            'Type': 'AWS::Lambda::Permission',
            'Properties': {
              'Action': 'lambda:InvokeFunction',
              'FunctionName': {
                'Fn::GetAtt': [ 'Function1LambdaFunction', 'Arn' ],
              },
              'Principal': '444444444444'
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
        functions: {
          function1: {}
        }
      });

      instance.addPoliciesForFunctions(['arn:aws:iam::111111111111:root']);

      expect(instance)
        .to.have.deep.property('serverless.service.resources.Resources')
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

    it('should support local allowAccess to be a single value', function() {
      const instance = createTestInstance({
        functions: {
          function1: {},
          function2: {
            allowAccess: 222222222222
          }
        }
      });

      instance.addPoliciesForFunctions([111111111111]);

      expect(instance)
        .to.have.deep.property('serverless.service.resources.Resources')
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
  });
});
