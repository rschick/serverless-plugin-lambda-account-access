[![CircleCI](https://circleci.com/gh/rschick/serverless-plugin-lambda-account-access/tree/master.svg?style=svg)](https://circleci.com/gh/rschick/serverless-plugin-lambda-account-access/tree/master)

# serverless-plugin-lambda-account-access

Add policies to allow cross-account access to your functions.

## Usage Example

`serverless.yml`

```yaml
service: sample

plugins:
  - serverless-plugin-lambda-account-access

provider:
  allowAccess: # can be defined as a single value or an array
    - 111111111111 # principal as accountId
    - 'arn:aws:iam::222222222222:root' # principal as ARN
    - Fn::Import: cloudformation-output-arn # principal as CloudFormation Output Value ARN

functions:
  function1:
  function2:
    allowAccess: false # excludes specific function
  function3:
    allowAccess: 333333333333 # allows access from these principals instead of the globally defined ones
```

The above allows all functions to be invoked from the principals listed in `provider` section, unless access is explicitly forbidden inside function config (`function2`), or accounts list is overridden locally (`function3`).

Permissions are granted by adding resources of the form:

```yaml
resources:
  Resources:
    Function1LambdaFunctionPermitInvokeFrom111111111111:
    Type: AWS::Lambda::Permission
      Properties:
        Action: lambda:InvokeFunction
        FunctionName:
          Fn::GetAtt:
            - Function1LambdaFunction
            - Arn
      Principal: '111111111111'
```

## Migration From 1.x

Version 2 has the following breaking changes:
  - `permitAccounts` field was changed to `allowAccess`
  - multiple principals can be defined as an array, instead of CSV list
