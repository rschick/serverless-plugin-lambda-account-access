# serverless-plugin-lambda-account-access

Add policies to allow cross-account access to your functions.

## Usage Example

`serverless.yml`

```yaml
service: sample

plugins:
  - serverless-plugin-lambda-account-access

provider:
  permitAccounts: 000001,000002 # CSV list of AWS account numbers

functions:
  function1:
  function2:
```

The above allows all functions to be invoked from the listed accounts.

Permissions are granted by adding resources of the form:

```yaml
resources:
  Resources:
    Function1LambdaFunctionPermitInvokeFromAccount000001:
	  Type: AWS::Lambda::Permission
      Properties:
        Action: lambda:InvokeFunction
        FunctionName:
          Fn::GetAtt:
            - Function1LambdaFunction
            - Arn
	    Principal: 000001
```
