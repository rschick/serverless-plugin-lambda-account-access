[![CircleCI](https://circleci.com/gh/rschick/serverless-plugin-lambda-account-access/tree/master.svg?style=svg)](https://circleci.com/gh/rschick/serverless-plugin-lambda-account-access/tree/master)

# serverless-plugin-lambda-account-access

Add policies and/or roles to allow cross-account access to your functions.

## Usage Example

`serverless.yml`

```yaml
service: sample

plugins:
  - serverless-plugin-lambda-account-access

provider:
  access:
    groups:
      api: # group has both role and policy access configured
        role:
          - name: sample-${self:custom.stage}-lambda-api-${self:custom.region}
            principals: # can be defined as a single value or an array
              - 222222222222 # principal as accountId
              - 'arn:aws:iam::333333333333:root' # principal as ARN
              - Fn::Import: cloudformation-output-arn-2 # principal as CloudFormation Output Value ARN
            allowTagSession: True # can optionally be defined to include sts:TagSession in assume role policy
            maxSessionDuration: 3600 # can optionally be defined to control max duration of an assume role session
        policy:
          principals:
            - 111111111111
            - 'arn:aws:iam::222222222222:root'
            - Fn::Import: cloudformation-output-arn
      other:
        policy:
          principals: 333333333333

functions:
  function1: # access is not allowed
  function2:
    allowAccess: api # allow access for principals specified in api group only
  function3:
    allowAccess: # allow access for principals specified in both api and other
      - api
      - other
```
