'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');

const validate = require('../src/validation');
const buildServerless = require('./serverless');

describe('validation', function() {
  it('should validate', function() {
    const serverless = buildServerless();
    const stubFunctionProperties = sinon.stub(serverless.configSchemaHandler, 'defineFunctionProperties');
    const stubProvider = sinon.stub(serverless.configSchemaHandler, 'defineProvider');

    validate(serverless);

    expect(stubFunctionProperties.callCount).to.equal(1);
    expect(stubProvider.callCount).to.equal(1);
  });

  it('should be backwards compatible', function() {
    const serverless = buildServerless({
      includeValidation: false,
    });

    expect(() => validate(serverless)).to.not.throw();
  });
});
