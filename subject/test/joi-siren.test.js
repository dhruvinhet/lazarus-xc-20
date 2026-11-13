const Joi = require('joi');
const expect = require('chai').expect;
const schemaToFields = require('../joi-siren');

describe('joi-siren', function () {

  it('converts a single text field', async () => {
    const schema = {
      single: Joi.string(),
    };

    const fields = schemaToFields(schema);
    expect(fields).to.be.an('array');
    expect(fields).to.have.length(1);
    expect(fields[0]).to.deep.equal({ name: 'single', type: 'text' });
  });

  it('converts numbers', async () => {
    const schema = {
      number: Joi.number(),
      integer: Joi.number().integer(),
      float: Joi.number().precision(2),
    };

    const fields = schemaToFields(schema);
    expect(fields).to.be.an('array');
    expect(fields).to.have.length(3);
    expect(fields[0]).to.deep.equal({ name: 'number', type: 'number' });
    expect(fields[1]).to.deep.equal({ name: 'integer', type: 'number' });
    expect(fields[2]).to.deep.equal({ name: 'float', type: 'number' });
  });

  it('converts booleans', async () => {
    const schema = {
      bool: Joi.boolean(),
    };

    const fields = schemaToFields(schema);
    expect(fields).to.be.an('array');
    expect(fields).to.have.length(1);
    expect(fields[0]).to.deep.equal({ name: 'bool', type: 'checkbox' });
  });

  it('converts multiple fields', async () => {
    const schema = {
      single: Joi.string(),
      double: Joi.string(),
    };

    const fields = schemaToFields(schema);
    expect(fields).to.be.an('array');
    expect(fields).to.have.length(2);
    expect(fields[0]).to.deep.equal({ name: 'single', type: 'text' });
    expect(fields[1]).to.deep.equal({ name: 'double', type: 'text' });
  });

  it('converts nested fields', async () => {
    const schema = {
      outer: {
        inner: Joi.string(),
      },
    };

    const fields = schemaToFields(schema);
    expect(fields).to.be.an('array');
    expect(fields).to.have.length(1);
    expect(fields[0]).to.deep.equal({ name: 'outer[inner]', type: 'text' });
  });

  it('converts nested fanout', async () => {
    const schema = {
      outer: {
        inner1: Joi.string(),
        inner2: Joi.string(),
      },
    };

    const fields = schemaToFields(schema);
    expect(fields).to.be.an('array');
    expect(fields).to.have.length(2);
    expect(fields[0]).to.deep.equal({ name: 'outer[inner1]', type: 'text' });
    expect(fields[1]).to.deep.equal({ name: 'outer[inner2]', type: 'text' });
  });

  it('converts varying levels of nesting', async () => {
    const schema = {
      outer: {
        inner: Joi.string(),
        layer2_1: {
          layer3: {
            mostInner: Joi.number(),
          },
        },
        layer2_2: {
          reallyInner: Joi.boolean(),
        },
      },
    };

    const fields = schemaToFields(schema);
    expect(fields).to.be.an('array');
    expect(fields).to.have.length(3);
    expect(fields[0]).to.deep.equal({ name: 'outer[inner]', type: 'text' });
    expect(fields[1]).to.deep.equal({ name: 'outer[layer2_1][layer3][mostInner]', type: 'number' });
    expect(fields[2]).to.deep.equal({ name: 'outer[layer2_2][reallyInner]', type: 'checkbox' });
  });

  it('converts a single field with description', async () => {
    const schema = {
      singleDesc: Joi.string().description('simple description'),
    };

    const fields = schemaToFields(schema);
    expect(fields).to.be.an('array');
    expect(fields).to.have.length(1);
    expect(fields[0]).to.deep.equal({ name: 'singleDesc', type: 'text', title: 'simple description' });
  });

  it('converts a field with an exact value', async () => {
    const schema = {
      outer: {
        inner: 'this is the only value',
      },
    };

    const fields = schemaToFields(schema);
    expect(fields).to.be.an('array');
    expect(fields).to.have.length(1);
    expect(fields[0]).to.deep.equal({ name: 'outer[inner]', type: 'text', value: 'this is the only value' });
  });

  it('errors if root of schema is not an object', async () => {
    const schema = Joi.string();

    expect(() => schemaToFields(schema)).to.throw('Root element must be an object');
  });
});
