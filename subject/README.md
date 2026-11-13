# joi-siren
Converts [Joi](https://github.com/hapijs/joi) schema into a [Siren action fields](https://github.com/kevinswiber/siren#fields).

## Install
```
npm install joi-siren
```

## Rules
- The root of the schema must be an object
- Supports these Joi types: Boolean, Number, Object and String

## Examples

For an exhaustive list of examples see the [tests](https://github.com/BinSentry/joi-siren/blob/master/test/joi-siren.test.js)

```
const Joi = require('joi');
const schemaToFields = require('joi-siren');

```

#### Simple
```
const schema = {
  single: Joi.string(),
};

const fields = schemaToFields(schema);
// [ { name: 'single', type: 'text' } ]

```

#### Nested with multiple types
```
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
//  [
//    { name: 'outer[inner]', type: 'text' },
//    { name: 'outer[layer2_1][layer3][mostInner]', type: 'number' },
//    { name: 'outer[layer2_2][reallyInner]', type: 'checkbox' }
//  ]
```

#### Exact values

```
const schema = {
  outer: {
    inner: 'this is the only value',
  },
};

const fields = schemaToFields(schema);
//  [ { name: 'outer[inner]', type: 'text', value: 'this is the only value' } ]
```
