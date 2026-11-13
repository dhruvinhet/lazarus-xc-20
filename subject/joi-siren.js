const Joi = require('joi');

const HTML5_TYPE_MAP = {
  boolean: 'checkbox',
  number: 'number',
  string: 'text',
};

module.exports = function (schema) {
  const description = Joi.describe(schema);
  if (description.type !== 'object') {
    throw new Error('Root element must be an object');
  }

  return parseElementChildren(description.children, '');
}

function parseElementChildren(children, fieldName) {
  const fields = [];
  for (const childElementName in children) {
    const childElement = children[childElementName];
    fields.push(...parseFields(childElement, childElementName, fieldName));
  }
  return fields;
}

function parseFields(element, elementName, fieldName) {
  const { type, children, description, valids } = element;
  fieldName = fieldName ? `${fieldName}[${elementName}]` : elementName;

  if (type === 'object') {
    return parseElementChildren(children, fieldName);
  }

  if (Object.keys(HTML5_TYPE_MAP).includes(type)) {
    const field = {
      name: fieldName,
      type: HTML5_TYPE_MAP[type],
    };

    if (description) {
      field.title = description;
    }

    if (valids && valids.length === 1) {
      const value = valids.pop();
      field.value = value;
    }

    return [field];
  }
}
