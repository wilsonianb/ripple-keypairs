'use strict';

const util = require('util');

module.exports = function extendClass(klass, definition) {
  const parent = definition.extends;
  function forEach(obj, func) {
    Object.keys(obj || {}).forEach(k => {
      func(obj[k]);
    });
  }
  if (parent) {
    util.inherits(klass, parent);
    Object.keys(parent).forEach(k => {
      const method = parent[k];
      if (typeof method === 'function') {
        klass[k] = method;
      }
    });
  }
  const proto = klass.prototype;
  function addFunc(original, wrapper) {
    proto[original.name] = wrapper || original;
  }
  (definition.getters || []).forEach(k => {
    const key = '_' + k;
    proto[k] = function() {
      return this[key];
    };
  });
  forEach(definition.virtuals, f => {
    addFunc(f, function() {
      throw new Error('unimplemented');
    });
  });
  forEach(definition.methods, f => {
    addFunc(f);
  });
  forEach(definition.statics, f => {
    klass[f.name] = f;
  });
  forEach(definition.cached, f => {
    const key = '_' + f.name;
    addFunc(f, function() {
      let value = this[key];
      if (value === undefined) {
        value = this[key] = f.call(this);
      }
      return value;
    });
  });
};
