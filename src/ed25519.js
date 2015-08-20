'use strict';

const elliptic = require('elliptic');
const Ed25519 = elliptic.eddsa('ed25519');
const {KeyPair, KeyType} = require('./keypair');
const {Sha512, extendClass} = require('./utils');

/*
@param {Array} seed bytes
 */
function deriveEdKeyPairPrivate(seed) {
  return new Sha512().add(seed).first256();
}

function Ed25519Pair(options) {
  KeyPair.call(this, options);
  this._type = KeyType.ed25519;
}

extendClass(Ed25519Pair, {
  extends: KeyPair,
  methods: {
    sign(message) {
      return this.key().sign(message).toBytes();
    },
    verify(message, signature) {
      return this.key().verify(message, signature);
    }
  },
  cached: {
    publicBytes() {
      return [0xED].concat(this.key().pubBytes());
    },
    privateBytes() {
      return deriveEdKeyPairPrivate(this.seedBytes());
    },
    key() {
      if (this.canGetPrivateKey()) {
        return Ed25519.keyFromSecret(this.privateBytes());
      }
      return Ed25519.keyFromPublic(this.publicBytes().slice(1));
    }
  }
});

module.exports = {
  Ed25519Pair
};
