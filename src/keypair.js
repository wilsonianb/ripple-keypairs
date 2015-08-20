'use strict';

const assert = require('assert');
const addresses = require('ripple-address-codec');
const {
  bytesToHex,
  extendClass,
  computePublicKeyHash,
  parseBytes,
  parseSeed,
  parsePublicKey,
  seedFromPhrase
} = require('./utils');

const KeyType = {
  secp256k1: 'secp256k1',
  ed25519: 'ed25519'
};

function checkLength(val, expected) {
  assert(val === undefined || val.length === expected);
}

function KeyPair({seedBytes, publicBytes, privateBytes, node}) {
  checkLength(seedBytes, 16);
  checkLength(privateBytes, 32);
  checkLength(publicBytes, 33);

  this._seedBytes = seedBytes;
  this._publicBytes = publicBytes;
  this._privateBytes = privateBytes;
  this._isNodeKey = Boolean(node);
}

extendClass(KeyPair, {
  getters: ['isNodeKey', 'type', 'seedBytes'],
  virtuals: {
    sign() {},
    /*
    * @param {Array<Byte>} message
    * @param {Array<Byte>} signature
    */
    verify() {},
    /*
    * @return {Array<Byte>} of bytes, in canonical form, for signing
    */
    publicBytes() {},
    /*
    * @return {Array<Byte>} of bytes, in canonical form, with leading key type
    *                       discriminator bytes
    */
    privateBytes() {}
  },
  statics: {
    fromPhrase(phrase, opts) {
      return this.fromSeed(seedFromPhrase(phrase), opts);
    },
    fromSeed(seed, opts = {}) {
      const {bytes} = parseSeed(seed);
      return new this({seedBytes: bytes, node: opts.node});
    },
    fromPrivate(privateKey) {
      return new this({privateBytes: parseBytes(privateKey)});
    },
    /**
    * @param {String|Array} publicKey - public key in canonical form
    *                                   (0xED + 32 bytes)
    * @return {Ed25519Pair} key pair
    */
    fromPublic(publicKey) {
      return new this({publicBytes: parsePublicKey(publicKey)});
    }
  },
  cached: {
    publicHex() {
      return bytesToHex(this.publicBytes());
    },
    privateHex() {
      return bytesToHex(this.privateBytes());
    },
    idBytes() {
      return computePublicKeyHash(this.publicBytes());
    },
    id() {
      const bytes = this.idBytes();
      return this.isNodeKey() ? bytesToHex(bytes) :
                                addresses.encodeAccountID(bytes);
    },
    seed() {
      // seed entropy used to create the pair, if specified
      return addresses.encodeSeed(this._seedBytes, this.type());
    }
  },
  methods: {
    canGetPrivateKey() {
      return this._privateBytes || this._seedBytes;
    },
    signHex(message) {
      return bytesToHex(this.sign(message));
    },
    toJSON() {
      const json = {
        id: this.id(),
        publicKey: this.isNodeKey() ?
                      addresses.encodeNodePublic(this.publicBytes()) :
                        this.publicHex()
      };
      const hasSeed = this._seedBytes;
      // const hasPrivate = this._privateBytes || hasSeed;
      if (hasSeed) {
        json.seed = this.seed();
      }
      // if (hasPrivate) {
      //   json.privateKey = this.privateHex();
      // }
      return json;
    }
  }
});

module.exports = {
  KeyPair,
  KeyType
};
