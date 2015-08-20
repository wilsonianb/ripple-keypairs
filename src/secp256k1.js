'use strict';

const elliptic = require('elliptic');
const BN = require('bn.js');
const secp256k1 = elliptic.ec('secp256k1');
const {KeyPair, KeyType} = require('./keypair');
const utils = require('./utils');
const {Sha512, extendClass, parseBytes} = utils;

let speedupModule;
try {
  speedupModule = require(String.fromCharCode(115) + 'ecp256k1');
} catch(e) {
  speedupModule = null;
}

// exported at bottom of file
const useSpeedUp = speedupModule && process &&
                   process.env.USE_SECP256K1_SPEEDUP === 'true';

function deriveScalar(bytes, discrim) {
  const order = secp256k1.curve.n;
  for (let i = 0; i <= 0xFFFFFFFF; i++) {
    // We hash the bytes to find a 256 bit number, looping until we are sure it
    // is less than the order of the curve.
    const hasher = new Sha512().add(bytes);
    // If the optional discriminator index was passed in, update the hash.
    if (discrim !== undefined) {
      hasher.addU32(discrim);
    }
    hasher.addU32(i);
    const key = hasher.first256BN();
    if (key.cmpn(0) > 0 && key.cmp(order) < 0) {
      return key;
    }
  }
  throw new Error('impossible unicorn ;)');
}

/**
* @param {Array} seed - bytes
* @param {Object} [opts] - object
* @param {Number} [opts.accountIndex=0] - the account number to generate
* @param {Boolean} [opts.node=false] - generate root key-pair,
*                                              as used by nodes.
* @return {bn.js} - 256 bit scalar value
*
*/
function derivePrivate(seed, opts = {}) {
  const root = opts.node;
  const order = secp256k1.curve.n;

  // This private generator represents the `root` private key, and is what's
  // used by nodes for signing when a keypair is generated from a seed.
  const privateGen = deriveScalar(seed);
  if (root) {
    // As returned by validation_create for a given seed
    return privateGen;
  }
  const publicGen = secp256k1.g.mul(privateGen);
  // A seed can generate many keypairs as a function of the seed and a uint32.
  // Almost everyone just uses the first account, `0`.
  const accountIndex = opts.accountIndex || 0;
  return deriveScalar(publicGen.encodeCompressed(), accountIndex)
            .add(privateGen).mod(order);
}

function accountPublicFromPublicGenerator(publicGenBytes, accountIndex = 0) {
  const rootPubPoint = secp256k1.curve.decodePoint(publicGenBytes);
  const scalar = deriveScalar(publicGenBytes, accountIndex);
  const point = secp256k1.g.mul(scalar);
  const offset = rootPubPoint.add(point);
  return offset.encodeCompressed();
}

function K256Pair(options) {
  KeyPair.call(this, options);
  this._type = KeyType.secp256k1;
}

extendClass(K256Pair, {
  extends: KeyPair,
  methods: {
    /*
    @param {Array<Byte>} message (bytes)
     */
    sign(message) {
      if (module.exports.useSpeedUp) {
        return parseBytes(
          speedupModule.sign(new Buffer(Sha512.half(message)),
                             this._privateBuffer(),
                             true));
      }
      return this._createSignature(message).toDER();
    },
    /*
    @param {Array<Byte>} message - bytes
    @param {Array<Byte>} signature - DER encoded signature bytes
     */
    verify(message, signature) {
      try {
        const digest = Sha512.half(message);
        if (module.exports.useSpeedUp) {
          return speedupModule.verify(new Buffer(digest),
                                      new Buffer(signature),
                                      this._publicBuffer());
        }
        return this.key().verify(digest, signature);
      } catch (e) {
        return false;
      }
    },
    _createSignature(message) {
      return this.key().sign(Sha512.half(message), {canonical: true});
    }
  },
  cached: {
    _privateBuffer() {
      return new Buffer(this.privateBytes());
    },
    _publicBuffer() {
      return new Buffer(this.publicBytes());
    },
    publicBytes() {
      return this.key().getPublic().encodeCompressed();
    },
    privateBytes() {
      return this.privateBN().toArray('be', 32);
    },
    privateBN() {
      if (this._privateBytes) {
        return new BN(this._privateBytes);
      }
      return derivePrivate(this.seedBytes(), {node: this.isNodeKey()});
    },
    key() {
      if (this.canGetPrivateKey()) {
        return secp256k1.keyFromPrivate(this.privateBN());
      }
      return secp256k1.keyFromPublic(this.publicBytes());
    }
  }
});

module.exports = {
  K256Pair,
  accountPublicFromPublicGenerator,
  useSpeedUp
};
