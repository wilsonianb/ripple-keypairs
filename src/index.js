'use strict';

const assert = require('assert');
const brorand = require('brorand');
const {decodeSeed, encodeAccountID} = require('ripple-address-codec');

const {KeyType} = require('./keypair');
const {Ed25519Pair} = require('./ed25519');
const {K256Pair, accountPublicFromPublicGenerator} = require('./secp256k1');
const {seedFromPhrase,
       parsePublicKey,
       computePublicKeyHash,
       parseKey} = require('./utils');

function pairConstructor(type) {
  return type === KeyType.ed25519 ? Ed25519Pair : K256Pair;
}

function keyPairFromSeed(seed, type = KeyType.secp256k1, options) {
  if (typeof seed === 'string') {
    const decoded = decodeSeed(seed);
    const optionsArg = type;
    return keyPairFromSeed(decoded.bytes, decoded.type, optionsArg);
  }
  assert(type === KeyType.secp256k1 || type === KeyType.ed25519);
  return pairConstructor(type).fromSeed(seed, options);
}

function keyFromPublic(publicKey) {
  const key = parseKey(publicKey);
  return pairConstructor(key.type).fromPublic(key.bytes);
}

function deriveAccountKeys(seed, type) {
  return keyPairFromSeed(seed, type).toJSON();
}

function generateAccountKeys(opts = {}) {
  const seedBytes = opts.entropy || brorand(16);
  return deriveAccountKeys(seedBytes, opts.type);
}

function accountKeysFromSeed(seed, seedType) {
  return deriveAccountKeys(seed, seedType);
}

function accountKeysFromPhrase(phrase, seedType) {
  return deriveAccountKeys(seedFromPhrase(phrase), seedType);
}

function deriveNodeKeys(seed) {
  return K256Pair.fromSeed(seed, {node: true}).toJSON();
}

function generateNodeKeys(opts = {}) {
  return deriveNodeKeys(opts.entropy || brorand(16));
}

function nodeKeysFromSeed(seed) {
  return deriveNodeKeys(seed);
}

function nodeKeysFromPhrase(phrase) {
  return deriveNodeKeys(seedFromPhrase(phrase));
}

function deriveNodeOwnerAccountID(publicKey) {
  const generatorBytes = parsePublicKey(publicKey);
  const accountPublicBytes = accountPublicFromPublicGenerator(generatorBytes);
  return encodeAccountID(computePublicKeyHash(accountPublicBytes));
}

module.exports = {
  accountKeysFromPhrase,
  accountKeysFromSeed,
  computePublicKeyHash,
  deriveNodeOwnerAccountID,
  generateAccountKeys,
  generateNodeKeys,
  keyFromPublic,
  keyPairFromSeed,
  nodeKeysFromPhrase,
  nodeKeysFromSeed,
  parsePublicKey,
  seedFromPhrase
};
