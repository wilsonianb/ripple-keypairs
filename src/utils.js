'use strict';

const hashjs = require('hash.js');
const {decodeSeed, decodeNodePublic} = require('ripple-address-codec');
const {utils: {toArray}} = require('elliptic');
const Sha512 = require('./sha512');
const extendClass = require('./extendclass');

function parseBytes(value) {
  return Array.isArray(value) ? value : toArray(value, 'hex');
}

function bytesToHex(a) {
  return parseBytes(a).map(function(byteValue) {
    const hex = byteValue.toString(16).toUpperCase();
    return hex.length > 1 ? hex : '0' + hex;
  }).join('');
}

function computePublicKeyHash(publicBytes) {
  const hash256 = hashjs.sha256().update(publicBytes).digest();
  const hash160 = hashjs.ripemd160().update(hash256).digest();
  return hash160;
}

function seedFromPhrase(phrase) {
  return hashjs.sha512().update(phrase).digest().slice(0, 16);
}

function parseSeed(seed, type = 'secp256k1') {
  if (typeof seed !== 'string') {
    return {bytes: parseBytes(seed), type};
  }
  return decodeSeed(seed);
}

function parsePublicKey(publicKey) {
  if (typeof publicKey === 'string' && publicKey[0] === 'n') {
    return decodeNodePublic(publicKey);
  }
  return parseBytes(publicKey);
}

function parseKey(key) {
  const bytes = parsePublicKey(key); // will handle node base58 or parse hex
  return {
    type: bytes.length === 33 && bytes[0] === 0xED ? 'ed25519' : 'secp256k1',
    bytes
  };
}

module.exports = {
  bytesToHex,
  computePublicKeyHash,
  extendClass,
  seedFromPhrase,
  Sha512,
  parseBytes,
  parsePublicKey,
  parseSeed,
  parseKey
};
