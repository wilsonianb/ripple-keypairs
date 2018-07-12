const elliptic = require('elliptic')
const Ed25519 = elliptic.eddsa('ed25519')

function getL(publicKeys) {
  // Call L = H(X1,X2,…)
  let Xs = []

  for (let publicKey of publicKeys) {
    Xs.push(Ed25519.keyFromPublic(publicKey).pub())
  }

// TODO sort keys

  return Ed25519.hashInt.apply(Ed25519, Xs)
}

function getAggregatePublicKey(L, publicKeys) {
  // Call X the sum of all H(L,Xi)Xis
  const X0 = Ed25519.keyFromPublic(publicKeys[0])
  let X = X0.pub().mul(Ed25519.hashInt(L, X0.pubBytes()))

  for (let i=1; i<publicKeys.length; i++) {
    const Xi = Ed25519.keyFromPublic(publicKeys[i])
    X = X.add(Xi.pub().mul(Ed25519.hashInt(L, Xi.pubBytes())))
  }

  return Ed25519.encodePoint(X)
}

function getR(Rs) {
  // Call R the sum of the Ri points
  const R0 = Ed25519.keyFromPublic(Rs[0])
  let R = R0.pub()

  for (let i=1; i<Rs.length; i++) {
    const Ri = Ed25519.keyFromPublic(Rs[i])
    R = R.add(Ri.pub())
  }

  return Ed25519.encodePoint(R)
}

function sign(m, secret, rSecret, pub, L, Rbytes) {
  // Each signer computes si = ri + H(X,R,m)H(L,Xi)xi
  const message = elliptic.utils.parseBytes(m);
  const key = Ed25519.keyFromSecret(secret)
  const rKey = Ed25519.keyFromSecret(rSecret)
  const X = Ed25519.keyFromPublic(pub)
  const R = Ed25519.keyFromPublic(Rbytes)
  const s_ = Ed25519.hashInt(R.pubBytes(), X.pubBytes(), message)
               .mul(Ed25519.hashInt(L, key.pubBytes()))
               .mul(key.priv())
  const si = rKey.priv().add(s_).umod(Ed25519.curve.n)
  return Ed25519.makeSignature({ R: R.pub(), S: si, Rencoded: R.pubBytes() })
}

function combine(sigs, Rbytes) {
  let S = Ed25519.makeSignature(sigs[0]).S()

  for (let i=1; i<sigs.length; i++) {
    S = S.add(Ed25519.makeSignature(sigs[i]).S()).umod(Ed25519.curve.n)
  }

  const R = Ed25519.keyFromPublic(Rbytes)

  return Ed25519.makeSignature({ R: R.pub(), S: S, Rencoded: R.pubBytes() })
}

module.exports = {
  getL,
  getAggregatePublicKey,
  getR,
  sign,
  combine
}
