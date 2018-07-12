const kp = require('./distrib/npm/index.js')
const RippleAPI = require('ripple-lib').RippleAPI
const binary = require('ripple-binary-codec')

const api = new RippleAPI({
  server: 'wss://s.altnet.rippletest.net'
});

async function preparePayment(account, destination, amount) {
  return await api.preparePayment(account, {
    "source": {
      "address": account,
      "amount": {
        "value": amount,
        "currency": "XRP"
      }
    },
    "destination": {
      "address": destination,
      "minAmount": {
        "value": amount,
        "currency": "XRP"
      }
    }
  })
}

async function doMusig (account, secret, n) {
  try {
    await api.connect()

    let privateKeys = []
    let publicKeys = []

    for (let i=0; i<n; i++) {
      const seed = kp.generateSeed({algorithm: 'ed25519'})
      const keypair = kp.deriveKeypair(seed)
      privateKeys.push(keypair.privateKey)
      publicKeys.push(keypair.publicKey)
    }

    const L = kp.musig.getL(publicKeys)
    const X = kp.musig.getAggregatePublicKey(L, publicKeys)

    // Fund multisign address
    const musigAddress = kp.deriveAddress(X)

    console.log(musigAddress)
    console.log(X)

    const fundingTx = await preparePayment(account, musigAddress, "25")
    const {signedTransaction} = api.sign(fundingTx.txJSON, secret)
    console.log(await api.submit(signedTransaction))

    let privateEphemerals = []
    let publicEphemerals = []

    for (let i=0; i<n; i++) {
      const seed = kp.generateSeed({algorithm: 'ed25519'})
      const keypair = kp.deriveKeypair(seed)
      privateEphemerals.push(keypair.privateKey)
      publicEphemerals.push(keypair.publicKey)
    }

    const R = kp.musig.getR(publicEphemerals)
    const tx = await preparePayment(musigAddress, account, "1")
    const txJSON = JSON.parse(tx.txJSON)
    txJSON.SigningPubKey = X
    const signingData = binary.encodeForSigning(txJSON)
    let sigs = []

    for (let i=0; i<n; i++) {
      sigs.push(kp.musig.sign(signingData, privateKeys[i], privateEphemerals[i], X, L, R))
    }

    txJSON.TxnSignature = kp.musig.combine(sigs, R)

    console.log(txJSON)
    console.log(await api.submit(binary.encode(txJSON)))
  } catch (err) {
    console.log(err)
  }
}

doMusig(
  'rDd6FpNbeY2CrQajSmP178BmNGusmQiYMM',
  'snyfcPrgMHCDR57M6Wrps8y6RPhiF',
  7)
