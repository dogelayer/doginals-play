const dogecore = require('bitcore-lib-doge')
const axios = require('axios')
const fs = require('fs')
const dotenv = require('dotenv')
const mime = require('mime-types')
const express = require('express')
const { PrivateKey, Address, Transaction, Script, Opcode } = dogecore
const { Hash, Signature } = dogecore.crypto
const protobuf = require('protobufjs')
const Long = require('long')

const API_URL = 'https://dogetest-explorer.dogelayer.org/api/v2/'
const MAX_SCRIPT_ELEMENT_SIZE = 520
const DRC20_P = 1

const DRC20_OP_MAP = {
  deploy: 1,
  mint: 2,
  transfer: 3
}

dotenv.config()

if (process.env.FEE_PER_KB) {
  Transaction.FEE_PER_KB = parseInt(process.env.FEE_PER_KB)
} else {
  Transaction.FEE_PER_KB = 100000000
}

const WALLET_PATH = process.env.WALLET || '.wallet.json'

const CONTENT_TYPE = 'application/x-protobuf'
// const CONTENT_TYPE = "text/plain;charset=utf-8"

// var proto_type_drc
var proto_type_drc20

function buffer2hex (buffer) {
  // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('')
}

async function main () {
  var root = await protobuf.load('drc.proto')

  // proto_type_drc = root.lookupType('drc.drc')
  proto_type_drc20 = root.lookupType('drc.drc20')

  if (process.env.TESTNET == 'true') {
    dogecore.Networks.defaultNetwork = dogecore.Networks.testnet
  } else {
    throw new Error('Only support testnet.')
  }

  let cmd = process.argv[2]

  if (fs.existsSync('pending-txs.json')) {
    console.log('found pending-txs.json. rebroadcasting...')
    const txs = JSON.parse(fs.readFileSync('pending-txs.json'))
    await broadcastAll(
      txs.map(tx => new Transaction(tx)),
      false
    )
    return
  }

  if (cmd == 'mint') {
    await mint()
  } else if (cmd == 'wallet') {
    await wallet()
  } else if (cmd == 'server') {
    await server()
  } else if (cmd == 'drc-20') {
    await doge20()
  } else {
    throw new Error(`unknown command: ${cmd}`)
  }
}

async function doge20 () {
  let subcmd = process.argv[3]

  if (subcmd === 'mint') {
    await doge20Transfer('mint')
  } else if (subcmd === 'transfer') {
    await doge20Transfer()
  } else if (subcmd === 'deploy') {
    await doge20Deploy()
  } else {
    throw new Error(`unknown subcommand: ${subcmd}`)
  }
}

async function doge20Deploy () {
  const argAddress = process.argv[4]
  const argTicker = process.argv[5]
  const argMax = process.argv[6]
  const argLimit = process.argv[7]

  // const doge20Tx = {
  //   p: 'drc-20',
  //   op: 'deploy',
  //   tick: `${argTicker.toLowerCase()}`,
  //   max: `${argMax}`,
  //   lim: `${argLimit}`
  // }

  // const parsedDoge20Tx = JSON.stringify(doge20Tx)

  // // encode the doge20Tx as hex string
  // const encodedDoge20Tx = Buffer.from(parsedDoge20Tx).toString('hex')
  const op = 'deploy'
  const doge20Tx = proto_type_drc20.create({
    p: DRC20_P,
    op: DRC20_OP_MAP[op],
    tick: `${argTicker.toLowerCase()}`,
    max: Long.fromString(argMax, true),
    lim: Long.fromString(argLimit, true)
  })
  const encodedDoge20Tx = proto_type_drc20.encode(doge20Tx).finish()

  console.log('Deploying drc-20 token...')
  await mint(argAddress, CONTENT_TYPE, buffer2hex(encodedDoge20Tx))
}

async function doge20Transfer (op = 'transfer') {
  const argAddress = process.argv[4]
  const argTicker = process.argv[5]
  const argAmount = process.argv[6]
  const argRepeat = Number(process.argv[7]) || 1

  // const doge20Tx = {
  //   p: 'drc-20',
  //   op,
  //   tick: `${argTicker.toLowerCase()}`,
  //   amt: `${argAmount}`
  // }

  // const parsedDoge20Tx = JSON.stringify(doge20Tx)

  // // encode the doge20Tx as hex string
  // const encodedDoge20Tx = Buffer.from(parsedDoge20Tx).toString('hex')

  const doge20Tx = proto_type_drc20.create({
    p: DRC20_P,
    op: DRC20_OP_MAP[op],
    tick: `${argTicker.toLowerCase()}`,
    amt: Long.fromString(argAmount, true)
  })
  const encodedDoge20Tx = proto_type_drc20.encode(doge20Tx).finish()

  for (let i = 0; i < argRepeat; i++) {
    console.log('Minting drc-20 token...', i + 1, 'of', argRepeat, 'times')
    await mint(argAddress, CONTENT_TYPE, buffer2hex(encodedDoge20Tx))
  }
}

async function wallet () {
  let subcmd = process.argv[3]

  if (subcmd == 'new') {
    walletNew()
  } else if (subcmd == 'sync') {
    await walletSync()
  } else if (subcmd == 'balance') {
    walletBalance()
  } else if (subcmd == 'send') {
    await walletSend()
  } else if (subcmd == 'split') {
    await walletSplit()
  } else {
    throw new Error(`unknown subcommand: ${subcmd}`)
  }
}

function walletNew () {
  if (!fs.existsSync(WALLET_PATH)) {
    const privateKey = new PrivateKey()
    const privkey = privateKey.toWIF()
    const address = privateKey.toAddress().toString()
    const json = { privkey, address, utxos: [] }
    fs.writeFileSync(WALLET_PATH, JSON.stringify(json, 0, 2))
    console.log('address', address)
  } else {
    throw new Error('wallet already exists')
  }
}

async function walletSync () {
  let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))
  console.log('syncing utxos with dogelayer.org api')

  let response = await axios.get(API_URL + 'utxo/' + wallet.address)
  wallet.utxos = response.data.map(output => {
    return {
      txid: output.txid,
      vout: output.vout,
      script: Script.buildPublicKeyHashOut(wallet.address).toHex(),
      satoshis: Number(output.value)
    }
  })

  fs.writeFileSync(WALLET_PATH, JSON.stringify(wallet, 0, 2))
  let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
  console.log('balance', balance)
}

function walletBalance () {
  let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))
  let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
  console.log(wallet.address, balance)
}

async function walletSend () {
  const argAddress = process.argv[4]
  const argAmount = process.argv[5]

  let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

  let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
  if (balance == 0) throw new Error('no funds to send')

  let receiver = new Address(argAddress)
  let amount = parseInt(argAmount)

  let tx = new Transaction()
  if (amount) {
    tx.to(receiver, amount)
    fund(wallet, tx)
  } else {
    tx.from(wallet.utxos)
    tx.change(receiver)
    tx.sign(wallet.privkey)
  }

  await broadcast(tx, true)
  console.log('tx hash: ', tx.hash)
}

async function walletSplit () {
  let splits = parseInt(process.argv[4])

  let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

  let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
  if (balance == 0) throw new Error('no funds to split')

  let tx = new Transaction()
  tx.from(wallet.utxos)
  for (let i = 0; i < splits - 1; i++) {
    tx.to(wallet.address, Math.floor(balance / splits))
  }
  tx.change(wallet.address)
  tx.sign(wallet.privkey)

  await broadcast(tx, true)

  console.log(tx.hash)
}

async function mint (paramAddress, paramContentTypeOrFilename, paramHexData) {
  const argAddress = paramAddress || process.argv[3]
  const argContentTypeOrFilename = paramContentTypeOrFilename || process.argv[4]
  const argHexData = paramHexData || process.argv[5]

  let address = new Address(argAddress)
  let contentType
  let data

  if (fs.existsSync(argContentTypeOrFilename)) {
    contentType = mime.contentType(mime.lookup(argContentTypeOrFilename))
    data = fs.readFileSync(argContentTypeOrFilename)
  } else {
    contentType = argContentTypeOrFilename
    if (!/^[a-fA-F0-9]*$/.test(argHexData)) throw new Error('data must be hex')
    data = Buffer.from(argHexData, 'hex')
  }

  if (data.length == 0) {
    throw new Error('no data to mint')
  }

  if (contentType.length > MAX_SCRIPT_ELEMENT_SIZE) {
    throw new Error('content type too long')
  }

  let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

  let txs = inscribe(wallet, address, contentType, data)

  await broadcastAll(txs, false)
}

async function broadcastAll (txs, retry) {
  for (let i = 0; i < txs.length; i++) {
    console.log(`broadcasting tx ${i + 1} of ${txs.length}`)

    try {
      await broadcast(txs[i], retry)
    } catch (e) {
      console.log('broadcast failed', e?.response.data)
      if (
        e?.response?.data.error?.message?.includes('bad-txns-inputs-spent') ||
        e?.response?.data.error?.message?.includes('already in block chain')
      ) {
        console.log('tx already sent, skipping')
        continue
      }
      console.log('saving pending txs to pending-txs.json')
      console.log('to reattempt broadcast, re-run the command')
      fs.writeFileSync(
        'pending-txs.json',
        JSON.stringify(txs.slice(i).map(tx => tx.toString()))
      )
      process.exit(1)
    }
  }

  try {
    fs.unlinkSync('pending-txs.json')
  } catch (err) {
    // ignore
  }

  if (txs.length > 1) {
    console.log('inscription txid:', txs[1].hash)
  }
}

function bufferToChunk (b, type) {
  b = Buffer.from(b, type)
  return {
    buf: b.length ? b : undefined,
    len: b.length,
    opcodenum: b.length <= 75 ? b.length : b.length <= 255 ? 76 : 77
  }
}

function numberToChunk (n) {
  return {
    buf:
      n <= 16
        ? undefined
        : n < 128
        ? Buffer.from([n])
        : Buffer.from([n % 256, n / 256]),
    len: n <= 16 ? 0 : n < 128 ? 1 : 2,
    opcodenum: n == 0 ? 0 : n <= 16 ? 80 + n : n < 128 ? 1 : 2
  }
}

function opcodeToChunk (op) {
  return { opcodenum: op }
}

const MAX_CHUNK_LEN = 240
const MAX_PAYLOAD_LEN = 1500

function inscribe (wallet, address, contentType, data) {
  let txs = []

  let privateKey = new PrivateKey(wallet.privkey)
  let publicKey = privateKey.toPublicKey()

  let parts = []
  while (data.length) {
    let part = data.slice(0, Math.min(MAX_CHUNK_LEN, data.length))
    data = data.slice(part.length)
    parts.push(part)
  }

  let inscription = new Script()
  inscription.chunks.push(bufferToChunk('ord'))
  inscription.chunks.push(numberToChunk(parts.length))
  inscription.chunks.push(bufferToChunk(contentType))
  parts.forEach((part, n) => {
    inscription.chunks.push(numberToChunk(parts.length - n - 1))
    inscription.chunks.push(bufferToChunk(part))
  })

  let p2shInput
  let lastLock
  let lastPartial

  while (inscription.chunks.length) {
    let partial = new Script()

    if (txs.length == 0) {
      partial.chunks.push(inscription.chunks.shift())
    }

    while (
      partial.toBuffer().length <= MAX_PAYLOAD_LEN &&
      inscription.chunks.length
    ) {
      partial.chunks.push(inscription.chunks.shift())
      partial.chunks.push(inscription.chunks.shift())
    }

    if (partial.toBuffer().length > MAX_PAYLOAD_LEN) {
      inscription.chunks.unshift(partial.chunks.pop())
      inscription.chunks.unshift(partial.chunks.pop())
    }

    let lock = new Script()
    lock.chunks.push(bufferToChunk(publicKey.toBuffer()))
    lock.chunks.push(opcodeToChunk(Opcode.OP_CHECKSIGVERIFY))
    partial.chunks.forEach(() => {
      lock.chunks.push(opcodeToChunk(Opcode.OP_DROP))
    })
    lock.chunks.push(opcodeToChunk(Opcode.OP_TRUE))

    let lockhash = Hash.ripemd160(Hash.sha256(lock.toBuffer()))

    let p2sh = new Script()
    p2sh.chunks.push(opcodeToChunk(Opcode.OP_HASH160))
    p2sh.chunks.push(bufferToChunk(lockhash))
    p2sh.chunks.push(opcodeToChunk(Opcode.OP_EQUAL))

    let p2shOutput = new Transaction.Output({
      script: p2sh,
      satoshis: 100000
    })

    let tx = new Transaction()
    if (p2shInput) tx.addInput(p2shInput)
    tx.addOutput(p2shOutput)
    fund(wallet, tx)

    if (p2shInput) {
      let signature = Transaction.sighash.sign(
        tx,
        privateKey,
        Signature.SIGHASH_ALL,
        0,
        lastLock
      )
      let txsignature = Buffer.concat([
        signature.toBuffer(),
        Buffer.from([Signature.SIGHASH_ALL])
      ])

      let unlock = new Script()
      unlock.chunks = unlock.chunks.concat(lastPartial.chunks)
      unlock.chunks.push(bufferToChunk(txsignature))
      unlock.chunks.push(bufferToChunk(lastLock.toBuffer()))
      tx.inputs[0].setScript(unlock)
    }

    updateWallet(wallet, tx)
    txs.push(tx)

    p2shInput = new Transaction.Input({
      prevTxId: tx.hash,
      outputIndex: 0,
      output: tx.outputs[0],
      script: ''
    })

    p2shInput.clearSignatures = () => {}
    p2shInput.getSignatures = () => {}

    lastLock = lock
    lastPartial = partial
  }

  let tx = new Transaction()
  tx.addInput(p2shInput)
  tx.to(address, 100000)
  fund(wallet, tx)

  let signature = Transaction.sighash.sign(
    tx,
    privateKey,
    Signature.SIGHASH_ALL,
    0,
    lastLock
  )
  let txsignature = Buffer.concat([
    signature.toBuffer(),
    Buffer.from([Signature.SIGHASH_ALL])
  ])

  let unlock = new Script()
  unlock.chunks = unlock.chunks.concat(lastPartial.chunks)
  unlock.chunks.push(bufferToChunk(txsignature))
  unlock.chunks.push(bufferToChunk(lastLock.toBuffer()))
  tx.inputs[0].setScript(unlock)

  updateWallet(wallet, tx)
  txs.push(tx)

  return txs
}

function fund (wallet, tx) {
  tx.change(wallet.address)
  delete tx._fee

  for (const utxo of wallet.utxos) {
    // console.log("get fee:",tx.getFee())
    if (utxo.satoshis <= 1000000) {
      continue
    }
    if (
      tx.inputs.length &&
      tx.outputs.length &&
      tx.inputAmount >= tx.outputAmount + tx.getFee()
    ) {
      break
    }

    delete tx._fee
    tx.from(utxo)

    tx.change(wallet.address)
    tx.sign(wallet.privkey)
  }

  if (tx.inputAmount < tx.outputAmount + tx.getFee()) {
    throw new Error('not enough funds')
  }
}

function updateWallet (wallet, tx) {
  wallet.utxos = wallet.utxos.filter(utxo => {
    for (const input of tx.inputs) {
      if (
        input.prevTxId.toString('hex') == utxo.txid &&
        input.outputIndex == utxo.vout
      ) {
        return false
      }
    }
    return true
  })

  tx.outputs.forEach((output, vout) => {
    if (output.script.toAddress().toString() == wallet.address) {
      wallet.utxos.push({
        txid: tx.hash,
        vout,
        script: output.script.toHex(),
        satoshis: output.satoshis
      })
    }
  })
}

async function broadcast_dogelayer_api (tx) {
  try {
    const response = await axios.post(API_URL + 'sendtx/', tx.toString())
    console.log(response.data)
  } catch (e) {
    console.log(e)
    return
  }

  let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))
  updateWallet(wallet, tx)
  fs.writeFileSync(WALLET_PATH, JSON.stringify(wallet, 0, 2))
}

async function broadcast (tx, retry = 0) {
  return broadcast_dogelayer_api(tx)
}

function chunkToNumber (chunk) {
  if (chunk.opcodenum == 0) return 0
  if (chunk.opcodenum == 1) return chunk.buf[0]
  if (chunk.opcodenum == 2) return chunk.buf[1] * 255 + chunk.buf[0]
  if (chunk.opcodenum > 80 && chunk.opcodenum <= 96) return chunk.opcodenum - 80
  return undefined
}

async function getAddressTxs (address) {
  let { data } = await axios.get(
    API_URL + '/address/' + address + '?details=txs'
  )
  txs = data.transactions
  return txs
}

function findSpendTx (txs, txid, n) {
  for (tx of txs) {
    for (vin of tx.vin) {
      if (vin.txid == txid && vin.n == n) {
        return tx.txid
      }
    }
  }
  return null
}

async function extract (txid) {
  let resp = await axios.get(API_URL + 'tx/' + txid)
  let transaction = resp.data
  let script = Script.fromHex(transaction.vin[0].hex)
  let chunks = script.chunks

  let prefix = chunks.shift().buf.toString('utf-8')
  if (prefix != 'ord') {
    throw new Error('not a doginal')
  }

  let pieces = chunkToNumber(chunks.shift())

  let contentType = chunks.shift().buf.toString('utf-8')

  let data = Buffer.alloc(0)
  let remaining = pieces

  // TODO: optimise finding all tx in series
  while (remaining && chunks.length) {
    let n = chunkToNumber(chunks.shift())

    if (n !== remaining - 1) {
      const txs = await getAddressTxs(transaction.vout[0].addresses[0])
      txid = findSpendTx(txs, transaction.txid, 0)
      console.log('next tx: ', txid)
      resp = await axios.get(API_URL + 'tx/' + txid)
      transaction = resp.data
      script = Script.fromHex(transaction.vin[0].hex)
      chunks = script.chunks
      continue
    }

    data = Buffer.concat([data, chunks.shift().buf])
    remaining -= 1
  }

  return {
    contentType,
    data
  }
}

function server () {
  const app = express()
  const port = process.env.SERVER_PORT
    ? parseInt(process.env.SERVER_PORT)
    : 3000

  app.get('/tx/:txid', (req, res) => {
    extract(req.params.txid)
      .then(result => {
        res.setHeader('content-type', result.contentType)
        res.send(result.data)
      })
      .catch(e => res.send(e.message))
  })

  app.listen(port, () => {
    console.log(`Listening on port ${port}`)
    console.log()
    console.log(`Example:`)
    console.log(
      `http://localhost:${port}/tx/b201783a8e5c8f98f40b250c28f666d16db105ae663efa70132a9eddc6f2e804`
    )
  })
}

main().catch(e => {
  let reason =
    e.response &&
    e.response.data &&
    e.response.data.error &&
    e.response.data.error.message
  console.error(reason ? e.message + ':' + reason : e.message)
})
