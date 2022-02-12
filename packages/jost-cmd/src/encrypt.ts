import { convertEd25519PublicKeyToX25519 } from '@jjavery/ed25519-to-x25519'
import { program } from 'commander'
import { createPrivateKey, createPublicKey } from 'crypto'
import { createReadStream, createWriteStream } from 'fs'
import {
  CompressionOptions,
  JostWriter,
  RecipientOptions,
  SignatureOptions
} from 'jose-stream'
import { homedir } from 'os'
import { pipeline } from 'stream/promises'
import Jwks from './jwks'

const defaultIdentityPath = `${homedir()}/.jost/identity.jwks.json`

interface EncryptOptions {
  output?: string
  recipient?: string[]
  recipientsFile?: string[]
  identity?: string
  signature: boolean
  compress: boolean
  self: boolean
}

export default async function encrypt(arg: string, options: EncryptOptions) {
  if (
    (options.recipient == null || options.recipient.length === 0) &&
    (options.recipientsFile == null || options.recipientsFile.length === 0)
  ) {
    program.error(
      `error: required options '-r, --recipient <path>' or '-R, --recipients-file <path>' not specified`
    )
  }

  let identities

  const identityPath = options.identity || defaultIdentityPath

  try {
    identities = Jwks.fromFile(identityPath)
  } catch (err: any) {
    if (options.identity == null) {
      program.error(
        `error: required option '-i, --identity <path>' not specified
or create a default identity file in '${defaultIdentityPath}'
example: mkdir ${homedir()}/.jost; jost keygen -o '${defaultIdentityPath}'`
      )
    } else {
      throw err
    }
  }

  const jwk = identities?.keys[0]

  const key = createPrivateKey({ key: jwk, format: 'jwk' })

  const identity = {
    privateKey: key,
    publicKey: createPublicKey(key)
  }

  const recipients: RecipientOptions[] = []

  options.recipient?.forEach((recipient) => {
    let key = createPublicKey({
      key: {
        crv: 'Ed25519',
        x: recipient,
        kty: 'OKP'
      },
      format: 'jwk'
    })

    key = convertEd25519PublicKeyToX25519(key)

    recipients.push({ key, alg: 'ECDH-ES+A256KW' })
  })

  options.recipientsFile?.forEach((path) => {
    const jwks = Jwks.fromFile(path)

    jwks.keys.forEach((jwk) => {
      let key = createPublicKey({ key: jwk, format: 'jwk' })

      key = convertEd25519PublicKeyToX25519(key)

      recipients.push({ key, alg: 'ECDH-ES+A256KW' })
    })
  })

  if (options.self === true) {
    recipients.push({
      key: convertEd25519PublicKeyToX25519(identity.publicKey),
      alg: 'ECDH-ES+A256KW'
    })
  }

  shuffle(recipients)

  let input, output

  if (arg != null) {
    input = createReadStream(arg)
  } else {
    input = process.stdin
  }

  if (options.output) {
    output = createWriteStream(options.output)
  } else {
    output = process.stdout
  }

  let signature: SignatureOptions | undefined

  if (options.signature === true) {
    signature = {
      publicKey: identity.publicKey,
      privateKey: identity.privateKey,
      alg: 'EdDSA',
      crv: 'Ed25519',
      contentHash: 'blake2b512',
      tagHash: 'blake2b512'
    }
  }

  let compression: CompressionOptions | undefined

  if (options.compress === true) {
    compression = { type: 'deflate' }
  }

  const jostWriter = new JostWriter({
    recipients,
    encryption: {
      enc: 'A256GCM'
    },
    signature,
    compression
    // chunkSize: 256
    // chunkSize: 1024 * 1024
  })

  await pipeline(input, jostWriter, output)
}

function shuffle(array: any[]) {
  let m = array.length,
    t,
    i

  // While there remain elements to shuffle...
  while (m) {
    // Pick a remaining element...
    i = Math.floor(Math.random() * m--)

    // And swap it with the current element.
    t = array[m]
    array[m] = array[i]
    array[i] = t
  }

  return array
}
