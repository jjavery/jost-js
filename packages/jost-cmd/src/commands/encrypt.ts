import { convertEd25519PublicKeyToX25519 } from '@jjavery/ed25519-to-x25519'
import { createPrivateKey, createPublicKey } from 'crypto'
import {
  CompressionOptions,
  JoseStreamWriter,
  RecipientOptions,
  SignatureOptions
} from 'jose-stream'
import { pipeline } from 'stream/promises'
import Jwks from '../jwks'
import { getIdentityPaths, getStreams, shuffle } from '../util'

interface EncryptOptions {
  output?: string
  recipient?: string[]
  recipientsFile?: string[]
  identity?: string
  sign: boolean
  compress: boolean
  self: boolean
}

export default async function encrypt(arg: string, options: EncryptOptions) {
  const identityPaths = await getIdentityPaths(options)

  const identityPath = identityPaths[0]

  const identities = Jwks.fromFile(identityPath)

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

    recipients.push({ key, algorithm: 'ECDH-ES+A256KW' })
  })

  options.recipientsFile?.forEach((path) => {
    const jwks = Jwks.fromFile(path)

    jwks.keys.forEach((jwk) => {
      let key = createPublicKey({ key: jwk, format: 'jwk' })

      key = convertEd25519PublicKeyToX25519(key)

      recipients.push({ key, algorithm: 'ECDH-ES+A256KW' })
    })
  })

  if (options.self === true) {
    recipients.push({
      key: convertEd25519PublicKeyToX25519(identity.publicKey),
      algorithm: 'ECDH-ES+A256KW'
    })
  }

  shuffle(recipients)

  let signature: SignatureOptions | undefined

  if (options.sign === true) {
    signature = {
      publicKey: identity.publicKey,
      privateKey: identity.privateKey,
      algorithm: 'EdDSA',
      curve: 'Ed25519',
      digest: 'blake2b512'
    }
  }

  let compression: CompressionOptions | undefined

  if (options.compress === true) {
    compression = { type: 'DEF' }
  }

  const joseStreamWriter = new JoseStreamWriter({
    recipients,
    encryption: {
      encryption: 'A256GCM'
    },
    signature,
    compression
    // chunkSize: 256
    // chunkSize: 1024 * 1024
  })

  let { input, output } = getStreams(arg, options)

  await pipeline(input, joseStreamWriter, output)
}
