import { createPrivateKey, createPublicKey } from 'crypto'
import { SignatureWriter, SignatureWriterOptions } from 'jose-stream'
import { Writable } from 'stream'
import { pipeline } from 'stream/promises'
import Jwks from '../jwks'
import { getIdentityPaths, getStreams, shuffle } from '../util'

interface SignOptions {
  output?: string
  identity?: string
  detached: boolean
}

export default async function sign(arg: string, options: SignOptions) {
  const identityPaths = await getIdentityPaths(options)

  const identityPath = identityPaths[0]

  const identities = Jwks.fromFile(identityPath)

  const jwk = identities?.keys[0]

  const key = createPrivateKey({ key: jwk, format: 'jwk' })

  const identity = {
    privateKey: key,
    publicKey: createPublicKey(key)
  }

  const signatureWriterOptions = {
    detached: options.detached,
    key,
    algorithm: 'EdDSA',
    curve: 'Ed25519',
    digest: 'sha256'
  }

  const signatureWriter = new SignatureWriter(signatureWriterOptions)

  let { input, output } = getStreams(arg, options)

  if (!options.detached) {
    await pipeline(input, signatureWriter, output)
  } else {
    const nowhere = new Writable({
      write: (chunk, encoding, callback) => callback()
    })

    await pipeline(input, signatureWriter, nowhere)

    const signature = await signatureWriter.getDetachedSignature()

    const json = JSON.stringify(signature, null, '  ') + '\n'

    await new Promise((resolve, reject) => {
      output.write(json, (err) => {
        if (err) reject(err)
        else resolve(null)
      })
    })
  }
}
