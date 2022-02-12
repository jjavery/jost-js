import { createWriteStream } from 'fs'
import { exportJWK, generateKeyPair } from 'jose-stream'
import { Writable } from 'stream'
import Jwks from './jwks'

export default async function (options: any) {
  let jwks: Jwks
  let output: Writable

  if (options.output != null) {
    try {
      try {
        jwks = Jwks.fromFile(options.output)
      } catch (err) {}

      output = createWriteStream(options.output)
    } catch (err: any) {
      console.error(err?.message)
      process.exit(1)
    }
  } else {
    output = process.stdout
  }

  jwks ??= new Jwks()

  let alg = options.algorithm
  let crv
  if (alg === 'EdDSA' || alg === 'ECDH-ES') {
    crv = options.curve
  }

  const keyPair = await generateKeyPair(alg, { crv })

  const jwk = await exportJWK(keyPair.privateKey)
  const pub = await exportJWK(keyPair.publicKey)

  jwk.kid = options.keyId
  jwk.ts = new Date().toJSON()
  jwk.pub = pub

  jwks.addKey(jwk)

  jwks.write(output)

  await new Promise((resolve, reject) => {
    output.end(resolve)
  })
}
