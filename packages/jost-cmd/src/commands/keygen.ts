import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose'
import { getJwksAndOutput } from '../util'

export default async function (options: any) {
  let alg = options.algorithm
  let crv
  if (alg === 'EdDSA' || alg === 'ECDH-ES') {
    crv = options.curve
  }

  const keyPair = await generateKeyPair(alg, { crv })

  const jwk = await exportJWK(keyPair.privateKey)
  // const pub = await exportJWK(keyPair.publicKey)

  const thumbprint = await calculateJwkThumbprint(jwk, 'sha256')

  jwk.kid = options.keyId
  jwk.ts = new Date().toJSON()
  // jwk.pub = pub
  jwk.tpt = thumbprint

  const { jwks, output } = getJwksAndOutput(options.output)

  jwks.addKey(jwk)

  jwks.write(output)

  await new Promise((resolve, reject) => {
    output.end(resolve)
  })
}
