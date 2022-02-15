import { createPrivateKey, createPublicKey } from 'crypto'
import Jwks from '../jwks'
import { getIdentityPaths, getJwksAndOutput } from '../util'

interface ExportOptions {
  identity?: string
  output?: string
  keyId?: string
}

export default async function export_(options: ExportOptions) {
  const identityPaths = await getIdentityPaths(options)

  const identities = Jwks.fromFile(identityPaths[0])

  let jwk

  if (options.keyId != null) {
    jwk = identities?.keys.find((key) => key.kid === options.keyId)
  } else {
    jwk = identities?.keys[0]
  }

  if (jwk == null) {
    throw new Error('key not found')
  }

  const key = createPrivateKey({ key: jwk, format: 'jwk' })
  const publicKey = createPublicKey(key)

  const publicJwk = publicKey.export({ format: 'jwk' })

  const { jwks, output } = getJwksAndOutput(options.output)

  jwks.addKey(publicJwk)

  jwks.write(output)

  await new Promise((resolve, reject) => {
    output.end(resolve)
  })
}
