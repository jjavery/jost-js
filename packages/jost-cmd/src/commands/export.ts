import { createPrivateKey, createPublicKey } from 'crypto'
import Jwks from '../jwks'
import { getIdentityPaths, getStreams } from '../util'

interface ExportOptions {
  identity?: string
  output?: string
}

export default async function export_(options: ExportOptions) {
  const identityPaths = await getIdentityPaths(options)

  const identityPath = identityPaths[0]

  const identities = Jwks.fromFile(identityPath)

  const jwk = identities?.keys[0]

  const key = createPrivateKey({ key: jwk, format: 'jwk' })

  const publicKey = createPublicKey(key)

  const publicJwk = publicKey.export({ format: 'jwk' })

  const json = JSON.stringify(publicJwk, null, '  ')

  let { output } = getStreams(null, options)

  output.write(json)
  output.write('\n')

  await new Promise((resolve, reject) => {
    output.end(resolve)
  })
}
