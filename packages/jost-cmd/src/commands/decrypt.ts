import { convertEd25519PrivateKeyToX25519 } from '@jjavery/ed25519-to-x25519'
import { createPrivateKey, createPublicKey } from 'crypto'
import { JostReader, KeyPair } from 'jose-stream'
import { pipeline } from 'stream/promises'
import Jwks from '../jwks'
import { getIdentityPaths, getStreams } from '../util'

interface DecryptOptions {
  output?: string
  identity?: string[]
}

export default async function decrypt(arg: string, options: DecryptOptions) {
  const identityPaths = await getIdentityPaths(options)

  const keyPairs: KeyPair[] = []

  identityPaths.forEach((path) => {
    const jwks = Jwks.fromFile(path)

    jwks.keys.forEach((jwk) => {
      let key = createPrivateKey({ key: jwk, format: 'jwk' })

      key = convertEd25519PrivateKeyToX25519(key)
      const publicKey = createPublicKey(key)

      keyPairs.push({ privateKey: key, publicKey })
    })
  })

  const jostReader = new JostReader({
    decryptionKeyPairs: keyPairs
  })

  let { input, output } = getStreams(arg, options)

  await pipeline(input, jostReader, output)
}
