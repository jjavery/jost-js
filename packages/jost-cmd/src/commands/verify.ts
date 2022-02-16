import { createPrivateKey, createPublicKey, KeyObject } from 'crypto'
import { KeyPair, SignatureReader, SignatureReaderOptions } from 'jose-stream'
import { pipeline } from 'stream/promises'
import Jwks from '../jwks'
import { getIdentityPaths, getStreams } from '../util'

interface VerifyOptions {
  output?: string
  keysFile?: string[]
}

export default async function verify(arg: string, options: VerifyOptions) {
  const keys: KeyObject[] = []

  options.keysFile?.forEach((path) => {
    const jwks = Jwks.fromFile(path)

    jwks.keys.forEach((jwk) => {
      let key = createPublicKey({ key: jwk, format: 'jwk' })

      keys.push(key)
    })
  })

  const signatureReaderOptions = {
    getKey: async (protectedHeader: any, token: any) => {
      return keys[0]
    }
  }

  const signatureReader = new SignatureReader(signatureReaderOptions)

  let { input, output } = getStreams(arg, options)

  await pipeline(input, signatureReader, output)
}
