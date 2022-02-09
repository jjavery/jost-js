import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import { ecdhKeyPair, signingKeyPair } from './test'
import JoseStreamWriter, { RecipientOptions, SignatureOptions } from './writer'

describe('JoseStreamWriter', () => {
  it('writes a JOSE stream', async () => {
    const recipient: RecipientOptions = {
      key: ecdhKeyPair.publicKey,
      alg: 'ECDH-ES+A256KW',
      kid: ecdhKeyPair.publicKey.export({ format: 'jwk' }).x
    }

    const joseStreamWriter = new JoseStreamWriter({
      recipients: [recipient],
      encryption: {
        enc: 'A256GCM'
      },
      signature: {
        publicKey: signingKeyPair.publicKey,
        privateKey: signingKeyPair.privateKey,
        alg: 'EdDSA',
        crv: 'Ed25519',
        contentHash: 'blake2b512',
        tagHash: 'blake2b512'
      },
      compression: {
        type: 'deflate'
      },
      // chunkSize: 256
    })

    const input = createReadStream('./test.txt')
    const output = createWriteStream('./test.jsonl')

    await pipeline(input, joseStreamWriter, output)
  })
})
