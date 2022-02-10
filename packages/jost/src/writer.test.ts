import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import { ecdhKeyPair, signingKeyPair } from './test'
import JostWriter, { RecipientOptions, SignatureOptions } from './writer'

describe('JostWriter', () => {
  it('writes a jost stream', async () => {
    const recipient: RecipientOptions = {
      key: ecdhKeyPair.publicKey,
      alg: 'ECDH-ES+A256KW',
      kid: ecdhKeyPair.publicKey.export({ format: 'jwk' }).x
    }

    const jostWriter = new JostWriter({
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
      }
      // chunkSize: 256
    })

    const input = createReadStream('./test.txt')
    const output = createWriteStream('./test-output.jsonl')

    await pipeline(input, jostWriter, output)
  })
})
