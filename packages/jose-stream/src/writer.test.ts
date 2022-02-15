import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import { ecdhKeyPair, signingKeyPair } from './test'
import JostWriter, { RecipientOptions, SignatureOptions } from './writer'

describe('JostWriter', () => {
  it('writes a jose-stream', async () => {
    const recipient: RecipientOptions = {
      key: ecdhKeyPair.publicKey,
      algorithm: 'ECDH-ES+A256KW',
      keyId: ecdhKeyPair.publicKey.export({ format: 'jwk' }).x
    }

    const jostWriter = new JostWriter({
      recipients: [recipient],
      encryption: {
        encryption: 'A256GCM'
      },
      signature: {
        publicKey: signingKeyPair.publicKey,
        privateKey: signingKeyPair.privateKey,
        algorithm: 'EdDSA',
        curve: 'Ed25519',
        digest: 'blake2b512'
      },
      compression: {
        type: 'deflate'
      }
      // chunkSize: 256
    })

    const input = createReadStream(`${__dirname}/../fixtures/test.txt`)
    const output = createWriteStream(`${__dirname}/../fixtures/test_output.jsonl`)

    await pipeline(input, jostWriter, output)
  })
})
