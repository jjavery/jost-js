import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import { ecdhKeyPair, signingKeyPair } from './test'
import JoseStreamWriter, { RecipientOptions, SignatureOptions } from './writer'

describe('JoseStreamWriter', () => {
  it('writes a JOSE stream', async () => {
    const joseStreamWriter = new JoseStreamWriter({
      recipient: [
        {
          key: ecdhKeyPair.publicKey,
          alg: 'ECDH-ES+A256KW',
          kid: ecdhKeyPair.publicKey.export({ format: 'jwk' }).x
        }
      ],
      encryption: {
        enc: 'A256GCM'
      },
      signature: {
        publicKey: signingKeyPair.publicKey,
        privateKey: signingKeyPair.privateKey,
        alg: 'EdDSA',
        crv: 'Ed25519',
        plaintextHash: 'blake2b512',
        ciphertextHash: 'blake2b512'
      },
      chunkSize: 256
    })

    const input = createReadStream('./test.txt')
    const output = createWriteStream('./test.jsonl')

    await pipeline(input, joseStreamWriter, output)
  })
})
