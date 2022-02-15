import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import SignatureWriter from './signature-writer'
import { signingKeyPair } from './test'

describe('SignatureWriter', () => {
  it('writes a signature', async () => {
    const keyId = signingKeyPair.publicKey.export({ format: 'jwk' }).x

    const options = {
      keyId,
      key: signingKeyPair.privateKey,
      algorithm: 'EdDSA',
      curve: 'Ed25519',
      digest: 'sha256'
    }

    const signatureWriter = new SignatureWriter(options)

    const input = createReadStream(`${__dirname}/../fixtures/test.txt`)
    const output = createWriteStream(
      `${__dirname}/../fixtures/signature_test_output.txt`
    )

    await pipeline(input, signatureWriter, output)
  })
})
