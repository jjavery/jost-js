import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import SignatureReader from './signature-reader'
import { signingKeyPair } from './test'

describe('SignatureReader', () => {
  it.only('reads a signature', async () => {
    const keyId = signingKeyPair.publicKey.export({ format: 'jwk' }).x

    const options = {
      key: signingKeyPair.publicKey,
      hash: 'sha256'
    }

    const signatureReader = new SignatureReader(options)

    const input = createReadStream(
      `${__dirname}/../fixtures/signature_test_output.txt`
    )
    const output = createWriteStream(
      `${__dirname}/../fixtures/signature_test_output_output.txt`
    )

    await pipeline(input, signatureReader, output)
  })
})
