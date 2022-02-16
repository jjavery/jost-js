import { createReadStream, createWriteStream } from 'fs'
import { Writable } from 'stream'
import { pipeline } from 'stream/promises'
import SignatureReader from './signature-reader'
import { signingKeyPair } from './test'

const detachedSignature = `{"signature":"ukiaX1vBnwWg--JjHQhOdDgux16ulsYj-V1aSpZYrXqQ-T4yY0Iay-t4gOPIX9Y9gpQOqpvMD_I-3Yzwvxc3Bg","payload":"0yBqwLyPhzQ7Gb7fGkvy_8ZG2mKyORiywwdbao4xyTU","protected":"eyJ0eXAiOiJqb3NlLXN0cmVhbS1zaWduYXR1cmUiLCJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJkaWciOiJzaGEyNTYifQ"}`

describe('SignatureReader', () => {
  it('reads a signature', async () => {
    const options = {
      key: signingKeyPair.publicKey
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

  it('reads a detached signature', async () => {
    const options = {
      key: signingKeyPair.publicKey,
      detachedSignature
    }

    const signatureReader = new SignatureReader(options)

    const input = createReadStream(`${__dirname}/../fixtures/test.txt`)
    const output = new Writable({
      write: (chunk, encoding, callback) => callback()
    })

    await pipeline(input, signatureReader, output)
  })
})
