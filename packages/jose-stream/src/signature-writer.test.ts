import { assert } from 'chai'
import { createReadStream, createWriteStream } from 'fs'
import { Writable } from 'stream'
import { pipeline } from 'stream/promises'
import SignatureWriter from './signature-writer'
import { signingKeyPair } from './test'

const detachedSignature = `{"signature":"ukiaX1vBnwWg--JjHQhOdDgux16ulsYj-V1aSpZYrXqQ-T4yY0Iay-t4gOPIX9Y9gpQOqpvMD_I-3Yzwvxc3Bg","payload":"0yBqwLyPhzQ7Gb7fGkvy_8ZG2mKyORiywwdbao4xyTU","protected":"eyJ0eXAiOiJqb3NlLXN0cmVhbS1zaWduYXR1cmUiLCJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJkaWciOiJzaGEyNTYifQ"}`

describe('SignatureWriter', () => {
  it('writes a signature', async () => {
    const options = {
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

  it('writes a detached signature', async () => {
    const options = {
      detached: true,
      key: signingKeyPair.privateKey,
      algorithm: 'EdDSA',
      curve: 'Ed25519',
      digest: 'sha256'
    }

    const signatureWriter = new SignatureWriter(options)

    const input = createReadStream(`${__dirname}/../fixtures/test.txt`)
    const output = new Writable({
      write: (chunk, encoding, callback) => callback()
    })

    await pipeline(input, signatureWriter, output)

    const signature = await signatureWriter.getDetachedSignature()

    assert.equal(JSON.stringify(signature), detachedSignature)
  })
})
