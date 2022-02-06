import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import { ecdhKeyPair, signingKeyPair } from './test'
import JoseStreamWriter from './writer'

describe('JoseStreamWriter', () => {
  it('writes a JOSE stream', async () => {

    const joseStreamWriter = new JoseStreamWriter({
      signingKeyPair,
      recipients: [ecdhKeyPair.publicKey]
    })

    const input = createReadStream('./test.txt')
    const output = createWriteStream('./test.jsonl')

    await pipeline(input, joseStreamWriter, output)
  })
})
