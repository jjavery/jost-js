import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import JoseStreamReader from './reader'
import { ecdhKeyPair } from './test'

describe('JoseStreamReader', () => {
  it('reads a JOSE stream', async () => {
    const joseStreamReader = new JoseStreamReader({
      decryptionKeyPairs: [ecdhKeyPair]
    })

    const input = createReadStream('./test.jsonl')
    const output = createWriteStream('./test-output.txt')

    await pipeline(input, joseStreamReader, output)
  })
})
