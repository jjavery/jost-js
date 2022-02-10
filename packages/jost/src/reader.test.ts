import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import JostReader from './reader'
import { ecdhKeyPair } from './test'

describe('JostReader', () => {
  it('reads a jost stream', async () => {
    const jostReader = new JostReader({
      decryptionKeyPairs: [ecdhKeyPair]
    })

    const input = createReadStream('./test.jsonl')
    const output = createWriteStream('./test-output.txt')

    await pipeline(input, jostReader, output)
  })
})
