import { createReadStream, createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import JostReader from './reader'
import { ecdhKeyPair } from './test'

describe('JostReader', () => {
  it('reads a jose-stream', async () => {
    const jostReader = new JostReader({
      decryptionKeyPairs: [ecdhKeyPair]
    })

    const input = createReadStream(`${__dirname}/../fixtures/test.jsonl`)
    const output = createWriteStream(`${__dirname}/../fixtures/test_output.txt`)

    await pipeline(input, jostReader, output)
  })
})
