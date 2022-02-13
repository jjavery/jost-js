import * as readline from 'readline'
import { getStreams } from '../util'

interface PrintOptions {
  output?: string
}

export default async function print(arg: string, options: PrintOptions) {
  let { input, output } = getStreams(arg, options)

  const lineReader = readline.createInterface({ input })

  let first = true

  output.write('[')

  lineReader.on('line', (line) => {
    const jwx = JSON.parse(line)

    jwx.protected = JSON.parse(
      Buffer.from(jwx.protected, 'base64url').toString()
    )

    if (first) first = false
    else output.write(',\n')

    output.write(JSON.stringify(jwx, null, '  '))
  })

  lineReader.on('close', () => {
    output.write(']\n')
    output.end()
  })
}
