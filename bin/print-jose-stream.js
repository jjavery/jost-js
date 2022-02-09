const readline = require('readline')
const fs = require('fs')

if (process.argv.length < 3) {
  console.error('error: missing input file')
  console.error(`Usage: print-jose-stream INPUT`)
  process.exit(1)
}

const input = fs.createReadStream(process.argv[2])
const output = process.stdout

const lineReader = readline.createInterface({ input })

let first = true

output.write('[')

lineReader.on('line', (line) => {
  const jwx = JSON.parse(line)

  jwx.protected = JSON.parse(Buffer.from(jwx.protected, 'base64url'))

  if (first) first = false
  else output.write(',\n')

  output.write(JSON.stringify(jwx, null, '  '))
})

lineReader.on('close', () => {
  output.write(']\n')
})
