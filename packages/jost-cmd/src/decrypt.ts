import { convertEd25519PrivateKeyToX25519 } from '@jjavery/ed25519-to-x25519'
import { program } from 'commander'
import { createPrivateKey, createPublicKey } from 'crypto'
import { constants, createReadStream, createWriteStream } from 'fs'
import { access } from 'fs/promises'
import { JostReader, KeyPair } from 'jose-stream'
import { homedir } from 'os'
import { pipeline } from 'stream/promises'
import Jwks from './jwks'

const defaultIdentityPath = `${homedir()}/.jost/identity.jwks.json`

interface DecryptOptions {
  output?: string
  identity?: string[]
}

export default async function decrypt(arg: string, options: DecryptOptions) {
  const identityPaths = [...(options.identity ?? [])]

  if (identityPaths.length === 0) {
    try {
      const canAccess = await access(defaultIdentityPath, constants.R_OK)

      identityPaths.push(defaultIdentityPath)
    } catch (err) {
      program.error(
        `error: required option '-i, --identity <path>' not specified
or create a default identity file in '${defaultIdentityPath}'
example: mkdir ${homedir()}/.jost; jost keygen -o '${defaultIdentityPath}'`
      )
    }
  }

  const keyPairs: KeyPair[] = []

  options.identity?.forEach((path) => {
    const jwks = Jwks.fromFile(path)

    jwks.keys.forEach((jwk) => {
      let key = createPrivateKey({ key: jwk, format: 'jwk' })

      key = convertEd25519PrivateKeyToX25519(key)
      const publicKey = createPublicKey(key)

      keyPairs.push({ privateKey: key, publicKey })
    })
  })

  let input, output

  if (arg != null) {
    input = createReadStream(arg)
  } else {
    input = process.stdin
  }

  if (options.output) {
    output = createWriteStream(options.output)
  } else {
    output = process.stdout
  }

  const jostReader = new JostReader({
    decryptionKeyPairs: keyPairs
  })

  await pipeline(input, jostReader, output)
}
