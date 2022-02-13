import { program } from 'commander'
import { constants, createReadStream, createWriteStream } from 'fs'
import { access } from 'fs/promises'
import { homedir } from 'os'
import { Readable, Writable } from 'stream'

const defaultIdentityPath = `${homedir()}/.jost/identity.jwks.json`

interface IdentityOptions {
  identity?: string | string[]
}

export async function getIdentityPaths(options: IdentityOptions) {
  let identityPaths: string[]

  if (Array.isArray(options.identity)) {
    identityPaths = [...options.identity]
  } else if (options.identity != null) {
    identityPaths = [options.identity]
  } else {
    identityPaths = []
  }

  if (identityPaths.length === 0) {
    try {
      await access(defaultIdentityPath, constants.R_OK)

      identityPaths.push(defaultIdentityPath)
    } catch (err) {
      program.error(
        `error: required option '-i, --identity <path>' not specified
or create a default identity file in '${defaultIdentityPath}'
example: mkdir ${homedir()}/.jost; jost keygen -o '${defaultIdentityPath}'`
      )
    }
  }

  return identityPaths
}

interface OutputOptions {
  output?: string
}

export function getStreams(arg: string | null, options: OutputOptions) {
  let input: Readable, output: Writable

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

  return { input, output }
}

export function shuffle(array: any[]) {
  let m = array.length,
    t,
    i

  // While there remain elements to shuffle...
  while (m) {
    // Pick a remaining element...
    i = Math.floor(Math.random() * m--)

    // And swap it with the current element.
    t = array[m]
    array[m] = array[i]
    array[i] = t
  }

  return array
}
