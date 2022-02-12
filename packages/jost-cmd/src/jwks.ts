import { createWriteStream, readFileSync } from 'fs'
import { Writable } from 'stream'

export default class Jwks {
  keys: any[] = []

  constructor() {}

  addKey(key: any) {
    this.keys.unshift(key)
  }

  // getUniqueKeyId() {
  //   let i = 1
  //   while (this.keys.some((key) => key.kid === `key${i}`)) {
  //     ++i
  //   }
  //   return `key${i}`
  // }

  async write(output: Writable) {
    const json = JSON.stringify(this, null, '  ') + '\n'

    await new Promise<void>((resolve, reject) => {
      output.write(json, 'utf8', (err) => {
        if (err) reject(err)
        else resolve()
      })
    })
  }

  async writeToFile(path: string) {
    const output = createWriteStream(path)

    await this.write(output)

    await new Promise((resolve, reject) => {
      output.end(resolve)
    })
  }

  static fromFile(path: string) {
    const json = readFileSync(path, { encoding: 'utf-8' })

    const obj = JSON.parse(json)

    const jwks = new Jwks()

    Object.assign(jwks, obj)

    if (!Array.isArray(jwks.keys)) jwks.keys = []

    return jwks
  }
}
