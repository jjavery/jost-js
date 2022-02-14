import { createHash, Hash, KeyObject } from 'crypto'
import { FlattenedSign } from 'jose'
import { Stream, Transform, TransformCallback } from 'stream'

const lfChar = '\n'.charCodeAt(0)

interface SignatureWriterOptions {
  keyId?: string
  key: KeyObject
  algorithm: string
  curve?: string
  hash: string
}

export default class SignatureWriter extends Transform {
  private _keyId?: string
  private _key: KeyObject
  private _algorithm: string
  private _curve?: string
  private _hashAlgorithm: string
  private _hash: Hash
  private _lastChar?: number

  constructor(options: SignatureWriterOptions) {
    super()

    this._keyId = options.keyId
    this._key = options.key
    this._algorithm = options.algorithm
    this._curve = options.curve
    this._hashAlgorithm = options.hash
    this._hash = createHash(options.hash)
  }

  _transform(
    chunk: Buffer,
    encoding: BufferEncoding,
    callback: TransformCallback
  ): void {
    this._hash.update(chunk)

    this._lastChar = chunk.at(-1)

    this.push(chunk)

    queueMicrotask(callback)
  }

  _flush(callback: TransformCallback): void {
    if (this._lastChar !== lfChar) {
      this._hash.update('\n')
      this.push('\n', 'utf8')
    }

    this._writeSignature().then(
      () => {
        queueMicrotask(callback)
      },
      (err) => {
        queueMicrotask(() => callback(err))
      }
    )
  }

  private async _writeSignature() {
    const digest = this._hash.digest()

    const protectedHeader = {
      typ: 'sig',
      alg: this._algorithm,
      crv: this._curve,
      hsh: this._hashAlgorithm,
      kid: this._keyId,
      b64: false
    }

    const sign = new FlattenedSign(digest).setProtectedHeader(protectedHeader)

    const jws: any = await sign.sign(this._key)

    // delete jws.payload

    const json = JSON.stringify(jws)

    this.push(json)
    this.push('\n')
  }
}
